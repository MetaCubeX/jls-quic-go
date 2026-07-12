package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go/internal/handshake"
	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/utils"
	"github.com/metacubex/jls-quic-go/internal/wire"
	"github.com/metacubex/jls-tls"
)

// JLS BEGIN: JLS camouflage forwarding tests.

func TestJLSRateLimiterAllowsInitialCycle(t *testing.T) {
	limiter := newJLSRateLimiter(1_000_000)
	if !limiter.allow(1200) {
		t.Fatal("first packet within the initial rate-limit cycle was rejected")
	}
	if limiter.allow(100) {
		t.Fatal("rate limiter allowed more than one cycle worth of bytes")
	}
}

func TestJLSForwardConnIdleFor(t *testing.T) {
	fwd := &jlsForwardConn{}
	now := time.Unix(100, 0)
	fwd.touch(now)
	if got := fwd.idleFor(now.Add(3 * time.Second)); got != 3*time.Second {
		t.Fatalf("idle duration = %s, want 3s", got)
	}
}

func TestJLSConnectionIDGeneratorValidatesGeneratedIDs(t *testing.T) {
	generator := newJLSConnectionIDGenerator(8)
	if got := generator.nonceLen(); got != 3 {
		t.Fatalf("nonce length = %d, want 3", got)
	}

	const count = 4096
	for i := 0; i < count; i++ {
		connID, err := generator.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		if !generator.ValidateConnectionID(connID) {
			t.Fatal("generated connection ID failed validation")
		}
	}

	connID, err := generator.GenerateConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	modified := append([]byte(nil), connID.Bytes()...)
	modified[len(modified)-1] ^= 1
	if generator.ValidateConnectionID(protocol.ParseConnectionID(modified)) {
		t.Fatal("modified connection ID passed validation")
	}
}

func TestJLSStatelessResetProfile(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	generator := newJLSConnectionIDGenerator(jlsDefaultConnectionIDLen)
	tr := &Transport{
		conn:                &basicConn{PacketConn: server},
		connIDLen:           jlsDefaultConnectionIDLen,
		connIDGenerator:     generator,
		StatelessResetKey:   &StatelessResetKey{1},
		statelessResetter:   newStatelessResetter(&StatelessResetKey{1}),
		statelessResetQueue: make(chan receivedPacket, 2),
		logger:              utils.DefaultLogger,
	}
	packet := func(size int) receivedPacket {
		data := make([]byte, size)
		data[0] = 0x40
		buf := getLargePacketBuffer()
		buf.Data = append(buf.Data, data...)
		return receivedPacket{data: buf.Data, buffer: buf, remoteAddr: client.LocalAddr()}
	}

	tooSmall := packet(jlsMinStatelessResetSize)
	if tr.maybeSendStatelessReset(tooSmall) {
		t.Fatal("minimum-sized trigger queued a stateless reset")
	}
	tooSmall.buffer.Release()

	first := packet(100)
	if !tr.maybeSendStatelessReset(first) {
		t.Fatal("first JLS stateless reset was not queued")
	}
	second := packet(100)
	if tr.maybeSendStatelessReset(second) {
		t.Fatal("JLS stateless reset ignored the minimum interval")
	}
	second.buffer.Release()

	queued := <-tr.statelessResetQueue
	tr.sendStatelessReset(queued)
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 100)
	n, _, err := client.ReadFrom(response)
	if err != nil {
		t.Fatal(err)
	}
	const idealMinResetSize = jlsStatelessResetMinPadding + jlsMaxConnectionIDLen + jlsStatelessResetTokenLen
	if n < idealMinResetSize || n >= 100 {
		t.Fatalf("stateless reset length = %d, want [%d, 100)", n, idealMinResetSize)
	}
}

func TestJLSVersionNegotiationProfileReplacesOfferedGrease(t *testing.T) {
	configured := []protocol.Version{jlsDefaultGreaseVersion, protocol.Version1, 0xff00001d}
	got := jlsVersionNegotiationProfile(jlsDefaultGreaseVersion, configured)
	want := []protocol.Version{jlsDefaultGreaseVersion + jlsGreaseVersionStep, protocol.Version1, 0xff00001d}
	if len(got) != len(want) {
		t.Fatalf("profile length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("profile[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestJLSTransportDefaults(t *testing.T) {
	pc := newUDPConnLocalhost(t)
	tr := &Transport{Conn: pc}
	listener, err := tr.Listen(&tls.Config{JLSConfig: &tls.JLSConfig{
		Enable: true,
		Users:  []tls.JLSUser{{Username: "user", Password: "password"}},
	}}, &Config{JLSConfig: &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.connIDLen; got != jlsDefaultConnectionIDLen {
		t.Fatalf("connection ID length = %d, want %d", got, jlsDefaultConnectionIDLen)
	}
	if _, ok := tr.connIDGenerator.(*jlsConnectionIDGenerator); !ok {
		t.Fatalf("connection ID generator = %T, want *jlsConnectionIDGenerator", tr.connIDGenerator)
	}
	if tr.StatelessResetKey == nil {
		t.Fatal("JLS transport did not generate a Stateless Reset key")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJLSTransportRoutesUnknownShortHeaderByCIDValidity(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	forwarder := newJLSForwarder(&basicConn{PacketConn: pc}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer forwarder.Close()
	if forwarder.newForwardConn(receivedPacket{remoteAddr: mustResolveUDPAddr(t, "127.0.0.1:12345")}) == nil {
		t.Fatal("failed to create existing forward connection")
	}

	generator := newJLSConnectionIDGenerator(jlsDefaultConnectionIDLen)
	tr := &Transport{
		connIDLen:           jlsDefaultConnectionIDLen,
		connIDGenerator:     generator,
		StatelessResetKey:   &StatelessResetKey{1},
		handlers:            make(map[protocol.ConnectionID]packetHandler),
		resetTokens:         make(map[protocol.StatelessResetToken]packetHandler),
		statelessResetQueue: make(chan receivedPacket, 1),
	}
	tr.jlsForwarder.Store(forwarder)

	validCID, err := generator.GenerateConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	validPacket, err := wire.AppendShortHeader(nil, validCID, 1, protocol.PacketNumberLen2, protocol.KeyPhaseZero)
	if err != nil {
		t.Fatal(err)
	}
	validPacket = append(validPacket, make([]byte, protocol.MinStatelessResetSize-len(validPacket)+1)...)
	validRemote := mustResolveUDPAddr(t, "127.0.0.1:12346")
	tr.handlePacket(newJLSReceivedPacket(validPacket, validRemote))
	select {
	case queued := <-tr.statelessResetQueue:
		queued.buffer.Release()
	default:
		t.Fatal("valid unknown JLS connection ID did not queue a Stateless Reset")
	}
	if forwarder.getForwardConn(validRemote) != nil {
		t.Fatal("valid unknown JLS connection ID created a camouflage forwarding flow")
	}

	invalidCIDBytes := append([]byte(nil), validCID.Bytes()...)
	invalidCIDBytes[len(invalidCIDBytes)-1] ^= 1
	invalidCID := protocol.ParseConnectionID(invalidCIDBytes)
	invalidPacket, err := wire.AppendShortHeader(nil, invalidCID, 2, protocol.PacketNumberLen2, protocol.KeyPhaseZero)
	if err != nil {
		t.Fatal(err)
	}
	invalidPacket = append(invalidPacket, make([]byte, protocol.MinStatelessResetSize-len(invalidPacket)+1)...)
	invalidRemote := mustResolveUDPAddr(t, "127.0.0.1:12347")
	tr.handlePacket(newJLSReceivedPacket(invalidPacket, invalidRemote))

	if forwarder.getForwardConn(invalidRemote) == nil {
		t.Fatal("invalid JLS connection ID did not create a migration forwarding flow")
	}
	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(invalidPacket)+1)
	n, _, err := upstream.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(invalidPacket) {
		t.Fatalf("forwarded migrated packet = %x, want %x", got[:n], invalidPacket)
	}
	select {
	case queued := <-tr.statelessResetQueue:
		queued.buffer.Release()
		t.Fatal("invalid JLS connection ID queued a Stateless Reset")
	default:
	}
}

func TestJLSForwarderMigratesForwardedShortPacket(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	fwd := newJLSForwarder(&basicConn{PacketConn: pc}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer fwd.Close()

	oldAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	if fwd.newForwardConn(receivedPacket{remoteAddr: oldAddr}) == nil {
		t.Fatal("failed to create existing forward connection")
	}

	payload := []byte{0x40, 0x01, 0x02, 0x03}
	p := newJLSReceivedPacket(payload, mustResolveUDPAddr(t, "127.0.0.1:12346"))
	if !fwd.handleMigratedClientPacket(p) {
		t.Fatal("migrated packet was not forwarded")
	}

	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	n, _, err := upstream.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("forwarded payload = %v, want %v", got[:n], payload)
	}
}

func TestJLSForwarderSendsCapturedPacketsBeforeRateLimit(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	fwd := newJLSForwarder(&basicConn{PacketConn: pc}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		RateLimit:    1,
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer fwd.Close()

	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	capture := &jlsForwardCapture{
		forwarder:  fwd,
		clientAddr: mustResolveUDPAddr(t, "127.0.0.1:12345"),
		packets:    [][]byte{payload},
		bytes:      len(payload),
	}
	fwd.activateForwardCapture(capture)

	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	n, _, err := upstream.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("forwarded payload = %v, want %v", got[:n], payload)
	}
}

func TestJLSForwarderRelaysUpstreamResponse(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer fwd.Close()

	request := []byte("request")
	fwd.activateForwardCapture(&jlsForwardCapture{
		forwarder:  fwd,
		clientAddr: client.LocalAddr(),
		packets:    [][]byte{request},
		bytes:      len(request),
	})

	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, forwardAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(request) {
		t.Fatalf("forwarded request = %q, want %q", buf[:n], request)
	}

	response := []byte("response")
	if _, err := upstream.WriteTo(response, forwardAddr); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, sourceAddr, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(response) {
		t.Fatalf("relayed response = %q, want %q", buf[:n], response)
	}
	if sourceAddr.String() != server.LocalAddr().String() {
		t.Fatalf("response source = %s, want listener %s", sourceAddr, server.LocalAddr())
	}
}

func testJLSDialer(t *testing.T, upstream net.PacketConn) JLSPacketDialer {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.PacketConn, net.Addr, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if address != upstream.LocalAddr().String() {
			t.Fatalf("dial address = %q, want %q", address, upstream.LocalAddr().String())
		}
		pc, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		return pc, upstream.LocalAddr(), nil
	}
}

func mustResolveUDPAddr(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return udpAddr
}

func composeJLSInitialPacketWithToken(t *testing.T, version protocol.Version, dcid, cryptoData, token []byte) []byte {
	return composeJLSInitialPacketFrame(t, version, dcid, cryptoData, token, 0, 1)
}

func composeJLSInitialPacketWithOffsetAndNumber(t *testing.T, version protocol.Version, dcid, cryptoData []byte, offset protocol.ByteCount, packetNumber protocol.PacketNumber) []byte {
	return composeJLSInitialPacketFrame(t, version, dcid, cryptoData, nil, offset, packetNumber)
}

func composeJLSInitialPacketFrame(t *testing.T, version protocol.Version, dcid, cryptoData, token []byte, offset protocol.ByteCount, packetNumber protocol.PacketNumber) []byte {
	t.Helper()

	destConnID := protocol.ParseConnectionID(dcid)
	srcConnID := protocol.ParseConnectionID([]byte{9, 8, 7, 6})
	sealer, _ := handshake.NewInitialAEAD(destConnID, protocol.PerspectiveClient, version)

	payload, err := (&wire.CryptoFrame{Offset: offset, Data: cryptoData}).Append(nil, version)
	if err != nil {
		t.Fatal(err)
	}

	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			Version:          version,
			DestConnectionID: destConnID,
			SrcConnectionID:  srcConnID,
			Token:            token,
		},
		PacketNumberLen: protocol.PacketNumberLen4,
		PacketNumber:    packetNumber,
	}
	hdr.Length = protocol.ByteCount(4 + len(payload) + sealer.Overhead())
	header, err := hdr.Append(nil, version)
	if err != nil {
		t.Fatal(err)
	}

	payloadOffset := len(header)
	packet := append(header, payload...)
	packet = sealer.Seal(packet[:payloadOffset], packet[payloadOffset:], hdr.PacketNumber, packet[:payloadOffset])
	pnOffset := payloadOffset - int(hdr.PacketNumberLen)
	sealer.EncryptHeader(packet[pnOffset+4:pnOffset+4+16], &packet[0], packet[pnOffset:pnOffset+4])
	return packet
}

func newJLSReceivedPacket(data []byte, remoteAddr net.Addr) receivedPacket {
	buf := getLargePacketBuffer()
	buf.Data = append(buf.Data, data...)
	return receivedPacket{data: buf.Data, buffer: buf, remoteAddr: remoteAddr}
}

// JLS END
