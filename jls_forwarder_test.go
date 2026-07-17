package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go/internal/handshake"
	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/wire"
	"github.com/metacubex/jls-tls"
)

// JLS BEGIN: JLS camouflage forwarding tests.

func TestJLSRateLimiterAccumulatesTokens(t *testing.T) {
	limiter := newJLSRateLimiter(100_000)
	now := time.Unix(100, 0)
	limiter.last = now

	if !limiter.allowAt(protocol.MaxPacketBufferSize, now) {
		t.Fatal("initial packet-sized burst was rejected")
	}
	if limiter.allowAt(1, now) {
		t.Fatal("rate limiter exceeded its burst")
	}
	if !limiter.allowAt(protocol.MaxPacketBufferSize, now.Add(time.Second)) {
		t.Fatal("rate limiter did not accumulate enough tokens for a complete packet")
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

func TestJLSTransportUsesQUICDefaults(t *testing.T) {
	pc := newUDPConnLocalhost(t)
	tr := &Transport{Conn: pc}
	config := &Config{JLSConfig: &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		},
	}}
	if _, err := tr.Listen(&tls.Config{}, config); err != errJLSConfigDisabled {
		t.Fatalf("error = %v, want %v", err, errJLSConfigDisabled)
	}
	listener, err := tr.Listen(&tls.Config{JLSConfig: &tls.JLSConfig{
		Enable: true,
		Users:  []tls.JLSUser{{Username: "user", Password: "password"}},
	}}, config)
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.connIDLen; got != protocol.DefaultConnectionIDLength {
		t.Fatalf("connection ID length = %d, want %d", got, protocol.DefaultConnectionIDLength)
	}
	if _, ok := tr.connIDGenerator.(*protocol.DefaultConnectionIDGenerator); !ok {
		t.Fatalf("connection ID generator = %T, want *protocol.DefaultConnectionIDGenerator", tr.connIDGenerator)
	}
	if tr.StatelessResetKey != nil {
		t.Fatal("JLS transport unexpectedly generated a Stateless Reset key")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
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
