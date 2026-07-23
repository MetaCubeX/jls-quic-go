package quic

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go/internal/handshake"
	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/wire"
	"github.com/metacubex/jls-tls"
	"go.uber.org/mock/gomock"
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
	if got := fwd.idleDeadline(); !got.Equal(now.Add(jlsForwardIdleTimeout)) {
		t.Fatalf("idle deadline = %s, want %s", got, now.Add(jlsForwardIdleTimeout))
	}
}

func TestJLSTentativeDeadlineOnlyRefreshesAfterForward(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	forwardConn := &jlsForwardConn{
		conn:         packetConn,
		upstreamAddr: upstream.LocalAddr(),
		sendLimiter:  newJLSRateLimiter(1),
	}
	initialDeadline := time.Unix(100, 0)
	tentative := &jlsTentativeForward{fwd: forwardConn, deadline: initialDeadline}
	if err := tentative.forwardPacket(&jlsForwarder{}, make([]byte, protocol.MaxPacketBufferSize+1)); err != nil {
		t.Fatal(err)
	}
	if !tentative.deadline.Equal(initialDeadline) {
		t.Fatalf("rate-limited packet refreshed deadline to %s", tentative.deadline)
	}
	if err := tentative.forwardPacket(&jlsForwarder{}, []byte("forwarded")); err != nil {
		t.Fatal(err)
	}
	if !tentative.deadline.After(initialDeadline) {
		t.Fatalf("forwarded packet did not refresh deadline: %s", tentative.deadline)
	}
}

func TestJLSPersistentDeadlineIgnoresUnexpectedResponseSource(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	unexpected, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unexpected.Close()

	deadlines := make(chan time.Time, 2)
	trackedConn := &jlsForwardConn{
		conn:         &jlsDeadlinePacketConn{PacketConn: packetConn, readDeadline: deadlines},
		upstreamAddr: upstream.LocalAddr(),
		active:       time.Now().Add(-time.Minute),
	}
	fwd := &jlsForwarder{
		conns:     map[string]*jlsForwardConn{"client": trackedConn},
		tentative: make(map[jlsTentativeForwardKey]*jlsTentativeForward),
	}
	readDeadline := func() time.Time {
		t.Helper()
		select {
		case deadline := <-deadlines:
			return deadline
		case <-time.After(time.Second):
			t.Fatal("persistent reader did not set a deadline")
			return time.Time{}
		}
	}
	go fwd.readForwardConn("client", trackedConn)
	firstDeadline := readDeadline()
	if _, err := unexpected.WriteTo([]byte("unexpected"), packetConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	secondDeadline := readDeadline()
	if !secondDeadline.Equal(firstDeadline) {
		t.Fatalf("unexpected response changed deadline from %s to %s", firstDeadline, secondDeadline)
	}
	_ = packetConn.Close()
	waitForJLSForwardCounts(t, fwd, 0, 0)
}

func TestJLSPersistentDeadlineFailureReleasesReservation(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	clientKey := "192.0.2.1"
	trackedConn := &jlsForwardConn{
		conn:      &jlsFailingReadDeadlinePacketConn{PacketConn: packetConn},
		active:    time.Now(),
		clientKey: clientKey,
		counted:   true,
	}
	fwd := &jlsForwarder{
		conns:            map[string]*jlsForwardConn{"client": trackedConn},
		tentative:        make(map[jlsTentativeForwardKey]*jlsTentativeForward),
		tentativeClients: map[string]*jlsTentativeClient{clientKey: {fallbacks: 1}},
		forwardCount:     1,
	}
	go fwd.readForwardConn("client", trackedConn)
	waitForJLSForwardCounts(t, fwd, 0, 0)
	fwd.mu.Lock()
	forwardCount := fwd.forwardCount
	clientFallbacks := fwd.tentativeClients[clientKey].fallbacks
	fwd.mu.Unlock()
	if forwardCount != 0 || clientFallbacks != 0 {
		t.Fatalf("deadline failure retained reservation: global %d, client %d", forwardCount, clientFallbacks)
	}
}

func TestJLSEnableForwardingBuffersLocalOutputUntilAuthentication(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	underlying := NewMockSendConn(mockCtrl)
	fwd := &jlsForwarder{}
	quicConn := &Conn{conn: underlying}
	quicConn.enableJLSForwarding(fwd, nil)
	conn, ok := quicConn.conn.(*jlsPreAuthSendConn)
	if !ok {
		t.Fatalf("connection send path has type %T, want *jlsPreAuthSendConn", quicConn.conn)
	}
	queue, ok := quicConn.sendQueue.(*sendQueue)
	if !ok {
		t.Fatalf("connection send queue has type %T, want *sendQueue", quicConn.sendQueue)
	}
	if queue.conn != conn || quicConn.jlsForwardCapture.sendConn != conn {
		t.Fatal("connection output paths do not share the pre-authentication gate")
	}

	data := []byte("buffered packet")
	underlying.EXPECT().Write([]byte("buffered packet"), uint16(1200), protocol.ECT0).Return(nil)
	if err := conn.Write(data, 1200, protocol.ECT0); err != nil {
		t.Fatal(err)
	}
	data[0] = 'x'
	if got := fwd.capturedBytes.Load(); got != int64(len(data)) {
		t.Fatalf("captured bytes = %d, want %d", got, len(data))
	}
	if err := conn.commit(); err != nil {
		t.Fatal(err)
	}
	if got := fwd.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after commit = %d, want 0", got)
	}
}

func TestJLSPreAuthSendConnDiscardsBufferedWrites(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := &jlsPreAuthSendConn{
		sendConn:  NewMockSendConn(mockCtrl),
		forwarder: &jlsForwarder{},
	}
	if err := conn.Write([]byte("local fingerprint"), 0, protocol.ECNNon); err != nil {
		t.Fatal(err)
	}
	conn.discard()
	if got := conn.forwarder.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after discard = %d, want 0", got)
	}
}

func TestJLSForwarderLimitsPersistentConnections(t *testing.T) {
	fwd := newJLSForwarder(nil, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		},
	})
	defer fwd.Close()

	now := time.Now()
	clientKey := "192.0.2.1"
	for i := 0; i < jlsMaxForwardConnsPerClient; i++ {
		if !fwd.reserveForwardConn(clientKey, now) {
			t.Fatalf("persistent connection %d was rejected", i)
		}
	}
	fwd.mu.Lock()
	client := fwd.tentativeClients[clientKey]
	client.fallbackRate.tokens = 1
	fwd.forwardRate.tokens = 1
	fwd.mu.Unlock()
	if fwd.reserveForwardConn(clientKey, now) {
		t.Fatal("per-client persistent connection limit was exceeded")
	}

	for i := 0; i < jlsMaxForwardConnsPerClient; i++ {
		fwd.releaseForwardReservation(clientKey)
	}
	fwd.mu.Lock()
	if fwd.forwardCount != 0 || client.fallbacks != 0 {
		t.Fatalf("released persistent connections = global %d, client %d", fwd.forwardCount, client.fallbacks)
	}
	fwd.forwardCount = jlsMaxForwardConns
	client.fallbackRate.tokens = 1
	fwd.forwardRate.tokens = 1
	fwd.mu.Unlock()
	if fwd.reserveForwardConn("198.51.100.1", now) {
		t.Fatal("global persistent connection limit was exceeded")
	}
	fwd.mu.Lock()
	fwd.forwardCount = 0
	fwd.mu.Unlock()
}

func TestJLSForwarderLimitsAuthenticatingConnections(t *testing.T) {
	t.Run("per client and rate", func(t *testing.T) {
		fwd := newBlockingJLSTentativeForwarder()
		defer fwd.Close()
		now := time.Now()
		addr := mustResolveUDPAddr(t, "192.0.2.1:12345")
		reservations := make([]*jlsAuthenticationReservation, 0, jlsMaxAuthenticatingConnsPerClient)
		for i := 0; i < jlsMaxAuthenticatingConnsPerClient; i++ {
			reservation := fwd.reserveAuthentication(addr, now)
			if reservation == nil {
				t.Fatalf("authentication connection %d was rejected", i)
			}
			reservations = append(reservations, reservation)
		}
		if reservation := fwd.reserveAuthentication(addr, now); reservation != nil {
			reservation.release()
			t.Fatal("per-client authentication connection limit was exceeded")
		}
		for _, reservation := range reservations {
			reservation.release()
		}
		if reservation := fwd.reserveAuthentication(addr, now); reservation != nil {
			reservation.release()
			t.Fatal("released connections bypassed the per-client creation rate")
		}
		reservation := fwd.reserveAuthentication(addr, now.Add(time.Second))
		if reservation == nil {
			t.Fatal("per-client authentication rate did not replenish")
		}
		reservation.release()
	})

	t.Run("global", func(t *testing.T) {
		fwd := newBlockingJLSTentativeForwarder()
		defer fwd.Close()
		now := time.Now()
		reservations := make([]*jlsAuthenticationReservation, 0, jlsMaxAuthenticatingConns)
		for i := 0; i < jlsMaxAuthenticatingConns; i++ {
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i)), Port: 12345}
			reservation := fwd.reserveAuthentication(addr, now)
			if reservation == nil {
				t.Fatalf("global authentication connection %d was rejected", i)
			}
			reservations = append(reservations, reservation)
		}
		if reservation := fwd.reserveAuthentication(mustResolveUDPAddr(t, "198.51.100.1:12345"), now); reservation != nil {
			reservation.release()
			t.Fatal("global authentication connection limit was exceeded")
		}
		for _, reservation := range reservations {
			reservation.release()
		}
		fwd.mu.Lock()
		count := fwd.authenticationCount
		fwd.mu.Unlock()
		if count != 0 {
			t.Fatalf("released authentication connections = %d, want 0", count)
		}
	})
}

func TestJLSAuthenticationReservationLifecycle(t *testing.T) {
	for _, test := range []struct {
		name       string
		transition func(*testing.T, *jlsForwardCapture)
	}{
		{
			name: "authenticated",
			transition: func(t *testing.T, capture *jlsForwardCapture) {
				if err := capture.authenticate(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{name: "disabled", transition: func(_ *testing.T, capture *jlsForwardCapture) { capture.disable() }},
		{
			name: "fallback",
			transition: func(t *testing.T, capture *jlsForwardCapture) {
				if _, _, ok := capture.beginActivation(); !ok {
					t.Fatal("fallback activation was rejected")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fwd := newBlockingJLSTentativeForwarder()
			defer fwd.Close()
			addr := mustResolveUDPAddr(t, "192.0.2.1:12345")
			reservation := fwd.reserveAuthentication(addr, time.Now())
			if reservation == nil {
				t.Fatal("failed to reserve authentication connection")
			}
			capture := &jlsForwardCapture{
				forwarder:      fwd,
				authentication: reservation,
				clientKey:      reservation.clientKey,
				clientAddr:     addr,
				packets:        [][]byte{{1}},
			}
			test.transition(t, capture)
			fwd.mu.Lock()
			count := fwd.authenticationCount
			clientCount := fwd.tentativeClients[reservation.clientKey].authenticating
			fwd.mu.Unlock()
			if count != 0 || clientCount != 0 || reservation.forwarder != nil {
				t.Fatalf("authentication reservation retained: global %d, client %d", count, clientCount)
			}
		})
	}
}

func TestJLSFallbackDialUsesDeadlineAndReleasesReservation(t *testing.T) {
	var dialDeadline time.Time
	fwd := newJLSForwarder(nil, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(ctx context.Context, _, _ string) (net.PacketConn, net.Addr, error) {
			var ok bool
			dialDeadline, ok = ctx.Deadline()
			if !ok {
				t.Error("fallback dial context has no deadline")
			}
			return nil, nil, nil
		},
	})
	defer fwd.Close()

	started := time.Now()
	capture := newTestJLSForwardCapture(t, fwd, mustResolveUDPAddr(t, "127.0.0.1:12345"), []byte("fallback"))
	fwd.activateForwardCapture(capture)
	if dialDeadline.Before(started.Add(jlsForwardIdleTimeout)) || dialDeadline.After(time.Now().Add(jlsForwardIdleTimeout)) {
		t.Fatalf("fallback dial deadline %s is outside the idle lifetime from %s", dialDeadline, started)
	}
	fwd.mu.Lock()
	forwardCount := fwd.forwardCount
	client := fwd.tentativeClients["127.0.0.1"]
	fwd.mu.Unlock()
	if forwardCount != 0 || client == nil || client.fallbacks != 0 {
		t.Fatalf("failed fallback dial retained reservation: global %d, client %+v", forwardCount, client)
	}
}

func TestJLSAuthenticationCaptureReleasesBudget(t *testing.T) {
	fwd := &jlsForwarder{}
	conn := &Conn{jlsForwardCapture: &jlsForwardCapture{forwarder: fwd}}
	packet := receivedPacket{
		data:       make([]byte, 1024),
		remoteAddr: mustResolveUDPAddr(t, "127.0.0.1:12345"),
	}
	if conn.handleJLSPacket(packet) {
		t.Fatal("authentication packet was unexpectedly forwarded")
	}
	if got := fwd.capturedBytes.Load(); got != int64(len(packet.data)) {
		t.Fatalf("captured bytes = %d, want %d", got, len(packet.data))
	}

	conn.releaseJLSForwardCapture()
	if got := fwd.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after disabling = %d, want 0", got)
	}
}

func TestJLSAuthenticationCapturePerConnectionLimit(t *testing.T) {
	fwd := &jlsForwarder{}
	capture := &jlsForwardCapture{forwarder: fwd}
	conn := &Conn{jlsForwardCapture: capture}
	remoteAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	conn.handleJLSPacket(receivedPacket{data: []byte{1}, remoteAddr: remoteAddr})
	conn.handleJLSPacket(receivedPacket{
		data:       make([]byte, jlsMaxAuthenticationCaptureBytes),
		remoteAddr: remoteAddr,
	})

	if !capture.overflow {
		t.Fatal("capture remained enabled after exceeding its per-connection limit")
	}
	if len(capture.packets) != 0 || capture.bytes != 0 {
		t.Fatalf("overflowed capture retained %d packets and %d bytes", len(capture.packets), capture.bytes)
	}
	if got := fwd.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after overflow = %d, want 0", got)
	}
}

func TestJLSAuthenticationCaptureGlobalLimit(t *testing.T) {
	fwd := &jlsForwarder{}
	if !fwd.reserveCapturedBytes("", jlsMaxAuthenticationCaptureBytesPerServer) {
		t.Fatal("failed to reserve the global capture budget")
	}
	capture := &jlsForwardCapture{forwarder: fwd}
	conn := &Conn{jlsForwardCapture: capture}
	conn.handleJLSPacket(receivedPacket{
		data:       []byte{1},
		remoteAddr: mustResolveUDPAddr(t, "127.0.0.1:12345"),
	})

	if !capture.overflow {
		t.Fatal("capture remained enabled after exhausting the global limit")
	}
	if got := fwd.capturedBytes.Load(); got != jlsMaxAuthenticationCaptureBytesPerServer {
		t.Fatalf("captured bytes = %d, want %d", got, jlsMaxAuthenticationCaptureBytesPerServer)
	}
	fwd.releaseCapturedBytes("", jlsMaxAuthenticationCaptureBytesPerServer)
}

func TestJLSAuthenticationCapturePerClientLimit(t *testing.T) {
	fwd := &jlsForwarder{}
	clientKey := "192.0.2.1"
	if !fwd.reserveCapturedBytes(clientKey, jlsMaxAuthenticationCaptureBytesPerClient) {
		t.Fatal("failed to reserve the per-client capture budget")
	}
	if fwd.reserveCapturedBytes(clientKey, 1) {
		t.Fatal("per-client capture budget was exceeded")
	}
	otherClientKey := "198.51.100.1"
	if !fwd.reserveCapturedBytes(otherClientKey, 1) {
		t.Fatal("one client exhausted another client's capture budget")
	}
	fwd.releaseCapturedBytes(clientKey, jlsMaxAuthenticationCaptureBytesPerClient)
	fwd.releaseCapturedBytes(otherClientKey, 1)
	if got := fwd.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after release = %d, want 0", got)
	}
}

func TestJLSAuthenticationCaptureIncludesPacketWhenReceiveQueueFull(t *testing.T) {
	fwd := &jlsForwarder{}
	capture := &jlsForwardCapture{forwarder: fwd}
	conn := &Conn{jlsForwardCapture: capture}
	conn.receivedPackets.Init(protocol.MaxConnUnprocessedPackets)
	for i := 0; i < protocol.MaxConnUnprocessedPackets; i++ {
		conn.receivedPackets.PushBack(receivedPacket{})
	}
	packet := receivedPacket{
		data:       []byte("fallback packet"),
		remoteAddr: mustResolveUDPAddr(t, "127.0.0.1:12345"),
	}
	conn.handlePacket(packet)

	if len(capture.packets) != 1 || string(capture.packets[0]) != string(packet.data) {
		t.Fatalf("captured packets = %q, want %q", capture.packets, packet.data)
	}
	conn.releaseJLSForwardCapture()
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

func TestJLSTransportRejectsSourceAddressRetry(t *testing.T) {
	pc := newUDPConnLocalhost(t)
	defer pc.Close()
	tr := &Transport{
		Conn: pc,
		VerifySourceAddress: func(net.Addr) bool {
			return true
		},
	}
	_, err := tr.Listen(&tls.Config{JLSConfig: &tls.JLSConfig{
		Enable: true,
		Users:  []tls.JLSUser{{Username: "user", Password: "password"}},
	}}, &Config{JLSConfig: &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		},
	}})
	if !errors.Is(err, errJLSVerifySourceAddr) {
		t.Fatalf("Listen error = %v, want %v", err, errJLSVerifySourceAddr)
	}
}

func TestJLSTransportForwardsUnmatchedShortHeaderForPathValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		firstByte byte
	}{
		{name: "fixed bit set", firstByte: 0x40},
		{name: "fixed bit greased", firstByte: 0x00},
	} {
		t.Run(test.name, func(t *testing.T) {
			testJLSTransportForwardsUnmatchedShortHeaderForPathValidation(t, test.firstByte)
		})
	}
}

func testJLSTransportForwardsUnmatchedShortHeaderForPathValidation(t *testing.T, firstByte byte) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	server := newUDPConnLocalhost(t)
	tr := &Transport{Conn: server}
	listener, err := tr.Listen(&tls.Config{JLSConfig: &tls.JLSConfig{
		Enable: true,
		Users:  []tls.JLSUser{{Username: "user", Password: "password"}},
	}}, &Config{JLSConfig: &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer tr.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	packet := append([]byte{firstByte}, make([]byte, protocol.DefaultConnectionIDLength+16)...)
	if _, err := client.WriteTo(packet, tr.Conn.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(packet))
	n, _, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(packet) {
		t.Fatalf("forwarded unmatched short-header packet = %x, want %x", buf[:n], packet)
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

	clientAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	capture := newTestJLSForwardCapture(t, fwd, clientAddr, payload)
	fwd.activateForwardCapture(capture)
	if got := fwd.capturedBytes.Load(); got != 0 {
		t.Fatalf("captured bytes after activation = %d, want 0", got)
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

	next := newJLSReceivedPacket(make([]byte, protocol.MaxPacketBufferSize+1), clientAddr)
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("persistent fallback did not intercept the next packet")
	}
	if err := upstream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := upstream.ReadFrom(got); err == nil {
		t.Fatal("post-activation packet bypassed the fallback rate limit")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("reading rate-limited packet: %v", err)
	}
}

func TestJLSAuthenticationFallbackReplayDoesNotHoldForwarderLock(t *testing.T) {
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
	forwardConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	blockingConn := &jlsBlockingWritePacketConn{
		PacketConn: forwardConn,
		started:    writeStarted,
		release:    releaseWrite,
	}
	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return blockingConn, upstream.LocalAddr(), nil
		},
	})
	defer fwd.Close()
	var releaseOnce sync.Once
	unblockWrite := func() { releaseOnce.Do(func() { close(releaseWrite) }) }
	defer unblockWrite()

	capture := newTestJLSForwardCapture(t, fwd, mustResolveUDPAddr(t, "127.0.0.1:12345"), []byte("captured"))
	replayDone := make(chan struct{})
	go func() {
		fwd.activateForwardCapture(capture)
		close(replayDone)
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback replay did not start")
	}

	lockAcquired := make(chan struct{})
	go func() {
		fwd.mu.Lock()
		fwd.mu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
	case <-time.After(time.Second):
		t.Fatal("fallback replay held the forwarder lock")
	}

	unblockWrite()
	select {
	case <-replayDone:
	case <-time.After(time.Second):
		t.Fatal("fallback replay did not finish")
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
	unexpected, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unexpected.Close()

	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer fwd.Close()

	request := []byte("request")
	fwd.activateForwardCapture(newTestJLSForwardCapture(t, fwd, client.LocalAddr(), request))

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

	if _, err := unexpected.WriteTo([]byte("unexpected response"), forwardAddr); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFrom(buf); err == nil {
		t.Fatal("unexpected response source was relayed to the client")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("reading filtered response: %v", err)
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

func TestJLSForwarderRelaysVersionNegotiationAndKeepsTentativeFlow(t *testing.T) {
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

	request, destConnID, srcConnID := composeJLSUnsupportedVersionPacket([]byte("version probe"))
	packet := newJLSReceivedPacket(request, client.LocalAddr())
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()

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
	key, ok := jlsTentativeKeyForPacket(client.LocalAddr(), request)
	if !ok {
		t.Fatal("version probe did not produce a tentative key")
	}
	fwd.mu.Lock()
	tentative := fwd.tentative[key]
	fwd.mu.Unlock()
	if tentative == nil {
		t.Fatal("version probe was not tentative")
	}
	initialDeadline := time.Unix(100, 0)
	tentative.mu.Lock()
	tentative.deadline = initialDeadline
	tentative.mu.Unlock()
	response := wire.ComposeVersionNegotiation(srcConnID, destConnID, []protocol.Version{protocol.Version1})
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
	tentative.mu.Lock()
	refreshedDeadline := tentative.deadline
	tentative.mu.Unlock()
	if !refreshedDeadline.After(initialDeadline) {
		t.Fatalf("Version Negotiation response did not refresh deadline: initial %s, refreshed %s", initialDeadline, refreshedDeadline)
	}
	waitForJLSForwardCounts(t, fwd, 0, 1)

	next := newJLSReceivedPacket(request, client.LocalAddr())
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("Version Negotiation flow did not intercept a retransmission")
	}
	n, _, err = upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(request) {
		t.Fatalf("forwarded retransmission = %q, want %q", buf[:n], request)
	}
}

func TestJLSForwarderPromotesNonVersionNegotiationResponse(t *testing.T) {
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

	request, _, _ := composeJLSUnsupportedVersionPacket([]byte("initial"))
	packet := newJLSReceivedPacket(request, client.LocalAddr())
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()

	buf := make([]byte, 64<<10)
	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, forwardAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	firstResponse := []byte("upstream accepted version")
	if _, err := upstream.WriteTo(firstResponse, forwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, client, server.LocalAddr(), buf, firstResponse)
	waitForJLSForwardCounts(t, fwd, 1, 0)

	nextRequest := []byte("next request")
	next := newJLSReceivedPacket(nextRequest, client.LocalAddr())
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("promoted flow did not intercept the next client packet")
	}
	n, _, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(nextRequest) {
		t.Fatalf("forwarded payload = %q, want %q", buf[:n], nextRequest)
	}
	secondResponse := []byte("next response")
	if _, err := upstream.WriteTo(secondResponse, forwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, client, server.LocalAddr(), buf, secondResponse)
}

func TestJLSForwarderRelaysMismatchedVersionNegotiationWithoutPromoting(t *testing.T) {
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

	request, destConnID, _ := composeJLSUnsupportedVersionPacket([]byte("version probe"))
	packet := newJLSReceivedPacket(request, client.LocalAddr())
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()

	buf := make([]byte, 64<<10)
	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, forwardAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedConnID := protocol.ArbitraryLenConnectionID{0xde, 0xad, 0xbe, 0xef}
	response := wire.ComposeVersionNegotiation(mismatchedConnID, destConnID, []protocol.Version{protocol.Version1})
	if _, err := upstream.WriteTo(response, forwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, client, server.LocalAddr(), buf, response)
	waitForJLSForwardCounts(t, fwd, 0, 1)

	next := newJLSReceivedPacket(request, client.LocalAddr())
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("mismatched Version Negotiation response did not preserve the tentative flow")
	}
	n, _, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(request) {
		t.Fatalf("forwarded retransmission = %q, want %q", buf[:n], request)
	}
}

func TestJLSForwarderValidatesMigratedPathWithoutReplacingExistingPath(t *testing.T) {
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
	oldClient, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer oldClient.Close()
	newClient, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer newClient.Close()

	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: testJLSDialer(t, upstream),
	})
	defer fwd.Close()

	buf := make([]byte, 64<<10)
	fwd.activateForwardCapture(newTestJLSForwardCapture(t, fwd, oldClient.LocalAddr(), []byte("old path")))
	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, oldForwardAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	firstPathPacket := []byte{0x40, 1, 2, 3, 4}
	packet := newJLSReceivedPacket(firstPathPacket, newClient.LocalAddr())
	if !fwd.handleCamouflagePathPacket(packet) {
		t.Fatal("migrated path was not scheduled for validation")
	}
	packet.buffer.Release()
	n, newForwardAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(firstPathPacket) {
		t.Fatalf("first migrated-path packet = %x, want %x", buf[:n], firstPathPacket)
	}
	if newForwardAddr.String() == oldForwardAddr.String() {
		t.Fatal("migrated path reused the established upstream packet connection")
	}
	pathKey := newJLSTentativeForwardKey(newClient.LocalAddr(), jlsTentativeForwardPath, 0, nil)
	fwd.mu.Lock()
	tentative := fwd.tentative[pathKey]
	fwd.mu.Unlock()
	if tentative == nil {
		t.Fatal("migrated path was not tentative")
	}
	if _, ok := tentative.ctx.Deadline(); ok {
		t.Fatal("migrated path lifecycle inherited the initial dial deadline")
	}
	tentative.mu.Lock()
	initialDeadline := tentative.deadline
	tentative.mu.Unlock()

	firstPathResponse := []byte("path challenge")
	if _, err := upstream.WriteTo(firstPathResponse, newForwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, newClient, server.LocalAddr(), buf, firstPathResponse)
	waitForJLSForwardCounts(t, fwd, 1, 1)
	tentative.mu.Lock()
	extendedDeadline := tentative.deadline
	tentative.mu.Unlock()
	if extendedDeadline.Before(initialDeadline) || time.Until(extendedDeadline) < jlsForwardIdleTimeout/2 {
		t.Fatalf("migrated path deadline was shortened: initial %s, refreshed %s", initialDeadline, extendedDeadline)
	}

	oldPathResponse := []byte("old path remains active")
	if _, err := upstream.WriteTo(oldPathResponse, oldForwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, oldClient, server.LocalAddr(), buf, oldPathResponse)

	secondPathPacket := []byte{0x40, 5, 6, 7, 8}
	next := newJLSReceivedPacket(secondPathPacket, newClient.LocalAddr())
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("validated client path response was not forwarded")
	}
	n, responseAddr, err := upstream.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(secondPathPacket) {
		t.Fatalf("second migrated-path packet = %x, want %x", buf[:n], secondPathPacket)
	}
	if responseAddr.String() != newForwardAddr.String() {
		t.Fatalf("second migrated-path source = %s, want %s", responseAddr, newForwardAddr)
	}

	validatedResponse := []byte("path validated")
	if _, err := upstream.WriteTo(validatedResponse, newForwardAddr); err != nil {
		t.Fatal(err)
	}
	assertJLSForwardedResponse(t, newClient, server.LocalAddr(), buf, validatedResponse)
	waitForJLSForwardCounts(t, fwd, 2, 0)

	fwd.mu.Lock()
	oldPath := fwd.conns[jlsAddrKey(oldClient.LocalAddr())]
	newPath := fwd.conns[jlsAddrKey(newClient.LocalAddr())]
	fwd.mu.Unlock()
	if oldPath == nil || newPath == nil || oldPath == newPath {
		t.Fatalf("forwarded paths = old %p, new %p", oldPath, newPath)
	}
	if oldPath.clientConn.RemoteAddr().String() != oldClient.LocalAddr().String() || newPath.clientConn.RemoteAddr().String() != newClient.LocalAddr().String() {
		t.Fatal("forwarded path changed another path's client address")
	}
}

func TestJLSForwarderQueuesPacketsWhileTentativeDialIsPending(t *testing.T) {
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
	clientAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	dial := make(chan struct{})
	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: func(ctx context.Context, network, _ string) (net.PacketConn, net.Addr, error) {
			select {
			case <-dial:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			pc, err := net.ListenPacket(network, "127.0.0.1:0")
			return pc, upstream.LocalAddr(), err
		},
	})
	defer fwd.Close()

	first, _, _ := composeJLSUnsupportedVersionPacket([]byte("first"))
	packet := newJLSReceivedPacket(first, clientAddr)
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()
	second, _, _ := composeJLSUnsupportedVersionPacket([]byte("second"))
	next := newJLSReceivedPacket(second, clientAddr)
	if !fwd.handleForwardedClientPacket(next) {
		t.Fatal("packet was not queued during tentative dialing")
	}
	close(dial)

	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	for i, want := range [][]byte{first, second} {
		n, _, err := upstream.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != string(want) {
			t.Fatalf("forwarded packet %d = %q, want %q", i, buf[:n], want)
		}
	}
}

func TestJLSTentativeForwardResetsIdleDeadlineAfterDial(t *testing.T) {
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

	dialDeadline := make(chan time.Time, 1)
	readDeadline := make(chan time.Time, 1)
	releaseDial := make(chan struct{})
	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: upstream.LocalAddr().String(),
		PacketDialer: func(ctx context.Context, network, _ string) (net.PacketConn, net.Addr, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("tentative dial context has no deadline")
				return nil, nil, nil
			}
			dialDeadline <- deadline
			<-releaseDial
			pc, err := net.ListenPacket(network, "127.0.0.1:0")
			if err != nil {
				return nil, nil, err
			}
			return &jlsDeadlinePacketConn{PacketConn: pc, readDeadline: readDeadline}, upstream.LocalAddr(), nil
		},
	})
	defer fwd.Close()

	request, _, _ := composeJLSUnsupportedVersionPacket(nil)
	packet := newJLSReceivedPacket(request, mustResolveUDPAddr(t, "127.0.0.1:12345"))
	started := time.Now()
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()

	var dial, read time.Time
	select {
	case dial = <-dialDeadline:
	case <-time.After(time.Second):
		t.Fatal("packet dialer did not receive a deadline")
	}
	time.Sleep(10 * time.Millisecond)
	close(releaseDial)
	select {
	case read = <-readDeadline:
	case <-time.After(time.Second):
		t.Fatal("forwarded packet connection did not receive a read deadline")
	}
	if !read.After(dial) {
		t.Fatalf("read deadline %s was not reset after dial deadline %s", read, dial)
	}
	if dial.Before(started.Add(jlsForwardIdleTimeout)) || dial.After(time.Now().Add(jlsForwardIdleTimeout)) {
		t.Fatalf("tentative deadline %s is outside the expected lifetime from %s", dial, started)
	}
}

func TestJLSForwarderLimitsAndReplacesPerClientTentativePaths(t *testing.T) {
	fwd := newBlockingJLSTentativeForwarder()
	request := []byte{0x40, 1, 2, 3, 4}
	clientIP := net.IPv4(127, 0, 0, 1)
	for i := 0; i < jlsMaxTentativePathsPerClient; i++ {
		addr := &net.UDPAddr{IP: clientIP, Port: 12000 + i}
		packet := newJLSReceivedPacket(request, addr)
		if !fwd.handleCamouflagePathPacket(packet) {
			t.Fatalf("tentative path %d was rejected", i)
		}
		packet.buffer.Release()
	}

	nextAddr := &net.UDPAddr{IP: clientIP, Port: 13000}
	clientKey := jlsClientIPKey(nextAddr)
	fwd.mu.Lock()
	_, first := fwd.oldestTentativeForwardLocked(clientKey, true)
	client := fwd.tentativeClients[clientKey]
	client.rate.tokens = 0
	client.rate.updated = time.Now()
	fwd.mu.Unlock()
	packet := newJLSReceivedPacket(request, nextAddr)
	if fwd.handleCamouflagePathPacket(packet) {
		t.Fatal("per-client creation rate limit accepted an immediate excess path")
	}
	packet.buffer.Release()

	fwd.mu.Lock()
	client.rate.tokens = 1
	client.rate.updated = time.Now()
	fwd.mu.Unlock()
	packet = newJLSReceivedPacket(request, nextAddr)
	if !fwd.handleCamouflagePathPacket(packet) {
		t.Fatal("replenished client was unable to replace its oldest tentative path")
	}
	packet.buffer.Release()

	select {
	case <-first.ctx.Done():
	default:
		t.Fatal("replaced tentative flow was not canceled")
	}
	fwd.mu.Lock()
	flowCount := len(fwd.tentative)
	clientCount := client.forwards
	pathCount := client.paths
	_, nextPresent := fwd.tentative[newJLSTentativeForwardKey(nextAddr, jlsTentativeForwardPath, 0, nil)]
	fwd.mu.Unlock()
	if flowCount != jlsMaxTentativePathsPerClient || clientCount != jlsMaxTentativePathsPerClient || pathCount != jlsMaxTentativePathsPerClient || !nextPresent {
		t.Fatalf("per-client paths = %d, tracked = %d/%d, next present = %t", flowCount, clientCount, pathCount, nextPresent)
	}
	fwd.Close()
}

func TestJLSForwarderDoesNotApplyPathLimitToVersionProbes(t *testing.T) {
	fwd := newBlockingJLSTentativeForwarder()
	request, _, _ := composeJLSUnsupportedVersionPacket(nil)
	clientIP := net.IPv4(127, 0, 0, 1)
	for i := 0; i <= jlsMaxTentativePathsPerClient; i++ {
		addr := &net.UDPAddr{IP: clientIP, Port: 12000 + i}
		packet := newJLSReceivedPacket(request, addr)
		if !fwd.handleCamouflageVersionPacket(packet) {
			t.Fatalf("version probe %d was rejected by the path limit", i)
		}
		packet.buffer.Release()
	}
	fwd.Close()
}

func TestJLSForwarderLimitsAndReplacesGlobalTentativeFlows(t *testing.T) {
	fwd := newBlockingJLSTentativeForwarder()
	request, _, srcConnID := composeJLSUnsupportedVersionPacket(nil)
	for i := 0; i < jlsMaxTentativeForwards; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(10, 0, byte(i), 1), Port: 12000 + i}
		packet := newJLSReceivedPacket(request, addr)
		if !fwd.handleCamouflageVersionPacket(packet) {
			t.Fatalf("tentative flow %d was rejected", i)
		}
		packet.buffer.Release()
	}

	nextAddr := mustResolveUDPAddr(t, "192.0.2.1:13000")
	fwd.mu.Lock()
	_, first := fwd.oldestTentativeForwardLocked("", false)
	fwd.tentativeRate.tokens = 0
	fwd.tentativeRate.updated = time.Now()
	fwd.mu.Unlock()
	packet := newJLSReceivedPacket(request, nextAddr)
	if fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("global creation rate limit accepted a flow after exhausting its burst")
	}
	packet.buffer.Release()

	fwd.mu.Lock()
	fwd.tentativeRate.tokens = 1
	fwd.tentativeRate.updated = time.Now()
	fwd.mu.Unlock()
	packet = newJLSReceivedPacket(request, nextAddr)
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("replenished server was unable to replace its oldest tentative flow")
	}
	packet.buffer.Release()

	select {
	case <-first.ctx.Done():
	default:
		t.Fatal("globally replaced tentative flow was not canceled")
	}
	fwd.mu.Lock()
	flowCount := len(fwd.tentative)
	_, nextPresent := fwd.tentative[newJLSTentativeForwardKey(nextAddr, jlsTentativeForwardVersionProbe, 0xff00001d, srcConnID)]
	fwd.mu.Unlock()
	if flowCount != jlsMaxTentativeForwards || !nextPresent {
		t.Fatalf("global tentative flows = %d, next present = %t", flowCount, nextPresent)
	}
	fwd.Close()
}

func TestJLSForwarderDoesNotInterceptAnotherVersionDuringTentativeForward(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	dial := make(chan struct{})
	fwd := newJLSForwarder(&basicConn{PacketConn: server}, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(ctx context.Context, _, _ string) (net.PacketConn, net.Addr, error) {
			select {
			case <-dial:
				return nil, nil, nil
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		},
	})
	defer fwd.Close()

	clientAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	request, _, _ := composeJLSUnsupportedVersionPacket(nil)
	packet := newJLSReceivedPacket(request, clientAddr)
	if !fwd.handleCamouflageVersionPacket(packet) {
		t.Fatal("tentative version forwarding was not scheduled")
	}
	packet.buffer.Release()

	supportedVersionPacket := append([]byte(nil), request...)
	binary.BigEndian.PutUint32(supportedVersionPacket[1:5], uint32(protocol.Version1))
	next := newJLSReceivedPacket(supportedVersionPacket, clientAddr)
	if fwd.handleForwardedClientPacket(next) {
		t.Fatal("tentative flow intercepted a packet using another QUIC version")
	}
	next.buffer.Release()
}

func TestJLSForwarderKeepsConcurrentProbesSeparate(t *testing.T) {
	fwd := newBlockingJLSTentativeForwarder()
	defer fwd.Close()
	clientAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")

	first, _, _ := composeJLSUnsupportedVersionPacket(nil)
	second := append([]byte(nil), first...)
	binary.BigEndian.PutUint32(second[1:5], 0x12345678)
	second[15]++
	for i, data := range [][]byte{first, second} {
		packet := newJLSReceivedPacket(data, clientAddr)
		if !fwd.handleCamouflageVersionPacket(packet) {
			t.Fatalf("version probe %d was rejected", i)
		}
		packet.buffer.Release()
	}
	pathData := []byte{0x40, 1, 2, 3, 4}
	pathPacket := newJLSReceivedPacket(pathData, clientAddr)
	if !fwd.handleCamouflagePathPacket(pathPacket) {
		t.Fatal("path probe was rejected while version probes were pending")
	}
	pathPacket.buffer.Release()

	fwd.mu.Lock()
	count := len(fwd.tentative)
	_, firstPresent := fwd.tentativeKeyForTest(clientAddr, first)
	_, secondPresent := fwd.tentativeKeyForTest(clientAddr, second)
	_, pathPresent := fwd.tentativeKeyForTest(clientAddr, pathData)
	fwd.mu.Unlock()
	if count != 3 || !firstPresent || !secondPresent || !pathPresent {
		t.Fatalf("concurrent probes = %d, present = %t/%t/%t", count, firstPresent, secondPresent, pathPresent)
	}
}

func (f *jlsForwarder) tentativeKeyForTest(addr net.Addr, data []byte) (jlsTentativeForwardKey, bool) {
	key, ok := jlsTentativeKeyForPacket(addr, data)
	if !ok {
		return key, false
	}
	_, present := f.tentative[key]
	return key, present
}

func TestJLSTransportSuppressesStatelessResetWhenForwardingIsLimited(t *testing.T) {
	pc := newUDPConnLocalhost(t)
	resetKey := StatelessResetKey{1, 2, 3, 4}
	tr := &Transport{Conn: pc, ConnectionIDLength: 4, StatelessResetKey: &resetKey}
	if err := tr.init(true); err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	fwd := newJLSForwarder(tr.conn, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		},
	})
	defer fwd.Close()
	fwd.mu.Lock()
	fwd.tentativeRate.tokens = 0
	fwd.tentativeRate.updated = time.Now()
	fwd.mu.Unlock()
	tr.jlsForwarder.Store(fwd)

	data := append([]byte{0x40, 1, 2, 3, 4}, make([]byte, protocol.MinStatelessResetSize)...)
	tr.handlePacket(newJLSReceivedPacket(data, mustResolveUDPAddr(t, "127.0.0.1:12345")))
	if queued := len(tr.statelessResetQueue); queued != 0 {
		t.Fatalf("queued stateless resets = %d, want 0", queued)
	}
}

func TestJLSForwarderCloseDetachesTentativeFlows(t *testing.T) {
	fwd := newJLSForwarder(nil, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, nil
		},
	})
	clientAddr := mustResolveUDPAddr(t, "127.0.0.1:12345")
	key := newJLSTentativeForwardKey(clientAddr, jlsTentativeForwardVersionProbe, 0xff00001d, protocol.ArbitraryLenConnectionID{9, 10, 11, 12})
	fwd.tentative[key] = &jlsTentativeForward{version: 0xff00001d}
	packet, _, _ := composeJLSUnsupportedVersionPacket(nil)
	firstHandled := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		handled := fwd.handleCamouflageVersionPacket(receivedPacket{data: packet, remoteAddr: clientAddr})
		firstHandled <- handled
		for handled {
			handled = fwd.handleCamouflageVersionPacket(receivedPacket{data: packet, remoteAddr: clientAddr})
		}
		close(done)
	}()
	if !<-firstHandled {
		t.Fatal("tentative flow did not handle the first packet")
	}
	fwd.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("camouflage version handler did not return during concurrent close")
	}

	fwd.mu.Lock()
	remaining := len(fwd.tentative)
	fwd.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("tentative flows after close = %d, want 0", remaining)
	}

	assertJLSForwarderHandlerReturns(t, "forwarded packet", func() bool {
		return fwd.handleForwardedClientPacket(receivedPacket{data: packet, remoteAddr: clientAddr})
	})
}

func composeJLSUnsupportedVersionPacket(payload []byte) ([]byte, protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID) {
	destConnID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	srcConnID := protocol.ArbitraryLenConnectionID{9, 10, 11, 12}
	packet := []byte{0xc0}
	packet = binary.BigEndian.AppendUint32(packet, 0xff00001d)
	packet = append(packet, byte(destConnID.Len()))
	packet = append(packet, destConnID.Bytes()...)
	packet = append(packet, byte(srcConnID.Len()))
	packet = append(packet, srcConnID.Bytes()...)
	packet = append(packet, payload...)
	return packet, destConnID, srcConnID
}

func waitForJLSForwardCounts(t *testing.T, fwd *jlsForwarder, persistent, tentative int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		fwd.mu.Lock()
		gotPersistent, gotTentative := len(fwd.conns), len(fwd.tentative)
		fwd.mu.Unlock()
		if gotPersistent == persistent && gotTentative == tentative {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward counts = persistent %d, tentative %d; want %d, %d", gotPersistent, gotTentative, persistent, tentative)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertJLSForwardedResponse(t *testing.T, client net.PacketConn, serverAddr net.Addr, buf, want []byte) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, sourceAddr, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("relayed response = %q, want %q", buf[:n], want)
	}
	if sourceAddr.String() != serverAddr.String() {
		t.Fatalf("response source = %s, want listener %s", sourceAddr, serverAddr)
	}
}

func assertJLSForwarderHandlerReturns(t *testing.T, name string, handler func() bool) {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- handler() }()
	select {
	case handled := <-done:
		if handled {
			t.Fatalf("%s was handled after the forwarder closed", name)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s handler did not return after the forwarder closed", name)
	}
}

type jlsDeadlinePacketConn struct {
	net.PacketConn
	readDeadline chan<- time.Time
}

type jlsFailingReadDeadlinePacketConn struct {
	net.PacketConn
}

func (*jlsFailingReadDeadlinePacketConn) SetReadDeadline(time.Time) error {
	return errors.New("jls test read deadline failure")
}

func (c *jlsDeadlinePacketConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline <- deadline
	return c.PacketConn.SetReadDeadline(deadline)
}

type jlsBlockingWritePacketConn struct {
	net.PacketConn
	once    sync.Once
	started chan<- struct{}
	release <-chan struct{}
}

func (c *jlsBlockingWritePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.once.Do(func() {
		close(c.started)
		<-c.release
	})
	return c.PacketConn.WriteTo(p, addr)
}

func newBlockingJLSTentativeForwarder() *jlsForwarder {
	return newJLSForwarder(nil, &JLSConfig{
		UpstreamAddr: "127.0.0.1:443",
		PacketDialer: func(ctx context.Context, _, _ string) (net.PacketConn, net.Addr, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	})
}

func newTestJLSForwardCapture(t *testing.T, fwd *jlsForwarder, clientAddr net.Addr, packets ...[]byte) *jlsForwardCapture {
	t.Helper()
	var capturedBytes int
	for _, packet := range packets {
		capturedBytes += len(packet)
	}
	clientKey := jlsClientIPKey(clientAddr)
	if !fwd.reserveCapturedBytes(clientKey, capturedBytes) {
		t.Fatalf("failed to reserve %d captured bytes", capturedBytes)
	}
	return &jlsForwardCapture{
		forwarder:  fwd,
		clientKey:  clientKey,
		clientAddr: clientAddr,
		packets:    packets,
		bytes:      capturedBytes,
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

	payload, err := (&wire.CryptoFrame{Offset: offset, Data: cryptoData}).Append(nil, version)
	if err != nil {
		t.Fatal(err)
	}
	return composeJLSInitialPacketPayload(t, version, dcid, token, packetNumber, payload)
}

func composeJLSInitialPacketPayload(t *testing.T, version protocol.Version, dcid, token []byte, packetNumber protocol.PacketNumber, payload []byte) []byte {
	t.Helper()

	destConnID := protocol.ParseConnectionID(dcid)
	srcConnID := protocol.ParseConnectionID([]byte{9, 8, 7, 6})
	sealer, _ := handshake.NewInitialAEAD(destConnID, protocol.PerspectiveClient, version)

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
