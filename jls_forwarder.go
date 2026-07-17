package quic

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/utils"
	tls "github.com/metacubex/jls-tls"
)

// JLS BEGIN: JLS camouflage forwarding support.

const (
	jlsRateLimitBurstPeriod  = 10 * time.Millisecond
	jlsForwardIdleTimeout    = 2 * time.Minute
	jlsForwardRecvBufferSize = 32 * 32 * 1024
	jlsMaxCapturedPackets    = 32
	jlsMaxCapturedBytes      = 64 << 10
)

var errJLSConfigDisabled = errors.New("quic: JLS forwarding requires TLS JLS")

type jlsForwarder struct {
	conn   rawConn
	cfg    *JLSConfig
	dialer JLSPacketDialer
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  map[string]*jlsForwardConn
	closed bool
}

type jlsForwardConn struct {
	conn         net.PacketConn
	upstreamAddr net.Addr
	clientConn   sendConn
	sendLimiter  *jlsRateLimiter
	recvLimiter  *jlsRateLimiter
	mu           sync.Mutex
	active       time.Time
}

type jlsForwardCaptureState uint8

const (
	jlsForwardCaptureActive jlsForwardCaptureState = iota
	jlsForwardCaptureActivating
	jlsForwardCaptureForwarded
	jlsForwardCaptureDisabled
)

type jlsForwardCapture struct {
	mu         sync.Mutex
	forwarder  *jlsForwarder
	state      jlsForwardCaptureState
	clientAddr net.Addr
	clientInfo packetInfo
	packets    [][]byte
	bytes      int
	overflow   bool
}

func (c *JLSConfig) forwardingEnabled() bool {
	return c != nil && c.UpstreamAddr != "" && c.PacketDialer != nil
}

type jlsFallbackError struct {
	err error
}

func (e *jlsFallbackError) Error() string { return e.err.Error() }

func (e *jlsFallbackError) Unwrap() error { return e.err }

func newJLSForwarder(conn rawConn, cfg *JLSConfig) *jlsForwarder {
	if !cfg.forwardingEnabled() {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &jlsForwarder{
		conn:   conn,
		cfg:    cfg,
		dialer: cfg.PacketDialer,
		ctx:    ctx,
		cancel: cancel,
		conns:  make(map[string]*jlsForwardConn),
	}
}

func (c *Conn) enableJLSForwarding(forwarder *jlsForwarder) {
	if forwarder != nil {
		c.jlsForwardCapture = &jlsForwardCapture{forwarder: forwarder}
	}
}

func (c *Conn) handleJLSPacket(p receivedPacket, capture bool) bool {
	pending := c.jlsForwardCapture
	if pending == nil {
		return false
	}

	pending.mu.Lock()
	if pending.state == jlsForwardCaptureForwarded {
		forwarder := pending.forwarder
		pending.mu.Unlock()
		if !forwarder.handleForwardedClientPacket(p) {
			p.buffer.Release()
		}
		return true
	}
	if capture && (pending.state == jlsForwardCaptureActive || pending.state == jlsForwardCaptureActivating) {
		if pending.clientAddr == nil {
			pending.clientAddr = p.remoteAddr
			pending.clientInfo = p.info
		}
		packetSize := len(p.data)
		if len(pending.packets) >= jlsMaxCapturedPackets || pending.bytes+packetSize > jlsMaxCapturedBytes {
			pending.packets = nil
			pending.bytes = 0
			pending.overflow = true
		} else if !pending.overflow {
			pending.packets = append(pending.packets, append([]byte(nil), p.data...))
			pending.bytes += packetSize
		}
	}
	pending.mu.Unlock()
	return false
}

func (c *Conn) handleJLSCryptoData(data []byte, encLevel protocol.EncryptionLevel) error {
	err := c.cryptoStreamHandler.HandleMessage(data, encLevel)
	if err == nil && c.jlsForwardCapture != nil && c.cryptoStreamHandler.ConnectionState().JLS.Status == tls.JLSDisabled {
		return errJLSConfigDisabled
	}
	return err
}

func (c *Conn) handleJLSHandshakeResult(err error) error {
	pending := c.jlsForwardCapture
	if pending == nil {
		return err
	}
	authenticated := err == nil && c.cryptoStreamHandler.ConnectionState().JLS.Status == tls.JLSAuthenticated
	pending.mu.Lock()
	defer pending.mu.Unlock()
	if err != nil {
		if pending.state == jlsForwardCaptureActive {
			return &jlsFallbackError{err: err}
		}
		return err
	}
	if authenticated && pending.state == jlsForwardCaptureActive {
		pending.state = jlsForwardCaptureDisabled
		pending.packets = nil
		pending.bytes = 0
	}
	return nil
}

func (c *Conn) forwardJLSFallback() {
	pending := c.jlsForwardCapture
	if pending != nil {
		pending.forwarder.activateForwardCapture(pending)
	}
}

func (c *jlsForwardCapture) beginActivation() (net.Addr, packetInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != jlsForwardCaptureActive {
		return nil, packetInfo{}, false
	}
	if c.overflow || c.clientAddr == nil || len(c.packets) == 0 {
		c.disable()
		return nil, packetInfo{}, false
	}
	c.state = jlsForwardCaptureActivating
	return c.clientAddr, c.clientInfo, true
}

func (c *jlsForwardCapture) completeActivation(forwarded bool) ([][]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != jlsForwardCaptureActivating {
		return nil, false
	}
	if !forwarded || c.overflow {
		c.disable()
		return nil, false
	}
	packets := c.packets
	c.state = jlsForwardCaptureForwarded
	c.packets = nil
	c.bytes = 0
	return packets, true
}

func (c *jlsForwardCapture) disable() {
	c.state = jlsForwardCaptureDisabled
	c.packets = nil
	c.bytes = 0
}

func (f *jlsForwarder) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.cancel()
	for _, conn := range f.conns {
		_ = conn.conn.Close()
	}
	f.mu.Unlock()
}

func (f *jlsForwarder) handleForwardedClientPacket(p receivedPacket) bool {
	if f == nil {
		return false
	}
	fwd := f.getForwardConn(p.remoteAddr)
	if fwd == nil {
		return false
	}
	f.forwardToUpstream(fwd, p.data)
	p.buffer.Release()
	return true
}

func (f *jlsForwarder) handleCamouflageVersionPacket(p receivedPacket) bool {
	if f == nil {
		return false
	}
	fwd := f.newForwardConn(p)
	if fwd == nil {
		return false
	}
	f.writeToUpstream(fwd, p.data)
	return true
}

func (f *jlsForwarder) getForwardConn(clientAddr net.Addr) *jlsForwardConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns[jlsAddrKey(clientAddr)]
}

func (f *jlsForwarder) activateForwardCapture(capture *jlsForwardCapture) {
	clientAddr, clientInfo, ok := capture.beginActivation()
	if !ok {
		return
	}

	prepared := f.dialForwardConn(clientAddr, clientInfo)
	if prepared == nil {
		capture.completeActivation(false)
		return
	}

	key := jlsAddrKey(clientAddr)
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = prepared.conn.Close()
		capture.completeActivation(false)
		return
	}
	target := f.conns[key]
	startReader := false
	if target == nil {
		target = prepared
		startReader = true
	} else {
		_ = prepared.conn.Close()
	}
	packets, ok := capture.completeActivation(true)
	if !ok {
		f.mu.Unlock()
		if startReader {
			_ = target.conn.Close()
		}
		return
	}
	for _, packet := range packets {
		f.writeToUpstream(target, packet)
	}
	if startReader {
		f.conns[key] = target
	}
	f.mu.Unlock()

	if startReader {
		go f.readForwardConn(key, target)
	}
}

func (f *jlsForwarder) newForwardConn(p receivedPacket) *jlsForwardConn {
	key := jlsAddrKey(p.remoteAddr)
	f.mu.Lock()
	if fwd := f.conns[key]; fwd != nil {
		f.mu.Unlock()
		return fwd
	}
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()

	fwd := f.dialForwardConn(p.remoteAddr, p.info)
	if fwd == nil {
		return nil
	}

	f.mu.Lock()
	if existing := f.conns[key]; existing != nil {
		f.mu.Unlock()
		_ = fwd.conn.Close()
		return existing
	}
	if f.closed {
		f.mu.Unlock()
		_ = fwd.conn.Close()
		return nil
	}
	f.conns[key] = fwd
	f.mu.Unlock()

	go f.readForwardConn(key, fwd)
	return fwd
}

func (f *jlsForwarder) dialForwardConn(clientAddr net.Addr, clientInfo packetInfo) *jlsForwardConn {
	pc, upstreamAddr, err := f.dialer(f.ctx, "udp", f.cfg.UpstreamAddr)
	if err != nil || pc == nil || upstreamAddr == nil {
		if pc != nil {
			_ = pc.Close()
		}
		return nil
	}
	return &jlsForwardConn{
		conn:         pc,
		upstreamAddr: upstreamAddr,
		clientConn:   newSendConn(f.conn, clientAddr, clientInfo, utils.DefaultLogger),
		sendLimiter:  newJLSRateLimiter(f.cfg.RateLimit),
		recvLimiter:  newJLSRateLimiter(f.cfg.RateLimit),
		active:       time.Now(),
	}
}

func (f *jlsForwarder) readForwardConn(key string, fwd *jlsForwardConn) {
	defer func() {
		_ = fwd.conn.Close()
		f.mu.Lock()
		if f.conns[key] == fwd {
			delete(f.conns, key)
		}
		f.mu.Unlock()
	}()

	buf := make([]byte, jlsForwardRecvBufferSize)
	for {
		_ = fwd.conn.SetReadDeadline(time.Now().Add(jlsForwardIdleTimeout))
		n, _, err := fwd.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && fwd.idleFor(time.Now()) < jlsForwardIdleTimeout {
				continue
			}
			return
		}
		fwd.touch(time.Now())
		if fwd.recvLimiter.allow(n) {
			_ = fwd.clientConn.Write(buf[:n], 0, protocol.ECNUnsupported)
		}
	}
}

func (f *jlsForwarder) forwardToUpstream(fwd *jlsForwardConn, data []byte) {
	fwd.touch(time.Now())
	if fwd.sendLimiter.allow(len(data)) {
		_, _ = fwd.conn.WriteTo(data, fwd.upstreamAddr)
	}
}

func (f *jlsForwarder) writeToUpstream(fwd *jlsForwardConn, data []byte) {
	fwd.touch(time.Now())
	_, _ = fwd.conn.WriteTo(data, fwd.upstreamAddr)
}

func jlsAddrKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.Network() + "|" + addr.String()
}

func (f *jlsForwardConn) touch(t time.Time) {
	f.mu.Lock()
	f.active = t
	f.mu.Unlock()
}

func (f *jlsForwardConn) idleFor(t time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return t.Sub(f.active)
}

type jlsRateLimiter struct {
	mu                 sync.Mutex
	unlimited          bool
	rateBytesPerSecond float64
	burst              float64
	available          float64
	last               time.Time
}

func newJLSRateLimiter(rateBps uint64) *jlsRateLimiter {
	if rateBps == 0 {
		return &jlsRateLimiter{unlimited: true}
	}
	rateBytesPerSecond := float64(rateBps) / 8
	burst := rateBytesPerSecond * jlsRateLimitBurstPeriod.Seconds()
	if burst < protocol.MaxPacketBufferSize {
		burst = protocol.MaxPacketBufferSize
	}
	now := time.Now()
	return &jlsRateLimiter{
		rateBytesPerSecond: rateBytesPerSecond,
		burst:              burst,
		available:          burst,
		last:               now,
	}
}

func (l *jlsRateLimiter) allow(n int) bool {
	return l.allowAt(n, time.Now())
}

func (l *jlsRateLimiter) allowAt(n int, now time.Time) bool {
	if l == nil || l.unlimited {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.available += elapsed * l.rateBytesPerSecond
		if l.available > l.burst {
			l.available = l.burst
		}
		l.last = now
	}
	if float64(n) > l.available {
		return false
	}
	l.available -= float64(n)
	return true
}

// JLS END
