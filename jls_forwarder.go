package quic

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/qerr"
	"github.com/metacubex/jls-quic-go/internal/utils"
	"github.com/metacubex/jls-quic-go/internal/wire"
	tls "github.com/metacubex/jls-tls"
)

// JLS BEGIN: JLS camouflage forwarding support.

const (
	jlsRateLimitBurstPeriod = 10 * time.Millisecond
	jlsForwardIdleTimeout   = 2 * time.Minute
	// Tentative forwarding handles unauthenticated version probes and new QUIC
	// paths. Keep its concurrency and creation rate bounded.
	jlsMaxTentativeForwards = 64
	// A single client can use at most one quarter of the global capacity for
	// longer-lived path validation, leaving capacity for other client IPs.
	jlsMaxTentativePathsPerClient = jlsMaxTentativeForwards / 4
	jlsMaxTentativeClients        = 1024
	// Keep replacement churn bounded independently from the longer idle lifetime.
	jlsTentativeForwardsPerSecond       = jlsMaxTentativeForwards
	jlsTentativeForwardBurst            = jlsMaxTentativeForwards
	jlsTentativePathsPerClientPerSecond = jlsMaxTentativePathsPerClient
	jlsTentativePathsPerClientBurst     = jlsMaxTentativePathsPerClient
	jlsForwardRecvBufferSize            = 64 << 10
	// Persistent fallback sockets are substantially more expensive than
	// tentative probes. Bound both concurrent state and creation churn.
	jlsMaxForwardConns                = 4 * jlsMaxTentativeForwards
	jlsMaxForwardConnsPerClient       = jlsMaxTentativePathsPerClient
	jlsForwardConnsPerSecond          = jlsTentativeForwardsPerSecond
	jlsForwardConnBurst               = jlsForwardConnsPerSecond
	jlsForwardConnsPerClientPerSecond = jlsMaxForwardConnsPerClient
	jlsForwardConnPerClientBurst      = jlsMaxForwardConnsPerClient
	// Authenticating QUIC connections are more expensive than forwarding
	// candidates. Bound both live state and rapid failed-handshake churn.
	jlsMaxAuthenticatingConns                = jlsMaxForwardConns
	jlsMaxAuthenticatingConnsPerClient       = jlsMaxForwardConnsPerClient
	jlsAuthenticatingConnsPerSecond          = jlsMaxAuthenticatingConns
	jlsAuthenticatingConnBurst               = jlsMaxAuthenticatingConns
	jlsAuthenticatingConnsPerClientPerSecond = jlsMaxAuthenticatingConnsPerClient
	jlsAuthenticatingConnPerClientBurst      = jlsMaxAuthenticatingConnsPerClient

	jlsMaxAuthenticationCaptureBytes = 10 << 20
	// Allow two full captures behind one client IP without letting that source
	// consume the server-wide fallback budget.
	jlsMaxAuthenticationCaptureBytesPerClient = 2 * jlsMaxAuthenticationCaptureBytes
	jlsMaxAuthenticationCaptureBytesPerServer = 100 << 20
	jlsMaxPreAuthOutputPackets                = 64
	jlsMaxPreAuthOutputBytes                  = 64 << 10
	jlsMaxTentativeCapturedPackets            = 32
	jlsMaxTentativeCapturedBytes              = 64 << 10
)

var (
	errJLSConfigDisabled     = errors.New("quic: JLS forwarding requires TLS JLS")
	errJLSPreAuthOutputLimit = errors.New("quic: JLS pre-authentication output limit exceeded")
	errJLSVerifySourceAddr   = errors.New("quic: JLS forwarding cannot be used with VerifySourceAddress")
)

type jlsForwarder struct {
	conn   rawConn
	cfg    *JLSConfig
	dialer JLSPacketDialer
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conns     map[string]*jlsForwardConn
	tentative map[jlsTentativeForwardKey]*jlsTentativeForward
	closed    bool

	tentativeRate       jlsTentativeRateLimiter
	forwardRate         jlsTentativeRateLimiter
	authenticationRate  jlsTentativeRateLimiter
	tentativeClients    map[string]*jlsTentativeClient
	tentativeSequence   uint64
	forwardCount        int
	authenticationCount int
	capturedBytes       atomic.Int64
}

type jlsForwardConn struct {
	conn         net.PacketConn
	upstreamAddr net.Addr
	clientConn   sendConn
	sendLimiter  *jlsRateLimiter
	recvLimiter  *jlsRateLimiter
	mu           sync.Mutex
	active       time.Time
	clientKey    string
	counted      bool
}

type jlsTentativeForwardKind uint8

const (
	jlsTentativeForwardVersionProbe jlsTentativeForwardKind = iota
	jlsTentativeForwardPath
)

type jlsTentativeForwardKey struct {
	clientAddr      string
	kind            jlsTentativeForwardKind
	version         protocol.Version
	clientSrcConnID string
}

type jlsTentativeForward struct {
	mu                      sync.Mutex
	fwd                     *jlsForwardConn
	ctx                     context.Context
	cancel                  context.CancelFunc
	deadline                time.Time
	sequence                uint64
	clientKey               string
	kind                    jlsTentativeForwardKind
	version                 protocol.Version
	clientSrcConnID         protocol.ArbitraryLenConnectionID
	packets                 [][]byte
	bytes                   int
	pathResponseRelayed     bool
	pathPacketAfterResponse bool
	done                    bool
}

type jlsTentativeClient struct {
	forwards           int
	paths              int
	fallbacks          int
	authenticating     int
	capturedBytes      int64
	rate               jlsTentativeRateLimiter
	fallbackRate       jlsTentativeRateLimiter
	authenticationRate jlsTentativeRateLimiter
	lastSeen           time.Time
}

type jlsTentativeRateLimiter struct {
	tokens  float64
	updated time.Time
}

type jlsForwardCaptureState uint8

const (
	jlsForwardCaptureActive jlsForwardCaptureState = iota
	jlsForwardCaptureActivating
	jlsForwardCaptureForwarded
	jlsForwardCaptureDisabled
)

type jlsForwardCapture struct {
	mu             sync.Mutex
	forwarder      *jlsForwarder
	sendConn       *jlsPreAuthSendConn
	authentication *jlsAuthenticationReservation
	state          jlsForwardCaptureState
	clientKey      string
	clientAddr     net.Addr
	clientInfo     packetInfo
	packets        [][]byte
	bytes          int
	overflow       bool
}

type jlsAuthenticationReservation struct {
	forwarder *jlsForwarder
	clientKey string
}

type jlsPreAuthSendState uint8

const (
	jlsPreAuthSendActive jlsPreAuthSendState = iota
	jlsPreAuthSendPassThrough
	jlsPreAuthSendDiscard
)

type jlsPreAuthWrite struct {
	data    []byte
	gsoSize uint16
	ecn     protocol.ECN
	addr    net.Addr
	info    packetInfo
	writeTo bool
}

func (w *jlsPreAuthWrite) write(conn sendConn) error {
	if w.writeTo {
		return conn.WriteTo(w.data, w.addr, w.info)
	}
	return conn.Write(w.data, w.gsoSize, w.ecn)
}

type jlsPreAuthSendConn struct {
	sendConn
	forwarder *jlsForwarder
	clientKey string

	mu       sync.Mutex
	state    jlsPreAuthSendState
	writes   []jlsPreAuthWrite
	bytes    int
	overflow bool
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
	now := time.Now()
	return &jlsForwarder{
		conn:               conn,
		cfg:                cfg,
		dialer:             cfg.PacketDialer,
		ctx:                ctx,
		cancel:             cancel,
		conns:              make(map[string]*jlsForwardConn),
		tentative:          make(map[jlsTentativeForwardKey]*jlsTentativeForward),
		tentativeRate:      newJLSTentativeRateLimiter(jlsTentativeForwardBurst, now),
		forwardRate:        newJLSTentativeRateLimiter(jlsForwardConnBurst, now),
		authenticationRate: newJLSTentativeRateLimiter(jlsAuthenticatingConnBurst, now),
		tentativeClients:   make(map[string]*jlsTentativeClient),
	}
}

func (c *Conn) enableJLSForwarding(forwarder *jlsForwarder, authentication *jlsAuthenticationReservation) {
	if forwarder != nil {
		var clientKey string
		if authentication != nil {
			clientKey = authentication.clientKey
		}
		sendConn := &jlsPreAuthSendConn{sendConn: c.conn, forwarder: forwarder, clientKey: clientKey}
		c.conn = sendConn
		c.sendQueue = newSendQueue(sendConn)
		c.jlsForwardCapture = &jlsForwardCapture{
			forwarder:      forwarder,
			sendConn:       sendConn,
			authentication: authentication,
			clientKey:      clientKey,
		}
	}
}

func (c *Conn) handleJLSPacket(p receivedPacket) bool {
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
	if pending.state == jlsForwardCaptureActive || pending.state == jlsForwardCaptureActivating {
		if pending.clientAddr == nil {
			pending.clientAddr = p.remoteAddr
			pending.clientInfo = p.info
			if pending.clientKey == "" {
				pending.clientKey = jlsClientIPKey(p.remoteAddr)
			}
		}
		packetSize := len(p.data)
		if !pending.overflow {
			if packetSize > jlsMaxAuthenticationCaptureBytes-pending.bytes || !pending.forwarder.reserveCapturedBytes(pending.clientKey, packetSize) {
				pending.clearCapturedPackets()
				pending.overflow = true
			} else {
				pending.packets = append(pending.packets, append([]byte(nil), p.data...))
				pending.bytes += packetSize
			}
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
	if err != nil {
		if pending.state == jlsForwardCaptureActive {
			pending.mu.Unlock()
			return &jlsFallbackError{err: err}
		}
		pending.mu.Unlock()
		return err
	}
	if authenticated && pending.state == jlsForwardCaptureActive {
		err = pending.authenticate()
	}
	pending.mu.Unlock()
	return err
}

func (c *Conn) handleJLSPreAuthPacketResult(err error) error {
	if err == nil {
		return nil
	}
	var fallbackErr *jlsFallbackError
	if errors.As(err, &fallbackErr) {
		return err
	}
	var transportErr *qerr.TransportError
	if !errors.As(err, &transportErr) || transportErr.Remote {
		return err
	}
	return c.handleJLSPreAuthFailure(err)
}

func (c *Conn) handleJLSPreAuthFailure(err error) error {
	pending := c.jlsForwardCapture
	if pending == nil {
		return err
	}
	pending.mu.Lock()
	active := pending.state == jlsForwardCaptureActive
	pending.mu.Unlock()
	if active {
		return &jlsFallbackError{err: err}
	}
	return err
}

func (c *Conn) forwardJLSFallback() {
	pending := c.jlsForwardCapture
	if pending != nil {
		pending.forwarder.activateForwardCapture(pending)
	}
}

func (c *Conn) releaseJLSForwardCapture() {
	pending := c.jlsForwardCapture
	if pending == nil {
		return
	}
	pending.mu.Lock()
	if pending.state == jlsForwardCaptureActive || pending.state == jlsForwardCaptureActivating {
		pending.disable()
	}
	pending.mu.Unlock()
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
	c.releaseAuthentication()
	if c.sendConn != nil {
		c.sendConn.discard()
	}
	return c.clientAddr, c.clientInfo, true
}

func (c *jlsForwardCapture) cancelActivation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == jlsForwardCaptureActivating {
		c.disable()
	}
}

func (c *jlsForwardCapture) disable() {
	c.state = jlsForwardCaptureDisabled
	c.releaseAuthentication()
	c.clearCapturedPackets()
	if c.sendConn != nil {
		c.sendConn.discard()
	}
}

func (c *jlsForwardCapture) authenticate() error {
	c.state = jlsForwardCaptureDisabled
	c.releaseAuthentication()
	c.clearCapturedPackets()
	if c.sendConn == nil {
		return nil
	}
	return c.sendConn.commit()
}

func (c *jlsForwardCapture) clearCapturedPackets() {
	c.packets = nil
	c.forwarder.releaseCapturedBytes(c.clientKey, c.bytes)
	c.bytes = 0
}

func (c *jlsForwardCapture) releaseAuthentication() {
	if c.authentication != nil {
		c.authentication.release()
		c.authentication = nil
	}
}

func (r *jlsAuthenticationReservation) release() {
	if r == nil || r.forwarder == nil {
		return
	}
	r.forwarder.releaseAuthentication(r.clientKey)
	r.forwarder = nil
}

func (f *jlsForwarder) reserveCapturedBytes(clientKey string, n int) bool {
	if n <= 0 {
		return true
	}
	if clientKey != "" {
		f.mu.Lock()
		client := f.tentativeClientLocked(clientKey, time.Now())
		if client == nil || int64(n) > jlsMaxAuthenticationCaptureBytesPerClient-client.capturedBytes {
			f.mu.Unlock()
			return false
		}
		if !f.reserveCapturedBytesGlobal(n) {
			f.mu.Unlock()
			return false
		}
		client.capturedBytes += int64(n)
		f.mu.Unlock()
		return true
	}
	return f.reserveCapturedBytesGlobal(n)
}

func (f *jlsForwarder) reserveCapturedBytesGlobal(n int) bool {
	for {
		captured := f.capturedBytes.Load()
		if int64(n) > jlsMaxAuthenticationCaptureBytesPerServer-captured {
			return false
		}
		if f.capturedBytes.CompareAndSwap(captured, captured+int64(n)) {
			return true
		}
	}
}

func (f *jlsForwarder) releaseCapturedBytes(clientKey string, n int) {
	if n <= 0 {
		return
	}
	if clientKey != "" {
		f.mu.Lock()
		if client := f.tentativeClients[clientKey]; client != nil {
			client.capturedBytes -= int64(n)
			if client.capturedBytes < 0 {
				client.capturedBytes = 0
			}
		}
		f.mu.Unlock()
	}
	f.capturedBytes.Add(-int64(n))
}

func (c *jlsPreAuthSendConn) Write(data []byte, gsoSize uint16, ecn protocol.ECN) error {
	return c.writeOrBuffer(jlsPreAuthWrite{data: data, gsoSize: gsoSize, ecn: ecn})
}

func (c *jlsPreAuthSendConn) WriteTo(data []byte, addr net.Addr, info packetInfo) error {
	return c.writeOrBuffer(jlsPreAuthWrite{data: data, addr: addr, info: info, writeTo: true})
}

func (c *jlsPreAuthSendConn) writeOrBuffer(write jlsPreAuthWrite) error {
	c.mu.Lock()
	switch c.state {
	case jlsPreAuthSendPassThrough:
		c.mu.Unlock()
		return write.write(c.sendConn)
	case jlsPreAuthSendDiscard:
		c.mu.Unlock()
		return nil
	}

	if !c.overflow {
		packetSize := len(write.data)
		if len(c.writes) >= jlsMaxPreAuthOutputPackets ||
			packetSize > jlsMaxPreAuthOutputBytes-c.bytes ||
			!c.forwarder.reserveCapturedBytes(c.clientKey, packetSize) {
			c.clearLocked()
			c.overflow = true
		} else {
			write.data = append([]byte(nil), write.data...)
			c.writes = append(c.writes, write)
			c.bytes += packetSize
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *jlsPreAuthSendConn) commit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != jlsPreAuthSendActive {
		return nil
	}
	if c.overflow {
		c.state = jlsPreAuthSendPassThrough
		return errJLSPreAuthOutputLimit
	}

	writes := c.writes
	c.writes = nil
	c.forwarder.releaseCapturedBytes(c.clientKey, c.bytes)
	c.bytes = 0
	for i := range writes {
		if err := writes[i].write(c.sendConn); err != nil {
			c.state = jlsPreAuthSendPassThrough
			return err
		}
	}
	c.state = jlsPreAuthSendPassThrough
	return nil
}

func (c *jlsPreAuthSendConn) discard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != jlsPreAuthSendActive {
		return
	}
	c.state = jlsPreAuthSendDiscard
	c.clearLocked()
}

func (c *jlsPreAuthSendConn) clearLocked() {
	c.writes = nil
	c.forwarder.releaseCapturedBytes(c.clientKey, c.bytes)
	c.bytes = 0
}

func newJLSTentativeRateLimiter(burst int, now time.Time) jlsTentativeRateLimiter {
	return jlsTentativeRateLimiter{tokens: float64(burst), updated: now}
}

func (l *jlsTentativeRateLimiter) refill(now time.Time, rate, burst int) {
	if elapsed := now.Sub(l.updated).Seconds(); elapsed > 0 {
		l.tokens += elapsed * float64(rate)
		if l.tokens > float64(burst) {
			l.tokens = float64(burst)
		}
		l.updated = now
	}
}

func (f *jlsForwarder) tentativeClientLocked(key string, now time.Time) *jlsTentativeClient {
	if f.tentativeClients == nil {
		f.tentativeClients = make(map[string]*jlsTentativeClient)
	}
	if client := f.tentativeClients[key]; client != nil {
		client.lastSeen = now
		return client
	}
	if len(f.tentativeClients) >= jlsMaxTentativeClients {
		var oldestKey string
		var oldestTime time.Time
		found := false
		for candidateKey, candidate := range f.tentativeClients {
			if candidate.forwards != 0 || candidate.fallbacks != 0 || candidate.authenticating != 0 ||
				candidate.capturedBytes != 0 || (!oldestTime.IsZero() && !candidate.lastSeen.Before(oldestTime)) {
				continue
			}
			oldestKey = candidateKey
			oldestTime = candidate.lastSeen
			found = true
		}
		if !found {
			return nil
		}
		delete(f.tentativeClients, oldestKey)
	}
	client := &jlsTentativeClient{
		rate:               newJLSTentativeRateLimiter(jlsTentativePathsPerClientBurst, now),
		fallbackRate:       newJLSTentativeRateLimiter(jlsForwardConnPerClientBurst, now),
		authenticationRate: newJLSTentativeRateLimiter(jlsAuthenticatingConnPerClientBurst, now),
		lastSeen:           now,
	}
	f.tentativeClients[key] = client
	return client
}

func (f *jlsForwarder) reserveAuthentication(addr net.Addr, now time.Time) *jlsAuthenticationReservation {
	clientKey := jlsClientIPKey(addr)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.authenticationCount >= jlsMaxAuthenticatingConns {
		return nil
	}
	client := f.tentativeClientLocked(clientKey, now)
	if client == nil || client.authenticating >= jlsMaxAuthenticatingConnsPerClient {
		return nil
	}
	f.authenticationRate.refill(now, jlsAuthenticatingConnsPerSecond, jlsAuthenticatingConnBurst)
	client.authenticationRate.refill(
		now,
		jlsAuthenticatingConnsPerClientPerSecond,
		jlsAuthenticatingConnPerClientBurst,
	)
	if f.authenticationRate.tokens < 1 || client.authenticationRate.tokens < 1 {
		return nil
	}
	f.authenticationRate.tokens--
	client.authenticationRate.tokens--
	f.authenticationCount++
	client.authenticating++
	return &jlsAuthenticationReservation{forwarder: f, clientKey: clientKey}
}

func (f *jlsForwarder) releaseAuthentication(clientKey string) {
	f.mu.Lock()
	if f.authenticationCount > 0 {
		f.authenticationCount--
	}
	if client := f.tentativeClients[clientKey]; client != nil && client.authenticating > 0 {
		client.authenticating--
	}
	f.mu.Unlock()
}

func (f *jlsForwarder) reserveForwardConn(clientKey string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reserveForwardConnLocked(clientKey, now)
}

func (f *jlsForwarder) reserveForwardConnLocked(clientKey string, now time.Time) bool {
	if f.closed || f.forwardCount >= jlsMaxForwardConns {
		return false
	}
	client := f.tentativeClientLocked(clientKey, now)
	if client == nil || client.fallbacks >= jlsMaxForwardConnsPerClient {
		return false
	}
	f.forwardRate.refill(now, jlsForwardConnsPerSecond, jlsForwardConnBurst)
	client.fallbackRate.refill(now, jlsForwardConnsPerClientPerSecond, jlsForwardConnPerClientBurst)
	if f.forwardRate.tokens < 1 || client.fallbackRate.tokens < 1 {
		return false
	}
	f.forwardRate.tokens--
	client.fallbackRate.tokens--
	f.forwardCount++
	client.fallbacks++
	return true
}

func (f *jlsForwarder) releaseForwardReservation(clientKey string) {
	f.mu.Lock()
	f.releaseForwardReservationLocked(clientKey)
	f.mu.Unlock()
}

func (f *jlsForwarder) releaseForwardReservationLocked(clientKey string) {
	if f.forwardCount > 0 {
		f.forwardCount--
	}
	if client := f.tentativeClients[clientKey]; client != nil && client.fallbacks > 0 {
		client.fallbacks--
	}
}

func (f *jlsForwarder) releaseForwardConnLocked(fwd *jlsForwardConn) {
	if fwd != nil && fwd.counted {
		fwd.counted = false
		f.releaseForwardReservationLocked(fwd.clientKey)
	}
}

func (f *jlsForwarder) allowTentativeForwardLocked(client *jlsTentativeClient, kind jlsTentativeForwardKind, now time.Time) bool {
	f.tentativeRate.refill(now, jlsTentativeForwardsPerSecond, jlsTentativeForwardBurst)
	if f.tentativeRate.tokens < 1 {
		return false
	}
	if kind == jlsTentativeForwardPath {
		client.rate.refill(now, jlsTentativePathsPerClientPerSecond, jlsTentativePathsPerClientBurst)
		if client.rate.tokens < 1 {
			return false
		}
		client.rate.tokens--
	}
	f.tentativeRate.tokens--
	return true
}

func (f *jlsForwarder) oldestTentativeForwardLocked(clientKey string, pathsOnly bool) (jlsTentativeForwardKey, *jlsTentativeForward) {
	var oldestKey jlsTentativeForwardKey
	var oldest *jlsTentativeForward
	for key, tentative := range f.tentative {
		if clientKey != "" && tentative.clientKey != clientKey {
			continue
		}
		if pathsOnly && tentative.kind != jlsTentativeForwardPath {
			continue
		}
		if oldest == nil || tentative.sequence < oldest.sequence {
			oldestKey = key
			oldest = tentative
		}
	}
	return oldestKey, oldest
}

func (f *jlsForwarder) removeTentativeClientLocked(clientKey string, kind jlsTentativeForwardKind) {
	if client := f.tentativeClients[clientKey]; client != nil && client.forwards > 0 {
		client.forwards--
		if kind == jlsTentativeForwardPath && client.paths > 0 {
			client.paths--
		}
	}
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
		f.releaseForwardConnLocked(conn)
		_ = conn.conn.Close()
	}
	f.conns = make(map[string]*jlsForwardConn)
	tentatives := f.tentative
	f.tentative = make(map[jlsTentativeForwardKey]*jlsTentativeForward)
	for _, tentative := range tentatives {
		f.removeTentativeClientLocked(tentative.clientKey, tentative.kind)
		tentative.mu.Lock()
		tentative.done = true
		if tentative.cancel != nil {
			tentative.cancel()
		}
		if tentative.fwd != nil {
			_ = tentative.fwd.conn.Close()
		}
		tentative.packets = nil
		tentative.bytes = 0
		tentative.mu.Unlock()
	}
	f.mu.Unlock()
}

func (f *jlsForwarder) handleForwardedClientPacket(p receivedPacket) bool {
	if f == nil {
		return false
	}
	clientAddrKey := jlsAddrKey(p.remoteAddr)
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return false
		}
		fwd := f.conns[clientAddrKey]
		tentativeKey, hasTentativeKey := jlsTentativeKeyForPacket(p.remoteAddr, p.data)
		var tentative *jlsTentativeForward
		if hasTentativeKey {
			tentative = f.tentative[tentativeKey]
		}
		f.mu.Unlock()
		if fwd != nil {
			f.forwardToUpstream(fwd, p.data)
			p.buffer.Release()
			return true
		}
		if tentative == nil {
			return false
		}
		tentative.mu.Lock()
		if tentative.done {
			tentative.mu.Unlock()
			continue
		}
		if !tentative.matchesPacket(p.data) {
			tentative.mu.Unlock()
			return false
		}
		deadlineErr := tentative.forwardPacket(f, p.data)
		tentative.mu.Unlock()
		if deadlineErr != nil {
			f.removeTentativeForward(tentativeKey, tentative)
		}
		p.buffer.Release()
		return true
	}
}

func newJLSTentativeForwardKey(
	addr net.Addr,
	kind jlsTentativeForwardKind,
	version protocol.Version,
	clientSrcConnID protocol.ArbitraryLenConnectionID,
) jlsTentativeForwardKey {
	return jlsTentativeForwardKey{
		clientAddr:      jlsAddrKey(addr),
		kind:            kind,
		version:         version,
		clientSrcConnID: string(clientSrcConnID.Bytes()),
	}
}

func jlsTentativeKeyForPacket(addr net.Addr, data []byte) (jlsTentativeForwardKey, bool) {
	if len(data) == 0 {
		return jlsTentativeForwardKey{}, false
	}
	if !wire.IsLongHeaderPacket(data[0]) {
		return newJLSTentativeForwardKey(addr, jlsTentativeForwardPath, 0, nil), true
	}
	version, err := wire.ParseVersion(data)
	if err != nil {
		return jlsTentativeForwardKey{}, false
	}
	_, _, srcConnID, err := wire.ParseArbitraryLenConnectionIDs(data)
	if err != nil {
		return jlsTentativeForwardKey{}, false
	}
	return newJLSTentativeForwardKey(addr, jlsTentativeForwardVersionProbe, version, srcConnID), true
}

func (f *jlsForwarder) handleCamouflageVersionPacket(p receivedPacket) bool {
	if f == nil {
		return false
	}
	version, err := wire.ParseVersion(p.data)
	if err != nil {
		return false
	}
	_, _, srcConnID, err := wire.ParseArbitraryLenConnectionIDs(p.data)
	if err != nil {
		return false
	}
	return f.handleTentativePacket(p, jlsTentativeForwardVersionProbe, version, srcConnID)
}

func (f *jlsForwarder) handleCamouflagePathPacket(p receivedPacket) bool {
	if f == nil || len(p.data) == 0 || wire.IsLongHeaderPacket(p.data[0]) {
		return false
	}
	return f.handleTentativePacket(p, jlsTentativeForwardPath, 0, nil)
}

func (f *jlsForwarder) handleTentativePacket(
	p receivedPacket,
	kind jlsTentativeForwardKind,
	version protocol.Version,
	clientSrcConnID protocol.ArbitraryLenConnectionID,
) bool {
	key := newJLSTentativeForwardKey(p.remoteAddr, kind, version, clientSrcConnID)
	clientAddrKey := jlsAddrKey(p.remoteAddr)
	for {
		var replacedForward *jlsForwardConn
		var replacedCancel context.CancelFunc
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return false
		}
		if fwd := f.conns[clientAddrKey]; fwd != nil {
			f.mu.Unlock()
			f.forwardToUpstream(fwd, p.data)
			return true
		}
		if tentative := f.tentative[key]; tentative != nil {
			f.mu.Unlock()
			tentative.mu.Lock()
			if tentative.done {
				tentative.mu.Unlock()
				continue
			}
			if tentative.kind != kind || (kind == jlsTentativeForwardVersionProbe && tentative.version != version) {
				tentative.mu.Unlock()
				return false
			}
			deadlineErr := tentative.forwardPacket(f, p.data)
			tentative.mu.Unlock()
			if deadlineErr != nil {
				f.removeTentativeForward(key, tentative)
			}
			return true
		}
		now := time.Now()
		clientKey := jlsClientIPKey(p.remoteAddr)
		client := f.tentativeClientLocked(clientKey, now)
		if client == nil {
			f.mu.Unlock()
			return false
		}
		var replacedKey jlsTentativeForwardKey
		var replaced *jlsTentativeForward
		pathLimitReached := kind == jlsTentativeForwardPath && client.paths >= jlsMaxTentativePathsPerClient
		globalLimitReached := len(f.tentative) >= jlsMaxTentativeForwards
		if pathLimitReached {
			replacedKey, replaced = f.oldestTentativeForwardLocked(clientKey, true)
		} else if globalLimitReached {
			replacedKey, replaced = f.oldestTentativeForwardLocked("", false)
		}
		if (pathLimitReached || globalLimitReached) && replaced == nil {
			f.mu.Unlock()
			return false
		}
		if !f.allowTentativeForwardLocked(client, kind, now) {
			f.mu.Unlock()
			return false
		}
		ctx, cancel := context.WithCancel(f.ctx)
		f.tentativeSequence++
		tentative := &jlsTentativeForward{
			ctx:             ctx,
			cancel:          cancel,
			sequence:        f.tentativeSequence,
			clientKey:       clientKey,
			kind:            kind,
			version:         version,
			clientSrcConnID: clientSrcConnID,
			packets:         [][]byte{append([]byte(nil), p.data...)},
			bytes:           len(p.data),
		}
		if replaced != nil {
			delete(f.tentative, replacedKey)
			f.removeTentativeClientLocked(replaced.clientKey, replaced.kind)
			replaced.mu.Lock()
			replaced.done = true
			replacedForward = replaced.fwd
			replaced.fwd = nil
			replaced.packets = nil
			replaced.bytes = 0
			replaced.mu.Unlock()
			replacedCancel = replaced.cancel
		}
		f.tentative[key] = tentative
		client.forwards++
		if kind == jlsTentativeForwardPath {
			client.paths++
		}
		f.mu.Unlock()
		if replacedCancel != nil {
			replacedCancel()
		}
		if replacedForward != nil {
			_ = replacedForward.conn.Close()
		}

		go f.runTentativeForward(key, tentative, p.remoteAddr, p.info)
		return true
	}
}

func (f *jlsForwarder) runTentativeForward(key jlsTentativeForwardKey, tentative *jlsTentativeForward, clientAddr net.Addr, clientInfo packetInfo) {
	defer tentative.cancel()

	dialCtx, cancelDial := context.WithTimeout(tentative.ctx, jlsForwardIdleTimeout)
	fwd := f.dialForwardConn(dialCtx, clientAddr, clientInfo)
	cancelDial()
	if fwd == nil || !f.attachTentativeForward(key, tentative, fwd) {
		if fwd != nil {
			_ = fwd.conn.Close()
		}
		f.removeTentativeForward(key, tentative)
		return
	}
	tentative.mu.Lock()
	deadlineErr := tentative.refreshReadDeadline(time.Now())
	tentative.mu.Unlock()
	if deadlineErr != nil {
		f.removeTentativeForward(key, tentative)
		return
	}

	buf := make([]byte, jlsForwardRecvBufferSize)
	for {
		var responseAddr net.Addr
		n, responseAddr, err := fwd.conn.ReadFrom(buf)
		if err != nil {
			f.removeTentativeForward(key, tentative)
			return
		}
		if !jlsResponseFromUpstream(responseAddr, fwd.upstreamAddr) {
			continue
		}

		response := buf[:n]
		if tentative.kind == jlsTentativeForwardVersionProbe {
			tentative.mu.Lock()
			if tentative.done {
				tentative.mu.Unlock()
				f.removeTentativeForward(key, tentative)
				return
			}
			deadlineErr := tentative.refreshReadDeadline(time.Now())
			if fwd.recvLimiter.allow(n) {
				_ = fwd.clientConn.Write(response, 0, protocol.ECNUnsupported)
			}
			tentative.mu.Unlock()
			if deadlineErr != nil {
				f.removeTentativeForward(key, tentative)
				return
			}
			if wire.IsVersionNegotiationPacket(response) {
				// Preserve the upstream mapping for retransmissions. The forwarding
				// layer must not reinterpret a response the client will validate.
				continue
			}
			if !f.promoteTentativeForward(key, tentative, fwd) {
				f.removeTentativeForward(key, tentative)
				return
			}
			tentative.cancel()
			fwd.touch(time.Now())
			f.readForwardConnWithBuffer(key.clientAddr, fwd, buf)
			return
		}

		fwd.touch(time.Now())
		tentative.mu.Lock()
		if tentative.done {
			tentative.mu.Unlock()
			f.removeTentativeForward(key, tentative)
			return
		}
		// Once the upstream responds, retain and refresh this path using the
		// same idle lifetime as an established fallback. This preserves the
		// upstream's native QUIC path-validation retransmissions.
		deadlineErr := tentative.refreshReadDeadline(time.Now())
		// Keep the candidate tentative until a complete response-driven round
		// trip proves that the new client path is reachable.
		relayed := fwd.recvLimiter.allow(n) && fwd.clientConn.Write(response, 0, protocol.ECNUnsupported) == nil
		if relayed {
			tentative.pathResponseRelayed = true
		}
		validated := relayed && tentative.pathPacketAfterResponse
		tentative.mu.Unlock()
		if deadlineErr != nil {
			f.removeTentativeForward(key, tentative)
			return
		}
		if !validated {
			continue
		}
		if !f.promoteTentativeForward(key, tentative, fwd) {
			f.removeTentativeForward(key, tentative)
			return
		}
		tentative.cancel()
		f.readForwardConnWithBuffer(key.clientAddr, fwd, buf)
		return
	}
}

func (f *jlsForwarder) attachTentativeForward(key jlsTentativeForwardKey, tentative *jlsTentativeForward, fwd *jlsForwardConn) bool {
	f.mu.Lock()
	if f.closed || f.tentative[key] != tentative {
		f.mu.Unlock()
		return false
	}
	tentative.mu.Lock()
	if tentative.done {
		tentative.mu.Unlock()
		f.mu.Unlock()
		return false
	}
	tentative.fwd = fwd
	packets := tentative.packets
	tentative.packets = nil
	tentative.bytes = 0
	f.mu.Unlock()
	for _, packet := range packets {
		f.writeToUpstream(fwd, packet)
	}
	tentative.mu.Unlock()
	return true
}

func (f *jlsForwarder) promoteTentativeForward(key jlsTentativeForwardKey, tentative *jlsTentativeForward, fwd *jlsForwardConn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.tentative[key] != tentative || f.conns[key.clientAddr] != nil {
		return false
	}
	tentative.mu.Lock()
	defer tentative.mu.Unlock()
	if tentative.done || tentative.fwd != fwd {
		return false
	}
	if !f.reserveForwardConnLocked(tentative.clientKey, time.Now()) {
		return false
	}
	tentative.done = true
	tentative.fwd = nil
	delete(f.tentative, key)
	f.removeTentativeClientLocked(tentative.clientKey, tentative.kind)
	fwd.clientKey = tentative.clientKey
	fwd.counted = true
	f.conns[key.clientAddr] = fwd
	return true
}

func (f *jlsForwarder) removeTentativeForward(key jlsTentativeForwardKey, tentative *jlsTentativeForward) {
	var fwd *jlsForwardConn
	var cancel context.CancelFunc
	f.mu.Lock()
	if f.tentative[key] == tentative {
		delete(f.tentative, key)
		f.removeTentativeClientLocked(tentative.clientKey, tentative.kind)
		tentative.mu.Lock()
		tentative.done = true
		fwd = tentative.fwd
		cancel = tentative.cancel
		tentative.fwd = nil
		tentative.packets = nil
		tentative.bytes = 0
		tentative.mu.Unlock()
	}
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if fwd != nil {
		_ = fwd.conn.Close()
	}
}

func (t *jlsTentativeForward) forwardPacket(f *jlsForwarder, data []byte) error {
	if t.done {
		return nil
	}
	if t.fwd != nil {
		forwarded := f.forwardToUpstream(t.fwd, data)
		if forwarded && t.kind == jlsTentativeForwardPath && t.pathResponseRelayed {
			t.pathPacketAfterResponse = true
		}
		if forwarded {
			return t.refreshReadDeadline(time.Now())
		}
		return nil
	}
	if len(t.packets) >= jlsMaxTentativeCapturedPackets || t.bytes+len(data) > jlsMaxTentativeCapturedBytes {
		return nil
	}
	t.packets = append(t.packets, append([]byte(nil), data...))
	t.bytes += len(data)
	return nil
}

func (t *jlsTentativeForward) refreshReadDeadline(now time.Time) error {
	deadline := now.Add(jlsForwardIdleTimeout)
	t.deadline = deadline
	return t.fwd.conn.SetReadDeadline(deadline)
}

func (t *jlsTentativeForward) matchesPacket(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if t.kind == jlsTentativeForwardPath {
		return !wire.IsLongHeaderPacket(data[0])
	}
	if !wire.IsLongHeaderPacket(data[0]) {
		return false
	}
	version, err := wire.ParseVersion(data)
	return err == nil && version == t.version
}

func jlsResponseFromUpstream(responseAddr, upstreamAddr net.Addr) bool {
	if responseAddr == nil || upstreamAddr == nil {
		return false
	}
	if responseAddr.String() == upstreamAddr.String() {
		return true
	}
	upstream, err := netip.ParseAddrPort(upstreamAddr.String())
	if err != nil {
		// A fresh PacketConn created by the caller still scopes hostname and
		// virtual upstreams even when ReadFrom reports a resolved address.
		return true
	}
	response, err := netip.ParseAddrPort(responseAddr.String())
	return err == nil && response == upstream
}

func (f *jlsForwarder) activateForwardCapture(capture *jlsForwardCapture) {
	clientAddr, clientInfo, ok := capture.beginActivation()
	if !ok {
		return
	}
	clientKey := jlsClientIPKey(clientAddr)
	if !f.reserveForwardConn(clientKey, time.Now()) {
		capture.cancelActivation()
		return
	}

	dialCtx, cancelDial := context.WithTimeout(f.ctx, jlsForwardIdleTimeout)
	prepared := f.dialForwardConn(dialCtx, clientAddr, clientInfo)
	cancelDial()
	if prepared == nil {
		f.releaseForwardReservation(clientKey)
		capture.cancelActivation()
		return
	}
	prepared.clientKey = clientKey
	prepared.counted = true

	key := jlsAddrKey(clientAddr)
	// Keep this capture in the activating state until replay finishes. Packets
	// for this connection then wait here instead of overtaking the replay.
	capture.mu.Lock()
	if capture.state != jlsForwardCaptureActivating || capture.overflow {
		if capture.state == jlsForwardCaptureActivating {
			capture.disable()
		}
		capture.mu.Unlock()
		prepared.counted = false
		f.releaseForwardReservation(clientKey)
		_ = prepared.conn.Close()
		return
	}

	f.mu.Lock()
	if f.closed {
		f.releaseForwardConnLocked(prepared)
		f.mu.Unlock()
		capture.disable()
		capture.mu.Unlock()
		_ = prepared.conn.Close()
		return
	}
	target := f.conns[key]
	startReader := false
	if target == nil {
		target = prepared
		f.conns[key] = target
		startReader = true
	} else {
		f.releaseForwardConnLocked(prepared)
	}
	f.mu.Unlock()

	for _, packet := range capture.packets {
		f.writeToUpstream(target, packet)
	}
	capture.state = jlsForwardCaptureForwarded
	capture.clearCapturedPackets()
	capture.mu.Unlock()

	if !startReader {
		_ = prepared.conn.Close()
	}
	if startReader {
		go f.readForwardConn(key, target)
	}
}

func (f *jlsForwarder) dialForwardConn(ctx context.Context, clientAddr net.Addr, clientInfo packetInfo) *jlsForwardConn {
	pc, upstreamAddr, err := f.dialer(ctx, "udp", f.cfg.UpstreamAddr)
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
	f.readForwardConnWithBuffer(key, fwd, make([]byte, jlsForwardRecvBufferSize))
}

func (f *jlsForwarder) readForwardConnWithBuffer(key string, fwd *jlsForwardConn, buf []byte) {
	defer func() {
		_ = fwd.conn.Close()
		f.mu.Lock()
		if f.conns[key] == fwd {
			delete(f.conns, key)
			f.releaseForwardConnLocked(fwd)
		}
		f.mu.Unlock()
	}()

	for {
		deadline := fwd.idleDeadline()
		if !deadline.After(time.Now()) {
			return
		}
		if err := fwd.conn.SetReadDeadline(deadline); err != nil {
			return
		}
		n, responseAddr, err := fwd.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && fwd.idleDeadline().After(time.Now()) {
				continue
			}
			return
		}
		if !jlsResponseFromUpstream(responseAddr, fwd.upstreamAddr) {
			continue
		}
		fwd.touch(time.Now())
		if fwd.recvLimiter.allow(n) {
			_ = fwd.clientConn.Write(buf[:n], 0, protocol.ECNUnsupported)
		}
	}
}

func (f *jlsForwarder) forwardToUpstream(fwd *jlsForwardConn, data []byte) bool {
	fwd.touch(time.Now())
	if fwd.sendLimiter.allow(len(data)) {
		_, err := fwd.conn.WriteTo(data, fwd.upstreamAddr)
		return err == nil
	}
	return false
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

func jlsClientIPKey(addr net.Addr) string {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if ip, valid := netip.AddrFromSlice(udpAddr.IP); valid {
			return ip.Unmap().String()
		}
	}
	if addr != nil {
		if addrPort, err := netip.ParseAddrPort(addr.String()); err == nil {
			return addrPort.Addr().Unmap().String()
		}
	}
	return jlsAddrKey(addr)
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

func (f *jlsForwardConn) idleDeadline() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active.Add(jlsForwardIdleTimeout)
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
