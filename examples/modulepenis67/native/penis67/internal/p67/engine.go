// Engine adapts the P67 client to the module host's transport interface.
// Carriers (TLS/TCP or QUIC) are established lazily, keepalived, and — with
// mc= — run in parallel with streams spread least-loaded. TSPU research
// note: multiple simultaneous connections to one endpoint is itself a
// signal, so mc stays 1 by default; raise it for bandwidth, not for stealth.
package p67

import (
	"context"
	"net"
	"sync"
	"time"

)

// Dialer is the transport the engine dials the carrier through: plain
// hooks instead of any host SDK, so the package stays self-contained.
type Dialer struct {
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	ListenUDP   func(ctx context.Context) (*net.UDPConn, error)
}

// Engine drives P67 carrier sessions.
type Engine struct {
	link   *Link
	dialer *Dialer
	log    func(string)

	mu    sync.Mutex
	conns []*Session
}

// NewEngine prepares the engine; nothing connects until the first dial.
func NewEngine(link *Link, dialer *Dialer, logLine func(string)) *Engine {
	if logLine == nil {
		logLine = func(string) {}
	}
	if dialer == nil {
		nd := &net.Dialer{}
		dialer = &Dialer{DialContext: nd.DialContext}
	}
	if link.MultiCarrier < 1 {
		link.MultiCarrier = 1
	}
	return &Engine{link: link, dialer: dialer, log: logLine}
}

var _ net.PacketConn = (*udpStreamConn)(nil)

// connectOne establishes one carrier. first pipelines into the auth flight
// when the link allows (rtt0, TCP); otherwise the stream opens right after.
func (e *Engine) connectOne(ctx context.Context, first *Target) (*Session, *Stream, error) {
	if e.link.Net == NetQUIC {
		sess, err := ConnectQUIC(ctx, ClientConfig{
			Link:        e.link,
			DialContext: e.dialer.DialContext,
			ListenUDP:   e.dialer.ListenUDP,
			Log:         e.log,
		})
		if err != nil {
			return nil, nil, err
		}
		go e.keepalive(sess)
		var stream *Stream
		if first != nil {
			stream, err = sess.Open(first.Host, first.Port, first.UDP)
			if err != nil {
				_ = sess.Close()
				return nil, nil, err
			}
		}
		return sess, stream, nil
	}
	pipelined := first
	if !e.link.RTT0 {
		pipelined = nil
	}
	sess, stream, err := ConnectOpen(ctx, ClientConfig{
		Link:        e.link,
		DialContext: e.dialer.DialContext,
		Log:         e.log,
		FirstOpen:   pipelined,
	})
	if err != nil {
		return nil, nil, err
	}
	go e.keepalive(sess)
	if first != nil && stream == nil {
		stream, err = sess.Open(first.Host, first.Port, first.UDP)
		if err != nil {
			_ = sess.Close()
			return nil, nil, err
		}
	}
	return sess, stream, nil
}

// sessionOpen returns a live carrier and, when first is set, an opened
// stream on it. Dead carriers are pruned; the pool tops up toward mc in
// the background.
func (e *Engine) sessionOpen(ctx context.Context, first *Target) (*Session, *Stream, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	live := e.pruneLocked()
	if len(live) > 0 {
		sess := leastLoaded(live)
		if first == nil {
			return sess, nil, nil
		}
		if st, err := sess.Open(first.Host, first.Port, first.UDP); err == nil {
			e.topUpLocked(ctx)
			return sess, st, nil
		}
		// Stale carrier: drop it and reconnect below.
		_ = sess.Close()
		live = e.pruneLocked()
	}
	sess, stream, err := e.connectOne(ctx, first)
	if err != nil {
		return nil, nil, err
	}
	e.conns = append(e.conns, sess)
	e.topUpLocked(ctx)
	return sess, stream, nil
}

// pruneLocked drops dead carriers and returns the live ones.
func (e *Engine) pruneLocked() []*Session {
	kept := e.conns[:0]
	for _, sess := range e.conns {
		select {
		case <-sess.Done():
			_ = sess.Close()
		default:
			kept = append(kept, sess)
		}
	}
	e.conns = kept
	return kept
}

// topUpLocked spawns background carriers toward the mc target.
func (e *Engine) topUpLocked(ctx context.Context) {
	for len(e.conns) < e.link.MultiCarrier {
		go func() {
			// Not holding the engine lock across a network dial.
			sess, _, err := e.connectOne(ctx, nil)
			if err != nil {
				return
			}
			e.mu.Lock()
			select {
			case <-sess.Done():
				// Died before registering.
			default:
				e.conns = append(e.conns, sess)
			}
			e.mu.Unlock()
		}()
		return // one at a time; the next dial tops up further
	}
}

func leastLoaded(sessions []*Session) *Session {
	best := sessions[0]
	for _, sess := range sessions[1:] {
		if sess.StreamCount() < best.StreamCount() {
			best = sess
		}
	}
	return best
}

// keepalive probes idle carriers; a dead one is reconnected lazily by the
// next dial.
func (e *Engine) keepalive(sess *Session) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sess.Done():
			return
		case <-ticker.C:
			if sess.IdleDuration() > 20*time.Second {
				if err := sess.Ping(); err != nil {
					_ = sess.Close()
					return
				}
			}
		}
	}
}

// DialContext opens one proxied TCP flow. With rtt0=1 the first flow after
// a cold start rides the auth flight.
func (e *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		_, stream, err := e.sessionOpen(ctx, &Target{Host: host, Port: port})
		if err == nil {
			return stream, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SupportsUDP reports UDP associations available.
func (e *Engine) SupportsUDP() bool { return true }

// PacketConn opens one UDP association to address.
func (e *Engine) PacketConn(ctx context.Context, address string) (net.PacketConn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		_, stream, err := e.sessionOpen(ctx, &Target{Host: host, Port: port, UDP: true})
		if err == nil {
			return &udpStreamConn{st: stream, remote: remote}, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Close tears every carrier down.
func (e *Engine) Close() error {
	e.mu.Lock()
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
	for _, sess := range conns {
		_ = sess.Close()
	}
	return nil
}

// LiveCarriers reports how many carriers are alive (tests).
func (e *Engine) LiveCarriers() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pruneLocked())
}

// udpStreamConn adapts a datagram-semantics stream to net.PacketConn for
// the SOCKS5 UDP relay.
type udpStreamConn struct {
	st     *Stream
	remote *net.UDPAddr
}

func (u *udpStreamConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := u.st.ReadDatagram(b)
	return n, u.remote, err
}

func (u *udpStreamConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if err := u.st.WriteDatagram(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *udpStreamConn) Close() error                       { return u.st.Close() }
func (u *udpStreamConn) LocalAddr() net.Addr                { return u.remote }
func (u *udpStreamConn) SetDeadline(t time.Time) error      { return u.st.SetDeadline(t) }
func (u *udpStreamConn) SetReadDeadline(t time.Time) error  { return u.st.SetReadDeadline(t) }
func (u *udpStreamConn) SetWriteDeadline(t time.Time) error { return u.st.SetWriteDeadline(t) }
