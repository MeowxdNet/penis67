// The QUIC carrier ("net=quic"): the same P67 mux and auth, riding one
// QUIC stream. This is the performance/carrier-diversity mode: traffic
// looks like a browser speaking HTTP/3 to the server (ALPN h3), uses
// quic-go's standard congestion control (research: custom CCAs like Brutal
// are trivially fingerprintable, FOCI 2025), and survives TCP-specific
// policing. The stealth-flagship features (sid marker, decoy relay) are
// TCP-only: QUIC Initials cannot carry our marker without a custom QUIC
// stack, so the QUIC path authenticates post-handshake via the v2 auth
// packet (uid + channel-bound HMAC) and closes unauthorized connections.
package p67

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicALPN is the browser HTTP/3 ALPN string.
const quicALPN = "h3"

// ConnectQUIC dials the server over QUIC, authenticates, and returns the
// mux session over one stream.
func ConnectQUIC(ctx context.Context, cfg ClientConfig) (*Session, error) {
	if cfg.Link == nil {
		return nil, errors.New("p67: no link")
	}
	link := cfg.Link
	log := cfg.Log
	if log == nil {
		log = func(string) {}
	}
	socket, err := listenUDPConn(ctx, cfg.ListenUDP)
	if err != nil {
		return nil, fmt.Errorf("p67: quic socket: %w", err)
	}
	remote, err := net.ResolveUDPAddr("udp", link.Address())
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	transport := &quic.Transport{Conn: socket}
	qconn, err := transport.Dial(ctx, remote, &tls.Config{
		NextProtos:         []string{quicALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // auth is the v2 HMAC challenge
	}, &quic.Config{
		MaxIdleTimeout:  75 * time.Second,
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("p67: quic dial: %w", err)
	}
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("p67: quic stream: %w", err)
	}

	certDER := []byte{}
	if certs := qconn.ConnectionState().TLS.PeerCertificates; len(certs) > 0 {
		certDER = certs[0].Raw
	}
	binding := channelBinding(nil, certDER, quicALPN)
	appKey := AppKey(link.User, binding)
	carrier := &quicStreamConn{Stream: stream, conn: qconn}
	if err := stream.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, err
	}
	packet, err := buildAuthPacket(link.User, appKey, "penis67-auth-client", binding)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, err
	}
	if _, err := carrier.Write(packet); err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("p67: auth write: %w", err)
	}
	reply, err := readAuthPacket(carrier)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("p67: auth reply: %w", err)
	}
	if !verifyAuthPacket(reply, link.User, appKey, "penis67-auth-server", binding) {
		_ = qconn.CloseWithError(0x103, "")
		return nil, errors.New("p67: quic server auth failed")
	}
	_ = stream.SetDeadline(time.Time{})

	pad := PadClient
	if !link.Pad {
		pad = PadOff
	}
	log("p67: session up (quic/h3 carrier)")
	return newSession(StreamConfig{
		Conn: carrier,
		Pad:  pad,
		Log:  log,
	}), nil
}

// listenUDPConn opens the QUIC client socket (the engine injects the
// protected listener; tests inject a loopback one).
func listenUDPConn(ctx context.Context, hook func(context.Context) (*net.UDPConn, error)) (*net.UDPConn, error) {
	if hook != nil {
		return hook(ctx)
	}
	var lc net.ListenConfig
	packet, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, errors.New("p67: not a UDP socket")
	}
	return udp, nil
}

// quicStreamConn ties the stream's lifecycle to the QUIC connection and
// presents it as a net.Conn (quic.Stream lacks address methods).
type quicStreamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *quicStreamConn) Close() error {
	err := q.Stream.Close()
	_ = q.conn.CloseWithError(0, "")
	return err
}

func (q *quicStreamConn) LocalAddr() net.Addr                { return q.conn.LocalAddr() }
func (q *quicStreamConn) RemoteAddr() net.Addr               { return q.conn.RemoteAddr() }
func (q *quicStreamConn) SetDeadline(t time.Time) error      { return q.Stream.SetDeadline(t) }
func (q *quicStreamConn) SetReadDeadline(t time.Time) error  { return q.Stream.SetReadDeadline(t) }
func (q *quicStreamConn) SetWriteDeadline(t time.Time) error { return q.Stream.SetWriteDeadline(t) }

var _ net.Conn = (*quicStreamConn)(nil)

// quicListener spins up the UDP listener when the server has QuicAddr set.
func (s *Server) startQUIC() error {
	if s.cfg.QuicAddr == "" {
		return nil
	}
	udp, err := net.ListenUDP("udp", mustUDPAddr(s.cfg.QuicAddr))
	if err != nil {
		return err
	}
	tlsConf, der, err := s.quicTLSConfig()
	if err != nil {
		_ = udp.Close()
		return err
	}
	s.quicCertDER.Store(der)
	listener, err := quic.Listen(udp, tlsConf, &quic.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		_ = udp.Close()
		return err
	}
	s.quicListener = listener
	s.wg.Add(1)
	go s.serveQUIC(listener)
	return nil
}

func mustUDPAddr(addr string) *net.UDPAddr {
	resolved, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return resolved
}

// quicTLSConfig builds the server-side QUIC TLS config with a fresh cert.
func (s *Server) quicTLSConfig() (*tls.Config, []byte, error) {
	cert, der, err := mintConnCert(s.certTemplate, s.decoyHost)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384},
	}, der, nil
}

// serveQUIC accepts QUIC connections until the listener closes.
func (s *Server) serveQUIC(listener *quic.Listener) {
	defer s.wg.Done()
	for {
		qconn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleQUICConn(qconn)
		}()
	}
}

func (s *Server) handleQUICConn(qconn *quic.Conn) {
	defer func() { _ = qconn.CloseWithError(0, "") }()
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTO)
	defer cancel()
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		return
	}
	// The carrier is exactly one stream; extra streams are protocol
	// violations and reset immediately.
	go func() {
		for {
			extra, err := qconn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			_ = extra.Close()
		}
	}()

	certDER := []byte{}
	if der := s.quicCertDER.Load(); der != nil {
		certDER = der.([]byte)
	}
	carrier := &quicStreamConn{Stream: stream, conn: qconn}
	if _, err := s.authorize(carrier, nil, nil, certDER, quicALPN); err != nil {
		return
	}
	sess := newSession(StreamConfig{
		Conn:        carrier,
		Pad:         PadServer,
		Log:         s.cfg.Log,
		ServeStream: s.serveStream,
	})
	defer sess.Close()
	s.watchIdle(sess)
	<-sess.Done()
}

// watchIdle closes sessions silent past the idle budget.
func (s *Server) watchIdle(sess *Session) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sess.Done():
				return
			case <-ticker.C:
				if sess.IdleDuration() > 90*time.Second {
					_ = sess.Close()
					return
				}
			}
		}
	}()
}
