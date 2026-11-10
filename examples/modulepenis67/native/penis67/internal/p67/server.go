// The server half. For every incoming TCP connection it reads the
// ClientHello first and decides, without sending a single byte back:
//
//   - the P67 marker opens (authorized user, fresh timestamp) → terminate
//     TLS 1.3 locally, run the challenge/response, serve the mux;
//   - anything else → splice the raw stream to the decoy site, so the
//     prober completes a genuine TLS handshake with, say, www.bing.com.
package p67

import (
	"container/list"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// ServerConfig is everything a P67 server needs.
type ServerConfig struct {
	Listen    string // "ip:port"
	Users     []UserKey
	StaticKey *ecdh.PrivateKey
	Decoy     string // host:port relayed for unauthorized traffic
	// QuicAddr optionally enables the QUIC carrier (UDP); empty = off.
	QuicAddr string
	Log      func(string)

	// DialContext for outbound connections (tests override it); nil uses
	// the default dialer.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	ListenUDP   func(ctx context.Context) (*net.UDPConn, error) // tests override
}

// Server serves one P67 endpoint.
type Server struct {
	cfg ServerConfig
	ln  net.Listener
	// certTemplate mirrors the decoy site's real certificate fields
	// (subject, SANs, key usage); every authorized connection mints a
	// fresh certificate from it so the terminating path never shows a
	// static, fingerprintable cert body.
	certTemplate *x509.Certificate
	decoyHost    string

	users      map[UserKey]struct{}
	usersByUID map[string]UserKey
	nonces     *nonceLRU

	// QUIC carrier (optional).
	quicListener *quic.Listener
	quicCertDER  atomic.Value

	wg       sync.WaitGroup
	closeOne sync.Once
}

// NewServer validates the config and prepares the listener.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("p67: no users configured")
	}
	if cfg.StaticKey == nil {
		return nil, errors.New("p67: no static key")
	}
	if cfg.Decoy == "" {
		return nil, errors.New("p67: no decoy configured")
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if cfg.DialContext == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		cfg.DialContext = dialer.DialContext
	}
	if cfg.ListenUDP == nil {
		cfg.ListenUDP = func(context.Context) (*net.UDPConn, error) {
			return net.ListenUDP("udp", &net.UDPAddr{})
		}
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	users := make(map[UserKey]struct{}, len(cfg.Users))
	usersByUID := make(map[string]UserKey, len(cfg.Users))
	for _, user := range cfg.Users {
		users[user] = struct{}{}
		usersByUID[string(UserID(user))] = user
	}
	decoyHost, _, err := net.SplitHostPort(cfg.Decoy)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("p67: bad decoy address: %w", err)
	}
	template := fetchDecoyTemplate(cfg.DialContext, cfg.Decoy, decoyHost)
	if template != nil {
		cfg.Log("p67: certificate template mirrors decoy " + template.Subject.CommonName)
	}
	server := &Server{
		cfg:          cfg,
		ln:           ln,
		certTemplate: template,
		decoyHost:    decoyHost,
		users:        users,
		usersByUID:   usersByUID,
		nonces:       newNonceLRU(8192),
	}
	if err := server.startQUIC(); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("p67: quic listener: %w", err)
	}
	return server, nil
}

// fetchDecoyTemplate dials the decoy once and captures its real leaf
// certificate as a template for per-connection minting (best effort).
func fetchDecoyTemplate(dial func(ctx context.Context, network, address string) (net.Conn, error), decoyAddr, decoyHost string) *x509.Certificate {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", decoyAddr)
	if err != nil {
		return nil
	}
	defer func() { _ = raw.Close() }()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         decoyHost,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

// mintConnCert issues the per-connection certificate: fresh ECDSA P-256
// key, random 120-bit serial, decoy-mirrored subject/SANs, back-dated
// random validity. P67 clients never PKI-verify it (auth is the HMAC
// challenge), so the fields are pure camouflage.
func mintConnCert(template *x509.Certificate, fallbackHost string) (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	host := fallbackHost
	subject := pkix.Name{CommonName: host}
	var dnsNames []string
	var ips []net.IP
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if template != nil {
		if template.Subject.CommonName != "" {
			subject = template.Subject
			host = template.Subject.CommonName
		}
		dnsNames = template.DNSNames
		ips = template.IPAddresses
		keyUsage = template.KeyUsage
		extUsage = template.ExtKeyUsage
	}
	if len(dnsNames) == 0 && ips == nil {
		dnsNames = []string{host}
	}
	notBefore := time.Now().Add(-time.Duration(30+randInt(59)) * 24 * time.Hour)
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(365 * 24 * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extUsage,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, der, nil
}

func randInt(n int) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// Addr is the bound listener address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// QUICAddr reports the bound QUIC (UDP) address, or nil when disabled.
func (s *Server) QUICAddr() net.Addr {
	if s.quicListener == nil {
		return nil
	}
	return s.quicListener.Addr()
}

// Close stops the server.
func (s *Server) Close() error {
	var err error
	s.closeOne.Do(func() {
		err = s.ln.Close()
		if s.quicListener != nil {
			_ = s.quicListener.Close()
		}
	})
	s.wg.Wait()
	return err
}

// Serve accepts connections until Close.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		// recover guards the decoy path against writer races only; the
		// protocol path handles its own errors.
	}()
	hello, buffered, err := ReadClientHello(conn)
	if err != nil {
		// Unparseable first flight: nothing sensible to relay.
		return
	}
	user, ephPub, ok := s.tryMarker(hello)
	if !ok {
		s.relay(conn, buffered)
		return
	}

	// Fresh per-connection certificate: no static cert body for anyone to
	// fingerprint, fields mirrored from the decoy's real certificate.
	connCert, certDER, err := mintConnCert(s.certTemplate, s.decoyHost)
	if err != nil {
		s.cfg.Log("p67: mint cert: " + err.Error())
		return
	}
	replayed := newReplayConn(conn, buffered)
	tlsConn := tls.Server(replayed, &tls.Config{
		Certificates:     []tls.Certificate{connCert},
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h2", "http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519},
		// AES-128 first: the suite big sites pick for browser clients.
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384},
	})
	hsCtx, cancel := context.WithTimeout(context.Background(), handshakeTO)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		s.cfg.Log("p67: tls with valid marker failed: " + err.Error())
		return
	}
	alpn := tlsConn.ConnectionState().NegotiatedProtocol
	if _, err := s.authorize(tlsConn, &user, ephPub, certDER, alpn); err != nil {
		s.cfg.Log("p67: auth rejected: " + err.Error())
		// close_notify is what any TLS server sends on error; no P67
		// signature is leaked.
		_ = tlsConn.Close()
		return
	}
	sess := newSession(StreamConfig{
		Conn:        tlsConn,
		Pad:         PadServer,
		Log:         s.cfg.Log,
		ServeStream: s.serveStream,
	})
	defer sess.Close()
	s.watchIdle(sess)
	<-sess.Done()
}

// tryMarker attempts both carriers: the session-ID marker (sealed under the
// ECDH with the hello's own X25519 share) and the legacy 0x2F47 extension.
// Any failure is indistinguishable: the caller relays to the decoy.
func (s *Server) tryMarker(hello *ClientHello) (UserKey, []byte, bool) {
	if hello.ExtAuth != nil {
		user, ephPub, err := OpenExtMarker(hello.ExtAuth, s.cfg.StaticKey, time.Now())
		if err == nil {
			if _, known := s.users[user]; known {
				return user, ephPub, true
			}
		}
	}
	if len(hello.SessionID) == 32 && hello.KeyShareX25519 != nil && hello.HelloMsg != nil {
		aad, clientRandom, err := HelloSIDAAD(hello.HelloMsg)
		if err == nil {
			uid, err := OpenSIDMarker(hello.SessionID, hello.KeyShareX25519, s.cfg.StaticKey, time.Now(), clientRandom, aad)
			if err == nil {
				for user := range s.users {
					if string(UserID(user)) == string(uid) {
						return user, hello.KeyShareX25519, true
					}
				}
			}
		}
	}
	return UserKey{}, nil, false
}

// authorize runs the post-handshake challenge/response over any carrier.
// markerUser, when non-nil, is the identity resolved from the ClientHello
// marker (TCP path) and must match the packet's user id; the QUIC path
// passes nil and the packet alone identifies the user.
func (s *Server) authorize(conn net.Conn, markerUser *UserKey, ephPub, certDER []byte, alpn string) (UserKey, error) {
	var user UserKey
	if err := conn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return user, err
	}
	packet, err := readAuthPacket(conn)
	if err != nil {
		return user, err
	}
	uid := packet[4:16]
	if markerUser != nil {
		if string(uid) != string(UserID(*markerUser)) {
			return user, errors.New("packet user differs from marker user")
		}
		user = *markerUser
	} else {
		found, ok := s.usersByUID[string(uid)]
		if !ok {
			return UserKey{}, errors.New("unknown user")
		}
		user = found
	}
	nonce := packet[16:24]
	ts := int64(binary.BigEndian.Uint64(packet[24:32]))
	delta := time.Now().Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(TimeSkew.Seconds()) {
		return user, errors.New("timestamp outside window")
	}
	nonceID := binary.BigEndian.Uint64(nonce)
	if !s.nonces.fresh(nonceID) {
		return user, errors.New("replayed nonce")
	}
	binding := channelBinding(ephPub, certDER, alpn)
	appKey := AppKey(user, binding)
	if !verifyAuthPacket(packet, user, appKey, "penis67-auth-client", binding) {
		return user, errors.New("bad auth tag")
	}

	reply, err := buildAuthPacket(user, appKey, "penis67-auth-server", binding)
	if err != nil {
		return user, err
	}
	if _, err := conn.Write(reply); err != nil {
		return user, err
	}
	return user, conn.SetDeadline(time.Time{})
}

// relay splices an unauthorized (or unknown) client to the decoy site. The
// buffered ClientHello bytes are replayed verbatim, so the client completes
// a genuine end-to-end TLS handshake with the decoy.
func (s *Server) relay(conn net.Conn, buffered []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decoy, err := s.cfg.DialContext(ctx, "tcp", s.cfg.Decoy)
	if err != nil {
		return
	}
	defer func() { _ = decoy.Close() }()
	if _, err := decoy.Write(buffered); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(decoy, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, decoy)
		done <- struct{}{}
	}()
	<-done
}

// serveStream dispatches one opened stream.
func (s *Server) serveStream(st *Stream, host string, port int, isUDP bool) {
	defer st.Close()
	if isUDP {
		s.serveUDP(st, host, port)
		return
	}
	s.serveTCP(st, host, port)
}

func (s *Server) serveTCP(st *Stream, host string, port int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := s.cfg.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		s.cfg.Log("p67: tcp dial " + host + ":" + strconv.Itoa(port) + ": " + err.Error())
		return
	}
	defer func() { _ = target.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(target, st)
		if closer, ok := target.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}()
	_, _ = io.Copy(st, target)
	_ = st.CloseWrite()
	<-done
}

// udpIdleTimeout expires silent UDP associations.
const udpIdleTimeout = 60 * time.Second

func (s *Server) serveUDP(st *Stream, host string, port int) {
	socket, err := s.cfg.ListenUDP(context.Background())
	if err != nil {
		s.cfg.Log("p67: udp socket: " + err.Error())
		return
	}
	defer func() { _ = socket.Close() }()
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			_ = socket.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, _, err := socket.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > MaxFramePayload {
				continue
			}
			if err := st.WriteDatagram(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		_ = st.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := st.ReadDatagram(buf)
		if err != nil {
			break
		}
		if _, err := socket.WriteTo(buf[:n], remote); err != nil {
			break
		}
	}
	<-done
}

// nonceLRU is a fixed-capacity replay cache of recently seen auth nonces.
type nonceLRU struct {
	mu    sync.Mutex
	seen  map[uint64]struct{}
	order *list.List // uint64 values, front = oldest
	cap   int
}

func newNonceLRU(capacity int) *nonceLRU {
	return &nonceLRU{seen: make(map[uint64]struct{}, capacity), order: list.New(), cap: capacity}
}

func (l *nonceLRU) fresh(nonce uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[nonce]; ok {
		return false
	}
	l.seen[nonce] = struct{}{}
	l.order.PushBack(nonce)
	if l.order.Len() > l.cap {
		oldest := l.order.Front()
		if oldest != nil {
			l.order.Remove(oldest)
			delete(l.seen, oldest.Value.(uint64))
		}
	}
	return true
}
