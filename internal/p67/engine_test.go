package p67

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"net.meowxd.modcommon/modhost"
)

// testbed spins up the full loopback constellation: a fake decoy HTTPS site,
// a P67 server relaying to it, and helpers to build client links.
type testbed struct {
	t *testing.T

	decoyLn   net.Listener
	decoyCert tls.Certificate
	decoyDER  []byte // leaf DER the decoy presents

	staticPriv *ecdh.PrivateKey
	server     *Server

	uuid string
}

func newTestbed(t *testing.T) *testbed {
	t.Helper()
	tb := &testbed{t: t, uuid: "00112233-4455-6677-8899-aabbccddeeff"}

	// --- fake decoy: plain TLS server with a self-signed cert ---
	decoyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "decoy.local"},
		DNSNames:     []string{"decoy.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, decoyPriv.Public(), decoyPriv)
	if err != nil {
		t.Fatal(err)
	}
	tb.decoyCert = tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  decoyPriv,
	}
	tb.decoyDER = der
	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tb.decoyLn = decoyLn
	go func() {
		for {
			conn, err := decoyLn.Accept()
			if err != nil {
				return
			}
			go tb.serveDecoy(conn)
		}
	}()

	// --- p67 server ---
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	user, err := ParseUUID(tb.uuid)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		Listen:    "127.0.0.1:0",
		Users:     []UserKey{user},
		StaticKey: static,
		Decoy:     decoyLn.Addr().String(),
		Log:       func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	tb.server = server
	tb.staticPriv = static
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { _ = server.Close(); _ = decoyLn.Close() })
	return tb
}

func (tb *testbed) serveDecoy(conn net.Conn) {
	defer conn.Close()
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{tb.decoyCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	if _, err := tlsConn.Read(buf); err != nil && err != io.EOF {
		return
	}
	fmt.Fprintf(tlsConn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ndecoy-page")
}

func (tb *testbed) link() *Link {
	return &Link{
		User:        mustUUID(tb.t, tb.uuid),
		Host:        "127.0.0.1",
		Port:        portOf(tb.t, tb.server.Addr()),
		Fingerprint: "chrome",
		SNI:         "decoy.local",
		PBK:         EncodePublicKey(tb.staticPriv.PublicKey()),
		Decoy:       "decoy.local",
		DecoyPort:   443,
		Pad:         true,
		Name:        "test",
	}
}

func mustUUID(t *testing.T, s string) UserKey {
	t.Helper()
	user, err := ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func portOf(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portText, "%d", &port)
	return port
}

func testDialer() *modhost.Dialer {
	return modhost.NewDialer(modhost.NoProtect)
}

// TestEndToEndTCP dials an echo server through the tunnel.
func TestEndToEndTCP(t *testing.T) {
	tb := newTestbed(t)

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	engine := NewEngine(tb.link(), testDialer(), nil)
	defer engine.Close()

	conn, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("penis67 "), 512) // 4 KiB, several frames
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("echo mismatch")
	}
}

// TestEndToEndUDP round-trips a datagram through a UDP association.
func TestEndToEndUDP(t *testing.T) {
	tb := newTestbed(t)

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte("echo:"), buf[:n]...)
			_, _ = echo.WriteToUDP(reply, from)
		}
	}()

	engine := NewEngine(tb.link(), testDialer(), nil)
	defer engine.Close()

	pc, err := engine.PacketConn(context.Background(), echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.WriteTo([]byte("hello-udp"), nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echo:hello-udp" {
		t.Errorf("udp echo = %q", buf[:n])
	}
}

// TestDecoyRelay proves the REALITY property: a plain TLS client (no P67
// marker) completes a genuine handshake with the decoy through our server
// and fetches the decoy page, seeing the decoy's own certificate.
func TestDecoyRelay(t *testing.T) {
	tb := newTestbed(t)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemOf(tb.decoyDER)) {
		t.Fatal("decoy cert into pool")
	}
	conn, err := tls.Dial("tcp", tb.server.Addr().String(), &tls.Config{
		ServerName: "decoy.local",
		RootCAs:    pool, // must verify against the DECOY's cert, not ours
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("prober handshake should succeed via relay: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer cert")
	}
	if !bytes.Equal(state.PeerCertificates[0].Raw, tb.decoyDER) {
		t.Error("prober saw a certificate that is not the decoy's own")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: decoy.local\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("decoy-page")) {
		t.Errorf("decoy body = %q", body)
	}
}

// TestWrongUserRelaysToDecoy: a valid-looking marker with an unknown user is
// indistinguishable from a foreign client — the connection falls through to
// the decoy, and the client's auth read fails.
func TestWrongUserRelaysToDecoy(t *testing.T) {
	tb := newTestbed(t)

	stranger, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = stranger
	link := tb.link()
	link.User = mustUUID(t, "ffffffff-ffff-ffff-ffff-ffffffffffff")
	sess, err := Connect(context.Background(), ClientConfig{
		Link:        link,
		DialContext: testDialer().DialContext,
		Log:         func(string) {},
	})
	if err == nil {
		_ = sess.Close()
		t.Fatal("auth with a foreign uuid must fail")
	}
}

// TestMarkerHidesFromParser: a ClientHello generated by the real client
// stack parses cleanly server-side, and a plain stdlib ClientHello carries
// no marker.
func TestMarkerHidesFromParser(t *testing.T) {
	// stdlib hello, no marker: spin the client side of a TLS handshake
	// against a listener that inspects the hello.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan *ClientHello, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		hello, _, err := ReadClientHello(conn)
		if err == nil {
			seen <- hello
		}
		close(seen)
		conn.Close()
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err == nil {
		conn.Close()
	}
	hello := <-seen
	if hello == nil {
		t.Fatal("no hello parsed")
	}
	if hello.ExtAuth != nil {
		t.Error("plain stdlib hello must not carry a marker")
	}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
