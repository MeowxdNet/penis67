package p67

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"net.meowxd.modcommon/modhost"
)

// TestFlowControlBigTransfer pushes well past the 256 KiB initial window:
// with a slow-ish consumer the sender must stall on credits and resume on
// Window frames without losing a byte.
func TestFlowControlBigTransfer(t *testing.T) {
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

	payload := make([]byte, 768*1024) // several legacy windows worth of data
	if _, err := readRand(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("large transfer mismatch (flow control dropped or reordered bytes)")
	}
}

func readRand(b []byte) (int, error) {
	return cryptoRandRead(b)
}

// TestMultiCarrier spreads streams over parallel carriers.
func TestMultiCarrier(t *testing.T) {
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

	link := tb.link()
	link.MultiCarrier = 2
	engine := NewEngine(link, testDialer(), nil)
	defer engine.Close()

	// Open a few streams so the pool tops up.
	conns := make([]net.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		conn, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for engine.LiveCarriers() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		// More dials keep the pool topping up.
		extra, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
		if err == nil {
			conns = append(conns, extra)
		}
	}
	if engine.LiveCarriers() < 2 {
		t.Fatalf("expected 2 carriers, have %d", engine.LiveCarriers())
	}
	// Streams still work across carriers.
	if _, err := conns[0].Write([]byte("spread")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	_ = conns[0].SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conns[0], buf); err != nil {
		t.Fatal(err)
	}
}

// TestPerConnectionCerts proves the terminating path never shows the same
// certificate body twice (JA4X-style static fingerprint impossible).
func TestPerConnectionCerts(t *testing.T) {
	digest := func(der []byte) []byte {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Raw
	}
	first, der1, err := mintConnCert(nil, "www.bing.com")
	if err != nil {
		t.Fatal(err)
	}
	second, der2, err := mintConnCert(nil, "www.bing.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest(der1), digest(der2)) {
		t.Error("two connections must not share one certificate body")
	}
	if first.Leaf == nil || second.Leaf == nil {
		t.Error("minted certs must carry a parsed leaf")
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Error("serial numbers must differ")
	}
}

// TestEndToEndQUIC runs TCP and UDP through the QUIC carrier.
func TestEndToEndQUIC(t *testing.T) {
	tb := newTestbed(t)

	// Re-start the server with QUIC enabled on an ephemeral UDP port.
	quicServer, err := NewServer(ServerConfig{
		Listen:    "127.0.0.1:0",
		Users:     []UserKey{mustUUID(t, tb.uuid)},
		StaticKey: tb.staticPriv,
		Decoy:     tb.decoyLn.Addr().String(),
		QuicAddr:  "127.0.0.1:0",
		Log:       func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = quicServer.Serve() }()
	t.Cleanup(func() { _ = quicServer.Close() })

	link := tb.link()
	link.Net = NetQUIC
	if quic := quicServer.QUICAddr(); quic != nil {
		link.Port = portOf(t, quic)
	}

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

	engine := NewEngine(link, modhost.NewDialer(modhost.NoProtect), nil)
	defer engine.Close()

	conn, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	msg := bytes.Repeat([]byte("quic"), 2048)
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Error("quic tcp echo mismatch")
	}

	// UDP through QUIC: DNS-ish echo.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte("q:"), buf[:n]...)
			_, _ = udp.WriteToUDP(reply, from)
		}
	}()
	pc, err := engine.PacketConn(context.Background(), udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := pc.WriteTo([]byte("dns?"), nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "q:dns?" {
		t.Errorf("quic udp echo = %q", buf[:n])
	}
}

// cryptoRandRead hides the direct rand.Read from the helpers above.
func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}
