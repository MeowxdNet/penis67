package p67

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestSealOpenSIDMarker(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	user := UserKey{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
	eph, err := GenerateStaticKey() // any X25519 pair works for the math
	if err != nil {
		t.Fatal(err)
	}
	clientRandom := make([]byte, 32)
	aad := make([]byte, 517)
	if _, err := rand.Read(clientRandom); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(aad); err != nil {
		t.Fatal(err)
	}
	sid, err := SealSIDMarker(user, eph, static.PublicKey(), time.Now(), clientRandom, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(sid) != 32 {
		t.Fatalf("sid marker %d bytes, want exactly 32", len(sid))
	}
	uid, err := OpenSIDMarker(sid, eph.PublicKey().Bytes(), static, time.Now(), clientRandom, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uid, UserID(user)) {
		t.Error("uid mismatch after open")
	}
	// AAD binding: the same sid in a different hello must not open.
	if _, err := OpenSIDMarker(sid, eph.PublicKey().Bytes(), static, time.Now(), clientRandom, append(aad, 0)); err == nil {
		t.Error("transplanted sid into another hello must fail")
	}
	// Different client random (nonce) must not open.
	other := append([]byte(nil), clientRandom...)
	other[20] ^= 1
	if _, err := OpenSIDMarker(sid, eph.PublicKey().Bytes(), static, time.Now(), other, aad); err == nil {
		t.Error("different nonce must fail")
	}
}

func TestOpenSIDMarkerRejects(t *testing.T) {
	static, _ := GenerateStaticKey()
	other, _ := GenerateStaticKey()
	user := UserKey{3, 1, 4, 1, 5}
	eph, _ := GenerateStaticKey()
	clientRandom := make([]byte, 32)
	aad := make([]byte, 400)
	_, _ = rand.Read(clientRandom)
	_, _ = rand.Read(aad)
	sid, err := SealSIDMarker(user, eph, static.PublicKey(), time.Now(), clientRandom, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSIDMarker(sid, eph.PublicKey().Bytes(), other, time.Now(), clientRandom, aad); err == nil {
		t.Error("wrong static key must fail")
	}
	staleEph, _ := GenerateStaticKey()
	stale, _ := SealSIDMarker(user, staleEph, static.PublicKey(), time.Now().Add(-TimeSkew-time.Minute), clientRandom, aad)
	if _, err := OpenSIDMarker(stale, staleEph.PublicKey().Bytes(), static, time.Now(), clientRandom, aad); err == nil {
		t.Error("stale timestamp must fail")
	}
	if _, err := OpenSIDMarker(make([]byte, 32), eph.PublicKey().Bytes(), static, time.Now(), clientRandom, aad); err == nil {
		t.Error("garbage must fail")
	}
}

// TestPrepareHelloPurity is the camouflage audit: the default sid carrier
// produces a hello with no 0x2F47 extension, no ECH-shaped extension, a
// 32-byte session id and a parseable X25519 share.
func TestPrepareHelloPurity(t *testing.T) {
	static, _ := GenerateStaticKey()
	serverPub := static.PublicKey()
	for _, fp := range []string{"chrome", "firefox", "safari", "ios", "edge"} {
		client, serverPipe := net.Pipe()
		uconn := utls.UClient(client, &utls.Config{
			ServerName: "www.bing.com", NextProtos: []string{"h2", "http/1.1"},
			MinVersion: utls.VersionTLS13, InsecureSkipVerify: true,
		}, utls.HelloCustom)
		link := &Link{Fingerprint: fp, Hide: HideSID, SNI: "www.bing.com", User: UserKey{9}}
		if _, err := prepareHello(uconn, link, serverPub); err != nil {
			t.Fatalf("%s: prepareHello: %v", fp, err)
		}
		hello, err := parseClientHello(uconn.HandshakeState.Hello.Raw)
		if err != nil {
			t.Fatalf("%s: parse own hello: %v", fp, err)
		}
		if hello.ExtAuth != nil {
			t.Errorf("%s: sid carrier must not carry the 0x2F47 extension", fp)
		}
		for _, ext := range hello.ExtTypes {
			if ext == 0xfe0d {
				t.Errorf("%s: ECH extension leaked into the hello", fp)
			}
		}
		if len(hello.SessionID) != 32 {
			t.Errorf("%s: session id %d bytes, want 32", fp, len(hello.SessionID))
		}
		if hello.KeyShareX25519 == nil {
			t.Errorf("%s: no X25519 share extracted", fp)
		}
		_ = serverPipe.Close()
		_ = client.Close()
	}
}

// TestPrepareHelloExtCarrier keeps the legacy carrier working.
func TestPrepareHelloExtCarrier(t *testing.T) {
	static, _ := GenerateStaticKey()
	client, serverPipe := net.Pipe()
	defer client.Close()
	defer serverPipe.Close()
	uconn := utls.UClient(client, &utls.Config{ServerName: "x"}, utls.HelloCustom)
	link := &Link{Fingerprint: "chrome", Hide: HideExt, User: UserKey{1}}
	if _, err := prepareHello(uconn, link, static.PublicKey()); err != nil {
		t.Fatal(err)
	}
	hello, err := parseClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ExtAuth == nil {
		t.Error("ext carrier must carry the marker extension")
	}
	if len(hello.ExtAuth) != ExtDataSize {
		t.Errorf("marker payload %d bytes", len(hello.ExtAuth))
	}
}

// TestKeyShareParserHybrid checks the MLKEM tail extraction directly.
func TestKeyShareParserHybrid(t *testing.T) {
	mlkem := bytes.Repeat([]byte{0xAA}, 1184)
	x25519 := bytes.Repeat([]byte{0xBB}, 32)
	// client_shares: one hybrid entry (group 0x11ec, 0x04c0 = 1216-byte key).
	entry := []byte{0x11, 0xec, 0x04, 0xc0}
	entry = append(entry, mlkem...)
	entry = append(entry, x25519...)
	data := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	got := parseKeyShareX25519(data)
	if !bytes.Equal(got, x25519) {
		t.Errorf("hybrid tail = %d bytes, want the x25519 half", len(got))
	}
	// Plain X25519 entry.
	plain := append([]byte{0x00, 0x1d, 0x00, 0x20}, x25519...)
	data2 := append([]byte{0x00, byte(len(plain))}, plain...)
	if got := parseKeyShareX25519(data2); !bytes.Equal(got, x25519) {
		t.Errorf("plain share = %d bytes", len(got))
	}
}

// TestFragConnSplitsFirstFlight verifies fragmentation stops after the
// hello flight (first read) and fragments during it.
func TestFragConnSplitsFirstFlight(t *testing.T) {
	client, serverPipe := net.Pipe()
	defer client.Close()
	defer serverPipe.Close()
	frag := &fragConn{Conn: client, size: 10, delay: 0}
	sizes := make(chan int, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := serverPipe.Read(buf)
			if err != nil {
				close(sizes)
				return
			}
			sizes <- n
		}
	}()
	if _, err := frag.Write(make([]byte, 25)); err != nil {
		t.Fatal(err)
	}
	// Server reading counts the fragments as they arrive on the pipe.
	for want := 0; want < 3; want++ {
		n := <-sizes
		if n > 10 {
			t.Errorf("fragment %d bytes, frag size is 10", n)
		}
	}
	// After the first read passthrough engages.
	_ = frag.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := frag.Read(buf); err != nil && !isTimeout(err) {
		t.Fatal(err)
	}
	if _, err := frag.Write(make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	total := 0
	for total < 5000 {
		select {
		case n, ok := <-sizes:
			if !ok {
				t.Fatal("pipe closed early")
			}
			if n > 10 {
				// passthrough: the 5000-byte write may arrive as one read
				return
			}
			total += n
		case <-deadline:
			t.Fatal("fragments stalled")
		}
	}
}

func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	if t, ok := err.(timeout); ok {
		return t.Timeout()
	}
	return false
}

// TestEndToEndFragmentedAndMixed runs the tunnel with ClientHello
// fragmentation and a rotating fingerprint to prove the paths compose.
func TestEndToEndFragmentedAndMixed(t *testing.T) {
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
			go func() { defer conn.Close(); _, _ = conn.Write([]byte("pong")) }()
		}
	}()

	link := tb.link()
	link.Fingerprint = "mixed"
	link.Frag = 64
	link.FragDelay = 1
	engine := NewEngine(link, testDialer(), nil)
	defer engine.Close()

	conn, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := readFullLive(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Errorf("reply %q", buf)
	}
}

// TestEndToEndExtCarrier runs one full tunnel over the legacy carrier.
func TestEndToEndExtCarrier(t *testing.T) {
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
			go func() { defer conn.Close(); _, _ = conn.Write([]byte("ext-ok")) }()
		}
	}()

	link := tb.link()
	link.Hide = HideExt
	engine := NewEngine(link, testDialer(), nil)
	defer engine.Close()

	conn, err := engine.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 6)
	if _, err := readFullLive(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ext-ok" {
		t.Errorf("reply %q", buf)
	}
}
