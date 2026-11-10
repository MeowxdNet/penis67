package p67

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	
)

// TestLiveAgainstLocalServer exercises the authorized path against a real
// penis67-server process started by hand:
//
//	penis67-server -listen 127.0.0.1:18443 \
//	  -uuid 00112233-4455-6677-8899-aabbccddeeff \
//	  -priv <b64url from -gen> -decoy www.bing.com:443
//	P67_LIVE=1 go test ./internal/p67 -run TestLiveAgainstLocalServer -v
//
// It fetches a DNS answer through the tunnel and fetches a page over TCP.
func TestLiveAgainstLocalServer(t *testing.T) {
	priv := os.Getenv("P67_LIVE_PRIV")
	if priv == "" {
		priv = "As5UNPVDmiM1S7qb2QnfNXVIU4cC93CET-FJSMDlAzw"
	}
	if os.Getenv("P67_LIVE") == "" {
		t.Skip("set P67_LIVE=1 (and optionally P67_LIVE_PRIV) to run")
	}
	link := &Link{
		User:        mustUUID(t, "00112233-4455-6677-8899-aabbccddeeff"),
		Host:        "127.0.0.1",
		Port:        18443,
		Fingerprint: "chrome",
		SNI:         "www.bing.com",
		PBK:         os.Getenv("P67_LIVE_PBK"),
		Decoy:       "www.bing.com",
		DecoyPort:   443,
		Pad:         true,
		Name:        "live",
	}
	if link.PBK == "" {
		static, err := DecodePrivateKey(priv)
		if err != nil {
			t.Fatalf("decode priv: %v (pass P67_LIVE_PRIV/P67_LIVE_PBK)", err)
		}
		link.PBK = EncodePublicKey(static.PublicKey())
	}

	engine := NewEngine(link, plainDialer(), func(string) {})
	defer engine.Close()

	// UDP: DNS through the tunnel.
	pc, err := engine.PacketConn(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := pc.WriteTo(query, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = pc.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("dns through tunnel: %v", err)
	}
	t.Logf("dns reply through p67 tunnel: %d bytes", n)

	// TCP: a real page through the tunnel.
	conn, err := engine.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 12)
	if _, err := readFullLive(conn, head); err != nil {
		t.Fatalf("http through tunnel: %v", err)
	}
	t.Logf("http status line through p67 tunnel: %q", head)
}

func readFullLive(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
