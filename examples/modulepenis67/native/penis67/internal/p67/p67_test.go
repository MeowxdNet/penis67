package p67

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestParseLinkDefaults(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	link, err := Parse("penis67://00112233-4455-6677-8899-aabbccddeeff@vps.example.com:8443?pbk=" +
		EncodePublicKey(static.PublicKey()) + "&fp=FIREFOX")
	if err != nil {
		t.Fatal(err)
	}
	if link.Fingerprint != "firefox" {
		t.Errorf("fp = %q, want firefox", link.Fingerprint)
	}
	if link.SNI != "vps.example.com" {
		t.Errorf("sni = %q", link.SNI)
	}
	if link.Decoy != "vps.example.com" || link.DecoyPort != 443 {
		t.Errorf("decoy = %q:%d", link.Decoy, link.DecoyPort)
	}
	if !link.Pad {
		t.Error("pad should default on")
	}
	if link.User.FormatUUID() != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Errorf("uuid = %q", link.User.FormatUUID())
	}
}

func TestParseLinkErrors(t *testing.T) {
	cases := []string{
		"penis67://not-a-uuid@host",
		"penis67://00112233445566778899aabbccddeeff@host", // missing pbk
		"penis67://00112233445566778899aabbccddeeff@host?pbk=short&fp=ultra",
		"vless://00112233445566778899aabbccddeeff@host?pbk=aGVsbG8",
	}
	for _, link := range cases {
		if _, err := Parse(link); err == nil {
			t.Errorf("Parse(%q) should fail", link)
		}
	}
}

func TestLinkRoundTrip(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	link := &Link{
		User:        UserKey{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Host:        "vpn.example.net",
		Port:        443,
		Fingerprint: "chrome",
		SNI:         "www.bing.com",
		PBK:         EncodePublicKey(static.PublicKey()),
		Decoy:       "www.bing.com",
		DecoyPort:   443,
		Pad:         true,
		Name:        "тестовая нода",
	}
	parsed, err := Parse(link.Build())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User != link.User || parsed.Host != link.Host || parsed.Port != link.Port ||
		parsed.SNI != link.SNI || parsed.PBK != link.PBK || parsed.Name != link.Name {
		t.Errorf("round trip mismatch: %+v", parsed)
	}
	if Summarize(link.Build()) == "" {
		t.Error("Summarize should render")
	}
}

func TestUUIDForms(t *testing.T) {
	dashed, err := ParseUUID("00112233-4455-6677-8899-AABBCCDDEEFF")
	if err != nil {
		t.Fatal(err)
	}
	compact, err := ParseUUID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if dashed != compact {
		t.Error("uuid forms disagree")
	}
}

func TestSealOpenExtMarker(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	user := UserKey{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	payload, _, err := SealExtMarker(user, static.PublicKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != ExtDataSize {
		t.Fatalf("payload %d bytes, want %d", len(payload), ExtDataSize)
	}
	got, _, err := OpenExtMarker(payload, static, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != user {
		t.Error("user mismatch after open")
	}
}

func TestOpenExtMarkerRejects(t *testing.T) {
	static, _ := GenerateStaticKey()
	other, _ := GenerateStaticKey()
	user := UserKey{1}
	payload, _, err := SealExtMarker(user, static.PublicKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenExtMarker(payload, other, time.Now()); err == nil {
		t.Error("wrong static key must fail")
	}
	stale, _, _ := SealExtMarker(user, static.PublicKey(), time.Now().Add(-TimeSkew-time.Minute))
	if _, _, err := OpenExtMarker(stale, static, time.Now()); err == nil {
		t.Error("stale timestamp must fail")
	}
	if _, _, err := OpenExtMarker([]byte{1, 2, 3}, static, time.Now()); err == nil {
		t.Error("garbage must fail")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	frame := Frame{Stream: 42, Flag: FlagData, Payload: []byte("hello penis67")}
	wire := EncodeFrame(nil, frame)
	back, err := ReadFrame(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if back.Stream != 42 || back.Flag != FlagData || string(back.Payload) != "hello penis67" {
		t.Errorf("mismatch: %+v", back)
	}
}

func TestTargetEncoding(t *testing.T) {
	for _, addr := range []struct {
		host string
		port int
	}{
		{"93.184.216.34", 443},
		{"example.com", 65535},
		{"2606:2800:220:1:248:1893:25c8:1946", 80},
	} {
		enc, err := EncodeTarget(nil, addr.host, addr.port)
		if err != nil {
			t.Fatalf("%s: %v", addr.host, err)
		}
		host, port, err := DecodeTarget(enc)
		if err != nil {
			t.Fatalf("decode %s: %v", addr.host, err)
		}
		if host != addr.host || port != addr.port {
			t.Errorf("got %s:%d want %s:%d", host, port, addr.host, addr.port)
		}
	}
}

func TestNonceLRU(t *testing.T) {
	lru := newNonceLRU(4)
	for i := uint64(1); i <= 4; i++ {
		if !lru.fresh(i) {
			t.Fatalf("nonce %d should be fresh", i)
		}
	}
	if lru.fresh(2) {
		t.Error("nonce 2 must not repeat")
	}
	lru.fresh(5) // evicts 1
	if !lru.fresh(1) {
		t.Error("nonce 1 should be evictable-reusable")
	}
}

func TestParseClientHelloSynthetic(t *testing.T) {
	// Hand-build a minimal ClientHello: version, random, empty session id,
	// one cipher suite, null compression, one server_name + our extension.
	body := []byte{}
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // compression

	var exts []byte
	// server_name: entry = type(1) + vec16 host
	name := []byte("bing.co")
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	sniExt := []byte{0x00, 0x00, byte(len(entry) >> 8), byte(len(entry))} // type 0, vec16 entries
	sniExt = append(sniExt, entry...)
	exts = append(exts, sniExt...)

	auth := bytes.Repeat([]byte{0xAB}, ExtDataSize)
	exts = append(exts, byte(ExtType>>8), byte(ExtType&0xff), byte(ExtDataSize>>8), byte(ExtDataSize))
	exts = append(exts, auth...)

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := append([]byte{helloClient, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	hello, err := parseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	if hello.SNI != "bing.co" {
		t.Errorf("sni = %q", hello.SNI)
	}
	if !bytes.Equal(hello.ExtAuth, auth) {
		t.Error("auth ext not extracted")
	}
	if _, err := parseClientHello(msg[:10]); err == nil {
		t.Error("truncated hello must fail")
	}
}

func TestReplayConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	buffered := []byte("PRELUDE")
	rconn := newReplayConn(server, buffered)
	go func() {
		_, _ = client.Write([]byte("TAIL"))
	}()
	buf := make([]byte, 10)
	n, err := rconn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "PRELUDE" {
		t.Fatalf("first read = %q", buf[:n])
	}
	n, err = rconn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "TAIL" {
		t.Fatalf("second read = %q", buf[:n])
	}
}
