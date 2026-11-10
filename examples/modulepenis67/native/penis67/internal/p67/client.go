// The client half: dial with a browser-faithful uTLS ClientHello carrying
// the marker, then upgrade the TLS session to a multiplexed P67 tunnel.
//
// Default carrier ("hide=sid"): the auth marker occupies the 32-byte
// legacy_session_id (random by definition in every TLS 1.3 hello) and its
// ephemeral key doubles as the handshake's own X25519 share — plain, or the
// tail of the X25519MLKEM768 hybrid share modern browsers send. The
// ClientHello then contains zero non-browser bytes.
package p67

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// authMagic prefixes the post-handshake auth exchange; version byte follows.
var authMagic = []byte("P67")

const (
	authVersion   = 2
	authPacketLen = 3 + 1 + 12 + 8 + 8 + 32 // magic, ver, uid, nonce, ts, tag
	authTimeout   = 15 * time.Second
	handshakeTO   = 15 * time.Second
)

// FingerprintID maps an fp= link value to a uTLS preset. "mixed" rotates.
func FingerprintID(name string) utls.ClientHelloID {
	presets := []utls.ClientHelloID{
		utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto,
		utls.HelloEdge_Auto, utls.HelloIOS_Auto, utls.HelloRandomizedALPN,
	}
	switch name {
	case "mixed":
		return presets[mathrand.IntN(len(presets))]
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "edge":
		return utls.HelloEdge_Auto
	case "random":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloChrome_Auto
	}
}

// buildSpec prepares the fingerprint: ECH stripped unless explicitly allowed
// (ECH is throttled in some networks), plus the 0x2F47 marker extension for
// the legacy "hide=ext" carrier.
func buildSpec(fp string, extMarker []byte, allowECH bool) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(FingerprintID(fp))
	if err != nil {
		return spec, fmt.Errorf("p67: fingerprint %q: %w", fp, err)
	}
	if !allowECH {
		kept := spec.Extensions[:0]
		for _, ext := range spec.Extensions {
			switch ext.(type) {
			case *utls.GREASEEncryptedClientHelloExtension:
				continue // Chrome's GREASE ECH — drop it, ECH-shaped bytes attract some DPIs
			default:
				kept = append(kept, ext)
			}
		}
		spec.Extensions = kept
	}
	if extMarker != nil {
		spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: ExtType, Data: extMarker})
	}
	return spec, nil
}

// markerEphKey picks the private X25519 key matching the first X25519-family
// share in the hello — the exact entry the server's parser extracts: a plain
// X25519 entry uses Ecdhe, the tail of an X25519MLKEM768 hybrid share uses
// MlkemEcdhe. Matching by public-key bytes keeps both sides in sync.
func markerEphKey(hello *utls.PubClientHelloMsg, keys *utls.KeySharePrivateKeys) (*ecdh.PrivateKey, error) {
	if keys == nil {
		return nil, errors.New("p67: fingerprint produced no key share")
	}
	for _, share := range hello.KeyShares {
		switch share.Group {
		case utls.X25519MLKEM768:
			if keys.MlkemEcdhe == nil || len(share.Data) < 32 {
				continue
			}
			if bytes.Equal(share.Data[len(share.Data)-32:], keys.MlkemEcdhe.PublicKey().Bytes()) {
				return keys.MlkemEcdhe, nil
			}
		case utls.X25519:
			if keys.Ecdhe == nil || len(share.Data) != 32 {
				continue
			}
			if bytes.Equal(share.Data, keys.Ecdhe.PublicKey().Bytes()) {
				return keys.Ecdhe, nil
			}
		}
	}
	return nil, errors.New("p67: fingerprint key share has no X25519 half")
}

// Target is one stream destination.
type Target struct {
	Host string
	Port int
	UDP  bool
}

// prepareHello arms a fresh UClient with the fingerprint and the marker.
// The default carrier hides the marker in legacy_session_id using the
// handshake's own X25519 share; when the fingerprint offers no X25519 share
// (e.g. android/OkHttp) it transparently falls back to the 0x2F47 carrier.
func prepareHello(uconn *utls.UConn, link *Link, serverPub *ecdh.PublicKey) ([]byte, error) {
	if link.Hide != HideExt {
		spec, err := buildSpec(link.Fingerprint, nil, link.AllowECH)
		if err != nil {
			return nil, err
		}
		if err := uconn.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("p67: apply fingerprint: %w", err)
		}
		if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
			return nil, fmt.Errorf("p67: build hello: %w", err)
		}
		ephPriv, err := markerEphKey(uconn.HandshakeState.Hello, uconn.HandshakeState.State13.KeyShareKeys)
		if err == nil {
			// REALITY-parity binding: AAD = the whole ClientHello with
			// the session-id slot zeroed, nonce from ClientRandom[20:32].
			aad, clientRandom, err := HelloSIDAAD(uconn.HandshakeState.Hello.Raw)
			if err != nil {
				return nil, fmt.Errorf("p67: sid aad: %w", err)
			}
			sid, err := SealSIDMarker(link.User, ephPriv, serverPub, time.Now(), clientRandom, aad)
			if err != nil {
				return nil, fmt.Errorf("p67: seal sid marker: %w", err)
			}
			uconn.HandshakeState.Hello.SessionId = sid
			if err := uconn.MarshalClientHello(); err != nil {
				return nil, fmt.Errorf("p67: re-marshal hello: %w", err)
			}
			return ephPriv.PublicKey().Bytes(), nil
		}
		// No X25519 share in this fingerprint — start over with the ext
		// carrier. Nothing has touched the wire yet, so this is safe.
	}
	marker, ephPub, err := SealExtMarker(link.User, serverPub, time.Now())
	if err != nil {
		return nil, fmt.Errorf("p67: seal marker: %w", err)
	}
	spec, err := buildSpec(link.Fingerprint, marker, link.AllowECH)
	if err != nil {
		return nil, err
	}
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("p67: apply fingerprint: %w", err)
	}
	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, fmt.Errorf("p67: build hello: %w", err)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("p67: marshal hello: %w", err)
	}
	return ephPub, nil
}

// ClientConfig describes one tunnel endpoint. FirstOpen, when set, pipelines
// the first stream into the auth flight, saving one RTT on cold connects.
// ListenUDP opens the client UDP socket for the QUIC carrier (the engine
// injects the protected listener).
type ClientConfig struct {
	Link        *Link
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	ListenUDP   func(ctx context.Context) (*net.UDPConn, error)
	Log         func(string)
	FirstOpen   *Target
}

// Connect performs the full P67 dance and returns the session.
func Connect(ctx context.Context, cfg ClientConfig) (*Session, error) {
	sess, _, err := ConnectOpen(ctx, cfg)
	return sess, err
}

// ConnectOpen performs the handshake and, when cfg.FirstOpen is set,
// returns a stream that was opened inside the auth flight (0-RTT open).
func ConnectOpen(ctx context.Context, cfg ClientConfig) (*Session, *Stream, error) {
	if cfg.Link == nil {
		return nil, nil, errors.New("p67: no link")
	}
	if cfg.DialContext == nil {
		cfg.DialContext = (&net.Dialer{}).DialContext
	}
	log := cfg.Log
	if log == nil {
		log = func(string) {}
	}
	link := cfg.Link

	serverPub, err := DecodePublicKey(link.PBK)
	if err != nil {
		return nil, nil, err
	}

	raw, err := cfg.DialContext(ctx, "tcp", link.Address())
	if err != nil {
		return nil, nil, fmt.Errorf("p67: dial: %w", err)
	}
	defer func() {
		if raw != nil {
			_ = raw.Close()
		}
	}()

	// Optional ClientHello fragmentation: split the first flight into small
	// TCP segments so per-segment DPI matchers lose the hello.
	wire := net.Conn(raw)
	if link.Frag > 0 {
		wire = &fragConn{Conn: raw, size: link.Frag, delay: time.Duration(link.FragDelay) * time.Millisecond}
	}

	tlsConfig := &utls.Config{
		ServerName:         link.SNI,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         utls.VersionTLS13,
		InsecureSkipVerify: true, // authentication is the ECDH marker + HMAC challenge
	}
	uconn := utls.UClient(wire, tlsConfig, utls.HelloCustom)

	var ephPub []byte // marker ephemeral public key, feeds the channel binding
	ephPub, err = prepareHello(uconn, link, serverPub)
	if err != nil {
		return nil, nil, err
	}

	hsCtx, cancel := context.WithTimeout(ctx, handshakeTO)
	defer cancel()
	if err := uconn.HandshakeContext(hsCtx); err != nil {
		return nil, nil, fmt.Errorf("p67: tls: %w", err)
	}

	state := uconn.ConnectionState()
	certDER := []byte{}
	if len(state.PeerCertificates) > 0 {
		certDER = state.PeerCertificates[0].Raw
	}
	binding := channelBinding(ephPub, certDER, state.NegotiatedProtocol)
	appKey := AppKey(link.User, binding)

	// Prove ourselves to the server and demand proof back. Both sides use
	// distinct HMAC purposes so a reflected packet never validates.
	packet, err := buildAuthPacket(link.User, appKey, "penis67-auth-client", binding)
	if err != nil {
		return nil, nil, err
	}

	// 0-RTT open (link.RTT0): the first stream's OPEN rides the same
	// flight as the auth packet — the server processes auth, then the mux,
	// saving an RTT. Off by default: it reveals the first target address
	// to anyone who terminates TLS in front of the server.
	flight := packet
	var preID uint32
	if cfg.FirstOpen != nil {
		preID = 1
		var payload []byte
		payload, err = EncodeTarget(nil, cfg.FirstOpen.Host, cfg.FirstOpen.Port)
		if err != nil {
			return nil, nil, err
		}
		flag := FlagOpenTCP
		if cfg.FirstOpen.UDP {
			flag = FlagOpenUDP
		}
		flight = EncodeFrame(packet, Frame{Stream: preID, Flag: flag, Payload: payload})
	}
	if err := uconn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return nil, nil, err
	}
	if _, err := uconn.Write(flight); err != nil {
		return nil, nil, fmt.Errorf("p67: auth write: %w", err)
	}
	reply, err := readAuthPacket(uconn)
	if err != nil {
		return nil, nil, fmt.Errorf("p67: auth reply: %w", err)
	}
	if !verifyAuthPacket(reply, link.User, appKey, "penis67-auth-server", binding) {
		return nil, nil, errors.New("p67: server auth failed (wrong pbk or forged endpoint)")
	}
	_ = uconn.SetDeadline(time.Time{})

	// Synthesize the pre-opened stream so the read loop can deliver into it
	// the moment it starts.
	preload := map[uint32]*Stream{}
	if cfg.FirstOpen != nil {
		preload[preID] = newStream(nil, preID, cfg.FirstOpen.UDP)
	}

	raw = nil // ownership moved into the session
	log("p67: session up (" + link.Fingerprint + " fp, sni " + link.SNI + ", hide " + link.Hide + ")")
	pad := PadClient
	if !link.Pad {
		pad = PadOff
	}
	sess := newSession(StreamConfig{
		Conn:    uconn,
		Pad:     pad,
		Log:     log,
		Preload: preload,
	})
	if st := preload[preID]; st != nil {
		return sess, st, nil
	}
	return sess, nil, nil
}

// channelBinding hashes every value both endpoints can compute but a
// middleman cannot forge: the marker's ephemeral key, the exact certificate
// the client saw, and the negotiated ALPN.
func channelBinding(ephPub, certDER []byte, alpn string) []byte {
	h := sha256.New()
	h.Write(ephPub)
	h.Write(certDER)
	h.Write([]byte(alpn))
	return h.Sum(nil)
}

func authTag(appKey []byte, purpose string, uid, nonce []byte, ts int64, binding []byte) []byte {
	mac := hmac.New(sha256.New, appKey)
	mac.Write([]byte(purpose))
	mac.Write(uid)
	mac.Write(nonce)
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(ts))
	mac.Write(tsBytes[:])
	mac.Write(binding)
	return mac.Sum(nil)
}

// buildAuthPacket mints the fixed-size v2 auth packet: the 12-byte user id
// rides inside so carriers without a ClientHello marker (QUIC) can resolve
// the user, sealed under the channel-bound app key.
func buildAuthPacket(user UserKey, appKey []byte, purpose string, binding []byte) ([]byte, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	uid := UserID(user)
	packet := make([]byte, 0, authPacketLen)
	packet = append(packet, authMagic...)
	packet = append(packet, authVersion)
	packet = append(packet, uid...)
	packet = append(packet, nonce...)
	packet = binary.BigEndian.AppendUint64(packet, uint64(now))
	packet = append(packet, authTag(appKey, purpose, uid, nonce, now, binding)...)
	return packet, nil
}

// verifyAuthPacket checks a peer's auth packet (uid must match when known).
func verifyAuthPacket(packet []byte, user UserKey, appKey []byte, purpose string, binding []byte) bool {
	uid := packet[4:16]
	if string(uid) != string(UserID(user)) {
		return false
	}
	nonce := packet[16:24]
	ts := int64(binary.BigEndian.Uint64(packet[24:32]))
	want := authTag(appKey, purpose, uid, nonce, ts, binding)
	return hmac.Equal(packet[32:64], want)
}

// readAuthPacket reads and shape-checks the fixed-size auth packet.
func readAuthPacket(conn net.Conn) ([]byte, error) {
	packet := make([]byte, authPacketLen)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return nil, err
	}
	if string(packet[:3]) != string(authMagic) || packet[3] != authVersion {
		return nil, errors.New("bad auth magic/version")
	}
	return packet, nil
}

// fragConn splits writes into ≤size TCP segments until the first server
// record arrives (i.e., only the ClientHello flight), then passes through.
type fragConn struct {
	net.Conn
	size    int
	delay   time.Duration
	passed  atomic.Bool
	writing atomic.Bool
}

func (f *fragConn) Write(b []byte) (int, error) {
	if f.passed.Load() || f.size <= 0 {
		return f.Conn.Write(b)
	}
	sent := 0
	for sent < len(b) {
		n := f.size
		if rem := len(b) - sent; rem < n {
			n = rem
		}
		if _, err := f.Conn.Write(b[sent : sent+n]); err != nil {
			return sent, err
		}
		sent += n
		if sent < len(b) && f.delay > 0 {
			time.Sleep(f.delay)
		}
	}
	return sent, nil
}

func (f *fragConn) Read(b []byte) (int, error) {
	n, err := f.Conn.Read(b)
	f.passed.Store(true)
	return n, err
}
