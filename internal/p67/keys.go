// Package p67 implements the penis67 protocol (P67): a REALITY-class stealth
// proxy tunnel that rides an ordinary-looking TLS 1.3 session.
//
// Design in one paragraph: the client sends a browser-faithful ClientHello
// (uTLS fingerprint) carrying a 72-byte authentication blob inside an
// unassigned TLS extension (0x2F47). The blob is sealed with AES-256-GCM
// under a key derived from an ephemeral X25519 ECDH with the server's static
// public key, so it is pseudorandom to everyone else. A server that cannot
// open the blob — wrong key, no extension, garbage — does not terminate TLS
// at all: it relays the raw bytes to the configured decoy site, so an active
// prober completes a genuine TLS handshake with, say, www.bing.com and
// fetches a genuine bing certificate. A server that opens the blob
// terminates TLS itself, proves its identity with an HMAC over a channel
// binding, and multiplexes TCP flows and UDP associations over the session.
package p67

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Protocol-wide constants.
const (
	// ExtType is the unassigned TLS extension codepoint carrying the P67
	// authentication blob. Unassigned per the IANA TLS extension registry
	// at design time; unknown extensions are ignored by TLS stacks and are
	// not blocked by known DPI deployments.
	ExtType uint16 = 0x2F47

	// Ext blob geometry (bytes): ephemeral X25519 public key, then the
	// AEAD-sealed payload (16-byte user key || 8-byte unix time || 16-byte
	// GCM tag).
	extEphSize    = 32
	extSealedSize = 16 + 8 + 16
	ExtDataSize   = extEphSize + extSealedSize

	// TimeSkew is the tolerated clock drift for the marker timestamp.
	TimeSkew = 2 * time.Minute

	hkdfExtSalt = "penis67-ext-v1"
	hkdfExtInfo = "auth"
	hkdfAppInfo = "penis67-app-v1"
)

// UserKey is the 16-byte shared secret (a UUID's bytes) identifying one user.
type UserKey [16]byte

// ParseUUID accepts the canonical 8-4-4-4-12 form, the dashed-free 32-hex
// form, and any capitalization, exactly like VLESS links do.
func ParseUUID(s string) (UserKey, error) {
	var key UserKey
	clean := strings.Map(func(r rune) rune {
		if r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(clean) != 32 {
		return key, fmt.Errorf("p67: uuid must be 32 hex chars, got %d", len(clean))
	}
	for i := 0; i < 16; i++ {
		v, err := parseHexByte(clean[i*2], clean[i*2+1])
		if err != nil {
			return key, fmt.Errorf("p67: bad uuid hex at %d: %w", i*2, err)
		}
		key[i] = v
	}
	return key, nil
}

// FormatUUID renders the key in canonical 8-4-4-4-12 form.
func (k UserKey) FormatUUID() string {
	hex := fmt.Sprintf("%032x", k[:])
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

func parseHexByte(hi, lo byte) (byte, error) {
	h, err := hexVal(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexVal(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("not hex")
}

// GenerateStaticKey creates the server's long-term X25519 identity.
func GenerateStaticKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// EncodePublicKey encodes an X25519 public key as unpadded base64url.
func EncodePublicKey(pub *ecdh.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub.Bytes())
}

// DecodePublicKey parses such a base64url X25519 public key.
func DecodePublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("p67: pbk is not base64url: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("p67: pbk must be 32 bytes, got %d", len(raw))
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// DecodePrivateKey parses a base64url X25519 private key (server side).
func DecodePrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("p67: private key is not base64url: %w", err)
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// extAuthKey derives the AEAD key for the ClientHello marker from the ECDH
// shared secret between the client's ephemeral key and the server's static key.
func extAuthKey(shared []byte) []byte {
	out := make([]byte, 32)
	h := hkdf.New(sha256.New, shared, []byte(hkdfExtSalt), []byte(hkdfExtInfo))
	if _, err := h.Read(out); err != nil {
		panic("p67: hkdf: " + err.Error())
	}
	return out
}

// AppKey derives the post-handshake MAC key from the user key and the channel
// binding, binding application auth to this exact TLS session.
func AppKey(user UserKey, binding []byte) []byte {
	out := make([]byte, 32)
	h := hkdf.New(sha256.New, user[:], binding, []byte(hkdfAppInfo))
	if _, err := h.Read(out); err != nil {
		panic("p67: hkdf: " + err.Error())
	}
	return out
}

// SealExtMarker builds the 72-byte extension payload that authenticates the
// client inside the ClientHello. It returns the payload and the ephemeral
// public key (needed later for the channel binding).
func SealExtMarker(user UserKey, serverPub *ecdh.PublicKey, now time.Time) (payload, ephPub []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(extAuthKey(shared))
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ephPub = eph.PublicKey().Bytes()
	plain := make([]byte, 0, 16+8)
	plain = append(plain, user[:]...)
	plain = binary.BigEndian.AppendUint64(plain, uint64(now.Unix()))
	sealed := gcm.Seal(nil, ephPub[:12], plain, []byte(hkdfExtSalt))
	payload = make([]byte, 0, ExtDataSize)
	payload = append(payload, ephPub...)
	payload = append(payload, sealed...)
	return payload, ephPub, nil
}

// OpenExtMarker reverses SealExtMarker. Any failure (wrong sizes, unknown
// key, stale timestamp, AEAD mismatch) must be treated identically by the
// caller: relay the connection to the decoy.
func OpenExtMarker(payload []byte, staticPriv *ecdh.PrivateKey, now time.Time) (UserKey, []byte, error) {
	var user UserKey
	if len(payload) != ExtDataSize {
		return user, nil, fmt.Errorf("p67: ext payload %d bytes", len(payload))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(payload[:extEphSize])
	if err != nil {
		return user, nil, err
	}
	shared, err := staticPriv.ECDH(ephPub)
	if err != nil {
		return user, nil, err
	}
	block, err := aes.NewCipher(extAuthKey(shared))
	if err != nil {
		return user, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return user, nil, err
	}
	plain, err := gcm.Open(nil, payload[:12], payload[extEphSize:], []byte(hkdfExtSalt))
	if err != nil {
		return user, nil, err
	}
	if len(plain) != 24 {
		return user, nil, errors.New("p67: ext plaintext size")
	}
	ts := int64(binary.BigEndian.Uint64(plain[16:24]))
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(TimeSkew.Seconds()) {
		return user, nil, errors.New("p67: marker timestamp stale")
	}
	copy(user[:], plain[:16])
	return user, payload[:extEphSize], nil
}

// Session-ID marker ("hide=sid", the default and most elegant carrier):
// the marker rides the 32-byte legacy_session_id, which every TLS 1.3
// client fills with random bytes for middlebox compatibility. The marker's
// ephemeral key is the classic X25519 half of the handshake's own key share
// (a plain X25519 share, or the tail of an X25519MLKEM768 hybrid share that
// modern browsers send), so the ClientHello carries zero non-browser bytes.
//
// Wire form (byte-exact REALITY parity): AES-256-GCM over
// userID[12] || ts[4], with the key derived from the per-connection ECDH
// (HKDF), the nonce taken from ClientHello.Random[20:32], and the ENTIRE
// ClientHello (with the session-id slot zeroed) as AAD — so a sealed marker
// cannot be transplanted into a different hello. 20 + 16 tag = 32 bytes.
const (
	hkdfSIDSalt = "penis67-sid-v1"
	sidPlainLen = 12 + 4
)

// UserID derives the 12-byte session-ID user identifier from the UUID.
func UserID(user UserKey) []byte {
	out := make([]byte, 12)
	h := hkdf.New(sha256.New, user[:], []byte(hkdfSIDSalt), []byte("uid"))
	if _, err := h.Read(out); err != nil {
		panic("p67: hkdf: " + err.Error())
	}
	return out
}

func sidAuthKey(shared []byte) []byte {
	out := make([]byte, 32)
	h := hkdf.New(sha256.New, shared, []byte(hkdfSIDSalt), []byte("auth"))
	if _, err := h.Read(out); err != nil {
		panic("p67: hkdf: " + err.Error())
	}
	return out
}

// SealSIDMarker builds the 32-byte session-ID marker. clientRandom is the
// hello's Random (nonce source), aad is the full ClientHello with the
// session-id bytes already zeroed.
func SealSIDMarker(user UserKey, ephPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey, now time.Time, clientRandom, aad []byte) ([]byte, error) {
	if len(clientRandom) != 32 {
		return nil, errors.New("p67: client random must be 32 bytes")
	}
	shared, err := ephPriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sidAuthKey(shared))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 0, sidPlainLen)
	plain = append(plain, UserID(user)...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(now.Unix()))
	return gcm.Seal(nil, clientRandom[20:32], plain, aad), nil
}

// OpenSIDMarker reverses SealSIDMarker using the X25519 share extracted from
// the ClientHello key_share extension. userID is the 12-byte identifier the
// server compares against its user table. clientRandom and aad must be the
// same hello bytes the client sealed against (sid slot zeroed in aad).
func OpenSIDMarker(sessionID, ephPub []byte, staticPriv *ecdh.PrivateKey, now time.Time, clientRandom, aad []byte) (userID []byte, err error) {
	if len(sessionID) != 32 || len(ephPub) != 32 || len(clientRandom) != 32 {
		return nil, errors.New("p67: bad sid marker geometry")
	}
	pub, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := staticPriv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sidAuthKey(shared))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, clientRandom[20:32], sessionID, aad)
	if err != nil {
		return nil, err
	}
	if len(plain) != sidPlainLen {
		return nil, errors.New("p67: bad sid plaintext")
	}
	ts := int64(binary.BigEndian.Uint32(plain[12:16]))
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(TimeSkew.Seconds()) {
		return nil, errors.New("p67: sid timestamp stale")
	}
	return plain[:12], nil
}

// HelloSIDAAD zeroes the session-id slot inside a serialized ClientHello
// handshake message (handshake header included: sid lives at bytes [39:71])
// and returns the AAD copy plus the client random.
func HelloSIDAAD(helloMsg []byte) (aad, clientRandom []byte, err error) {
	if len(helloMsg) < 4+2+32+1+32 || helloMsg[0] != helloClient {
		return nil, nil, errors.New("p67: hello too short for sid aad")
	}
	if helloMsg[38] != 32 {
		return nil, nil, errors.New("p67: hello session id is not 32 bytes")
	}
	aad = append([]byte(nil), helloMsg...)
	for i := 39; i < 39+32; i++ {
		aad[i] = 0
	}
	return aad, helloMsg[6:38], nil
}

// server presents. Its content is irrelevant to P67 clients (they
// authenticate through the ECDH marker and the HMAC challenge), but it
// mirrors the decoy name for plausibility.
// GenerateCert mints the ephemeral self-signed certificate the terminating
// server presents. Its content is irrelevant to P67 clients (they
// authenticate through the ECDH marker and the HMAC challenge), but it
// mirrors the decoy name for plausibility.
func GenerateCert(sni string) (*ecdsa.PrivateKey, []byte, error) {
	// ECDSA P-256: the most common server key type on the web.
	certPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	host := sni
	if host == "" {
		host = "localhost"
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, certPriv.Public(), certPriv)
	if err != nil {
		return nil, nil, err
	}
	return certPriv, der, nil
}
