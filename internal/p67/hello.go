// Server-side ClientHello inspection: reads exactly the first flight off a
// raw TCP connection, parses the handshake message, and extracts the P67
// authentication extension without disturbing the bytes, so the same bytes
// can be replayed either into the local TLS stack (authorized) or to the
// decoy site (everyone else).
package p67

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	recordHandshake = 0x16
	helloClient     = 0x01
	maxHelloBytes   = 1 << 16
)

// ClientHello is the minimal parsed view the server needs.
type ClientHello struct {
	Raw       []byte // the full first flight (record framing included)
	HelloMsg  []byte // the handshake message (4-byte header included)
	Random    []byte
	SessionID []byte
	SNI       string
	ExtAuth   []byte // P67 marker payload from the 0x2F47 extension, nil when absent
	// KeyShareX25519 is the classic X25519 public key half of the hello's
	// key_share: either a plain X25519 entry, or the 32-byte tail of an
	// X25519MLKEM768 hybrid share (RFC 9370 orders it mlkem||x25519).
	KeyShareX25519 []byte
	// ExtTypes lists every extension type in arrival order (tests and
	// camouflage audits).
	ExtTypes []uint16
}

// Key share group identifiers (TLS Supported Groups registry).
const (
	groupX25519       = 0x001d
	groupX25519MLKEM7 = 0x11ec
)

// ReadClientHello consumes exactly the ClientHello flight from conn and
// returns both the buffered raw bytes and the parsed view.
func ReadClientHello(conn net.Conn) (*ClientHello, []byte, error) {
	buffered := make([]byte, 0, 1024)
	// Assemble the complete handshake message across (rare) record splits.
	var message []byte
	for {
		if len(buffered) > maxHelloBytes {
			return nil, nil, errors.New("p67: client hello too large")
		}
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, nil, fmt.Errorf("p67: read record header: %w", err)
		}
		buffered = append(buffered, header...)
		if header[0] != recordHandshake {
			return nil, nil, fmt.Errorf("p67: first record type 0x%02x, not handshake", header[0])
		}
		length := int(header[3])<<8 | int(header[4])
		if length == 0 || length > maxHelloBytes {
			return nil, nil, fmt.Errorf("p67: bad record length %d", length)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, nil, fmt.Errorf("p67: read record body: %w", err)
		}
		buffered = append(buffered, body...)
		message = append(message, body...)
		if len(message) < 4 {
			continue
		}
		total := 4 + (int(message[1])<<16 | int(message[2])<<8 | int(message[3]))
		if total > maxHelloBytes {
			return nil, nil, errors.New("p67: handshake message too large")
		}
		if len(message) >= total {
			message = message[:total]
			break
		}
	}
	hello, err := parseClientHello(message)
	if err != nil {
		return nil, nil, err
	}
	hello.Raw = buffered
	hello.HelloMsg = message
	return hello, buffered, nil
}

func parseClientHello(msg []byte) (*ClientHello, error) {
	if len(msg) < 4 || msg[0] != helloClient {
		return nil, errors.New("p67: not a ClientHello")
	}
	body := msg[4:]
	if len(body) < 2+32+1 {
		return nil, errors.New("p67: hello truncated (fixed fields)")
	}
	hello := &ClientHello{}
	pos := 0
	pos += 2 // legacy_version
	hello.Random = body[pos : pos+32]
	pos += 32
	sessionLen := int(body[pos])
	pos++
	if sessionLen > 32 || pos+sessionLen > len(body) {
		return nil, errors.New("p67: bad session id")
	}
	hello.SessionID = body[pos : pos+sessionLen]
	pos += sessionLen
	skipLen := func(width int) (int, error) {
		if pos+width > len(body) {
			return 0, errors.New("p67: hello truncated (vector length)")
		}
		var n int
		switch width {
		case 1:
			n = int(body[pos])
		case 2:
			n = int(body[pos])<<8 | int(body[pos+1])
		}
		pos += width
		if pos+n > len(body) {
			return 0, errors.New("p67: hello truncated (vector body)")
		}
		out := n
		pos += n
		return out, nil
	}
	if _, err := skipLen(2); err != nil { // cipher suites
		return nil, err
	}
	if _, err := skipLen(1); err != nil { // compression
		return nil, err
	}
	if pos+2 > len(body) {
		return nil, errors.New("p67: no extensions")
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+extTotal > len(body) {
		return nil, errors.New("p67: truncated extensions")
	}
	extensions := body[pos : pos+extTotal]
	for e := 0; e+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[e : e+2])
		extLen := int(binary.BigEndian.Uint16(extensions[e+2 : e+4]))
		e += 4
		if e+extLen > len(extensions) {
			break
		}
		data := extensions[e : e+extLen]
		hello.ExtTypes = append(hello.ExtTypes, extType)
		switch extType {
		case ExtType:
			hello.ExtAuth = data
		case 0x0000: // server_name
			hello.SNI = parseSNI(data)
		case 0x0033: // key_share
			hello.KeyShareX25519 = parseKeyShareX25519(data)
		}
		e += extLen
	}
	return hello, nil
}

// parseSNI pulls the first dns_name out of a server_name extension.
func parseSNI(data []byte) string {
	// ServerNameList: vec16 of (type(1), host_name vec16).
	if len(data) < 5 || data[0] != 0x00 {
		return ""
	}
	nameLen := int(data[1])<<8 | int(data[2])
	if 3+nameLen > len(data) {
		return ""
	}
	return string(data[3 : 3+nameLen])
}

// parseKeyShareX25519 walks a client key_share extension and returns the
// classic X25519 public key: a plain x25519 entry verbatim, or the 32-byte
// tail of an X25519MLKEM768 hybrid share.
func parseKeyShareX25519(data []byte) []byte {
	// KeyShareClientHello: client_shares vec16 of (group(2), key_exchange vec16).
	if len(data) < 2 {
		return nil
	}
	total := int(data[0])<<8 | int(data[1])
	pos := 2
	end := 2 + total
	if end > len(data) {
		end = len(data)
	}
	for pos+4 <= end {
		group := int(data[pos])<<8 | int(data[pos+1])
		keyLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if pos+keyLen > end {
			return nil
		}
		key := data[pos : pos+keyLen]
		switch group {
		case groupX25519:
			if keyLen == 32 {
				return key
			}
		case groupX25519MLKEM7:
			if keyLen >= 32 {
				return key[keyLen-32:] // mlkem768 (1184) || x25519 (32)
			}
		}
		pos += keyLen
	}
	return nil
}

// replayConn re-serves the already-read bytes before switching to the live
// connection. Everything the server does next — terminating TLS or relaying
// to the decoy — must start from these bytes.
type replayConn struct {
	net.Conn
	pending []byte
	pos     int
}

func newReplayConn(conn net.Conn, buffered []byte) *replayConn {
	return &replayConn{Conn: conn, pending: buffered}
}

func (r *replayConn) Read(b []byte) (int, error) {
	if r.pos < len(r.pending) {
		n := copy(b, r.pending[r.pos:])
		r.pos += n
		return n, nil
	}
	return r.Conn.Read(b)
}
