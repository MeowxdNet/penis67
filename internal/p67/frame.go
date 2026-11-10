// Mux framing for the post-auth session. One TLS record stream carries
// every TCP flow and UDP association:
//
//	stream u32 | flag u8 | length u16 | payload (all big endian)
//
// stream 0 carries session-level frames (ping/pong/pad); streams 1.. are
// client-allocated, increasing, and never reused.
package p67

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// Frame flags.
const (
	FlagData    uint8 = 0x00 // stream payload chunk / one UDP datagram
	FlagOpenTCP uint8 = 0x01 // payload: target address
	FlagOpenUDP uint8 = 0x02 // payload: target address
	FlagFin     uint8 = 0x03 // half-close: payload delivered, then EOF
	FlagRst     uint8 = 0x04 // kill stream, payload dropped
	FlagPing    uint8 = 0x05 // keepalive probe, payload is random
	FlagPong    uint8 = 0x06 // keepalive answer
	FlagPad     uint8 = 0x07 // padding, ignored by the receiver
	FlagWindow  uint8 = 0x09 // flow-control credit refill, payload: u32 BE bytes
)

// MaxFramePayload bounds one frame's payload; writers chunk above it.
const MaxFramePayload = 16384

// StreamZero is the session-control pseudo-stream.
const StreamZero uint32 = 0

// Frame is one decoded mux frame.
type Frame struct {
	Stream  uint32
	Flag    uint8
	Payload []byte
}

// EncodeFrame appends the wire form of f to dst.
func EncodeFrame(dst []byte, f Frame) []byte {
	var head [7]byte
	binary.BigEndian.PutUint32(head[0:4], f.Stream)
	head[4] = f.Flag
	binary.BigEndian.PutUint16(head[5:7], uint16(len(f.Payload)))
	dst = append(dst, head[:]...)
	return append(dst, f.Payload...)
}

// frameHeaderSize is the fixed frame prefix length.
const frameHeaderSize = 7

// errFrameTooLarge rejects oversized length prefixes.
var errFrameTooLarge = errors.New("p67: frame payload too large")

// ReadFrame reads exactly one frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var head [frameHeaderSize]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Frame{}, err
	}
	length := int(binary.BigEndian.Uint16(head[5:7]))
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{
		Stream:  binary.BigEndian.Uint32(head[0:4]),
		Flag:    head[4],
		Payload: payload,
	}, nil
}

// Target address encoding inside OPEN payloads (SOCKS/VLESS style):
// atype(1) | body | port u16, where atype is 0x01 IPv4, 0x03 domain,
// 0x04 IPv6.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// EncodeTarget appends the encoded host:port to dst.
func EncodeTarget(dst []byte, host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return dst, fmt.Errorf("p67: bad port %d", port)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			raw := ip.As4()
			dst = append(dst, atypIPv4, raw[0], raw[1], raw[2], raw[3], byte(port>>8), byte(port))
			return dst, nil
		}
		raw := ip.As16()
		dst = append(dst, atypIPv6)
		dst = append(dst, raw[:]...)
		dst = append(dst, byte(port>>8), byte(port))
		return dst, nil
	}
	if host == "" || len(host) > 255 {
		return dst, fmt.Errorf("p67: bad host %q", host)
	}
	dst = append(dst, atypDomain, byte(len(host)))
	dst = append(dst, host...)
	dst = append(dst, byte(port>>8), byte(port))
	return dst, nil
}

// DecodeTarget parses an OPEN payload.
func DecodeTarget(payload []byte) (host string, port int, err error) {
	if len(payload) < 1+1+2 {
		return "", 0, errors.New("p67: target truncated")
	}
	switch payload[0] {
	case atypIPv4:
		if len(payload) != 4+1+2 {
			return "", 0, errors.New("p67: bad ipv4 target")
		}
		host = net.IP(payload[1:5]).String()
	case atypDomain:
		nameLen := int(payload[1])
		if len(payload) != 1+1+nameLen+2 {
			return "", 0, errors.New("p67: bad domain target")
		}
		host = string(payload[2 : 2+nameLen])
	case atypIPv6:
		if len(payload) != 16+1+2 {
			return "", 0, errors.New("p67: bad ipv6 target")
		}
		host = net.IP(payload[1:17]).String()
	default:
		return "", 0, fmt.Errorf("p67: bad atype 0x%02x", payload[0])
	}
	port = int(payload[len(payload)-2])<<8 | int(payload[len(payload)-1])
	return host, port, nil
}

// splitHostPort wraps net.SplitHostPort with a port sanity check.
func splitHostPort(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("p67: bad port %q", portText)
	}
	return host, port, nil
}
