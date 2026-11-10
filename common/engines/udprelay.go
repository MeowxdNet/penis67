package engines

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// udpRelay is the datagram side of one UDP ASSOCIATE session: it strips the
// SOCKS5 UDP header on the way in, forwards the payload through the engine's
// per-destination packet path and stamps the header back on the way out.
type udpRelay struct {
	socket  *net.UDPConn
	engine  Engine
	targets sync.Map // "host:port" -> *udpTarget
	once    sync.Once

	clientMu sync.Mutex
	client   *net.UDPAddr
}

type udpTarget struct {
	conn net.PacketConn
	dst  string // original destination, for the reply header
}

func newUDPRelay(engine Engine) (*udpRelay, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &udpRelay{socket: socket, engine: engine}, nil
}

func (r *udpRelay) close() {
	r.once.Do(func() {
		_ = r.socket.Close()
		r.targets.Range(func(_, value any) bool {
			_ = value.(*udpTarget).conn.Close()
			return true
		})
	})
}

// serve pumps datagrams between the SOCKS5 client and the engine until the
// association closes. It also remembers the client's source address so the
// inbound path can reply to the very socket that opened the association.
func (r *udpRelay) serve() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := r.socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.clientMu.Lock()
		r.client = from
		r.clientMu.Unlock()
		if n <= 3 {
			continue
		}
		payload, destination, err := splitUDPHeader(buf[:n])
		if err != nil || payload == nil {
			continue
		}
		go r.forward(payload, destination)
	}
}

func (r *udpRelay) forward(payload []byte, destination string) {
	target := r.target(destination)
	if target == nil {
		return
	}
	_ = target.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = target.conn.WriteTo(payload, mustUDPAddr(destination))
}

func (r *udpRelay) target(destination string) *udpTarget {
	if existing, ok := r.targets.Load(destination); ok {
		return existing.(*udpTarget)
	}
	conn, err := r.engine.PacketConn(context.Background(), destination)
	if err != nil {
		return nil
	}
	target := &udpTarget{conn: conn, dst: destination}
	actual, loaded := r.targets.LoadOrStore(destination, target)
	if loaded {
		_ = conn.Close()
		return actual.(*udpTarget)
	}
	go r.receive(target)
	return target
}

// receive loops a target's inbound datagrams back to the SOCKS5 client with
// the SOCKS5 UDP header restored.
func (r *udpRelay) receive(target *udpTarget) {
	// Idle expiry keeps the NAT table small; the next packet re-dials.
	_ = target.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	buf := make([]byte, 64*1024)
	for {
		n, _, err := target.conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if loaded, ok := r.targets.LoadAndDelete(target.dst); ok && loaded.(*udpTarget) == target {
					_ = target.conn.Close()
				}
				return
			}
			if loaded, ok := r.targets.Load(target.dst); ok && loaded.(*udpTarget) == target {
				r.targets.Delete(target.dst)
			}
			_ = target.conn.Close()
			return
		}
		_ = target.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		r.clientMu.Lock()
		client := r.client
		r.clientMu.Unlock()
		if client == nil {
			continue
		}
		packet := appendUDPHeader(make([]byte, 0, 22+len(payloadClip(buf[:n]))), target.dst, buf[:n])
		_, _ = r.socket.WriteToUDP(packet, client)
	}
}

// payloadClip exists only to size the reply buffer; the slice is not copied.
func payloadClip(b []byte) []byte { return b }

func mustUDPAddr(destination string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		return &net.UDPAddr{}
	}
	return addr
}

// splitUDPHeader parses the SOCKS5 UDP request header (RFC 1928 §7).
func splitUDPHeader(packet []byte) (payload []byte, destination string, err error) {
	if len(packet) < 4 || packet[1] != 0 {
		return nil, "", errors.New("bad udp header")
	}
	if packet[2] != 0 { // fragments unsupported
		return nil, "", errors.New("fragmented udp")
	}
	var host string
	var offset int
	switch packet[3] {
	case 0x01:
		if len(packet) < 4+4+2 {
			return nil, "", errors.New("short ipv4 udp")
		}
		host = net.IP(packet[4 : 4+4]).String()
		offset = 4 + 4
	case 0x03:
		length := int(packet[4])
		if len(packet) < 5+length+2 {
			return nil, "", errors.New("short domain udp")
		}
		host = string(packet[5 : 5+length])
		offset = 5 + length
	case 0x04:
		if len(packet) < 4+16+2 {
			return nil, "", errors.New("short ipv6 udp")
		}
		host = net.IP(packet[4 : 4+16]).String()
		offset = 4 + 16
	default:
		return nil, "", errors.New("bad udp atyp")
	}
	port := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	return packet[offset+2:], net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// appendUDPHeader prepends the SOCKS5 UDP reply header to a datagram.
func appendUDPHeader(dst []byte, source string, payload []byte) []byte {
	host, portText, err := net.SplitHostPort(source)
	if err != nil {
		return dst
	}
	port, _ := strconv.Atoi(portText)
	ip := net.ParseIP(host)
	out := append(dst, 0, 0, 0)
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else if ip != nil {
		out = append(out, 0x04)
		out = append(out, ip.To16()...)
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	out = append(out, portBytes[:]...)
	return append(out, payload...)
}
