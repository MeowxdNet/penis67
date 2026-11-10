package engines

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 constants (RFC 1928).
const (
	socks5Version          = 5
	socks5AuthNone         = 0x00
	socks5AuthUserPass     = 0x02
	socks5AuthNoAcceptable = 0xFF
	socks5CmdConnect       = 0x01
	socks5CmdUDPAssociate  = 0x03
	socks5ReplySuccess     = 0x00
	socks5ReplyGeneralFail = 0x01
	socks5ReplyNotAllowed  = 0x02
	socks5ReplyHostUnreach = 0x04
	socks5ReplyCmdSupport  = 0x07
	socks5ReplyAddrSupport = 0x08
)

// SOCKS5Front serves the module's SOCKS5 endpoint for the sing-box core:
// username/password auth, CONNECT for TCP and UDP ASSOCIATE with a relay
// socket for datagrams. It never exits; the host kills the process instead.
type SOCKS5Front struct {
	listener net.Listener
	engine   Engine
	user     string
	pass     string

	udpMu    sync.Mutex
	udpNext  int
	relays   map[*udpRelay]struct{}
	closing  bool
	logLine  func(string)
}

// NewSOCKS5Front binds 127.0.0.1:port. The listener is protected implicitly
// (loopback never leaves the device).
func NewSOCKS5Front(port int, engine Engine, user, pass string, logLine func(string)) (*SOCKS5Front, error) {
	if logLine == nil {
		logLine = func(string) {}
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	return &SOCKS5Front{
		listener: listener,
		engine:   engine,
		user:     user,
		pass:     pass,
		relays:   make(map[*udpRelay]struct{}),
		logLine:  logLine,
	}, nil
}

// Addr is the bound SOCKS5 address.
func (s *SOCKS5Front) Addr() string { return s.listener.Addr().String() }

// Close stops accepting and tears down every live session.
func (s *SOCKS5Front) Close() error {
	s.udpMu.Lock()
	s.closing = true
	relays := make([]*udpRelay, 0, len(s.relays))
	for relay := range s.relays {
		relays = append(relays, relay)
	}
	s.udpMu.Unlock()
	for _, relay := range relays {
		relay.close()
	}
	return s.listener.Close()
}

// Serve accepts connections until the listener closes.
func (s *SOCKS5Front) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5Front) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != socks5Version {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	offered := map[byte]bool{}
	for _, m := range methods {
		offered[m] = true
	}
	var authRequired = s.user != "" || s.pass != ""
	if authRequired {
		if !offered[socks5AuthUserPass] {
			_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
			return
		}
		if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
			return
		}
		if !s.authenticate(conn) {
			return
		}
	} else {
		if !offered[socks5AuthNone] {
			_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
			return
		}
		if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
			return
		}
	}

	// Request.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != socks5Version {
		return
	}
	host, port, err := readSOCKS5Address(conn, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case socks5CmdConnect:
		s.serveConnect(conn, net.JoinHostPort(host, fmt.Sprint(port)))
	case socks5CmdUDPAssociate:
		s.serveUDPAssociate(conn)
	default:
		s.reply(conn, socks5ReplyCmdSupport, "0.0.0.0", 0)
	}
}

// authenticate runs RFC 1929 username/password auth; every failed attempt
// closes the connection.
func (s *SOCKS5Front) authenticate(conn net.Conn) bool {
	ver := make([]byte, 2) // version, user length
	if _, err := io.ReadFull(conn, ver[:1]); err != nil || ver[0] != 1 {
		return false
	}
	if _, err := io.ReadFull(conn, ver[1:]); err != nil {
		return false
	}
	user := make([]byte, int(ver[1]))
	if len(user) > 0 {
		if _, err := io.ReadFull(conn, user); err != nil {
			return false
		}
	}
	var passLen [1]byte
	if _, err := io.ReadFull(conn, passLen[:]); err != nil {
		return false
	}
	pass := make([]byte, int(passLen[0]))
	if len(pass) > 0 {
		if _, err := io.ReadFull(conn, pass); err != nil {
			return false
		}
	}
	if string(user) == s.user && string(pass) == s.pass {
		_, _ = conn.Write([]byte{1, 0})
		return true
	}
	_, _ = conn.Write([]byte{1, 1})
	return false
}

func (s *SOCKS5Front) serveConnect(conn net.Conn, address string) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	remote, err := s.engine.DialContext(context.Background(), "tcp", address)
	if err != nil {
		s.reply(conn, socks5ReplyGeneralFail, "0.0.0.0", 0)
		s.logLine("connect " + address + ": " + err.Error())
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if err := s.reply(conn, socks5ReplySuccess, "0.0.0.0", 0); err != nil {
		remote.Close()
		return
	}
	relay(conn, remote)
}

func (s *SOCKS5Front) serveUDPAssociate(conn net.Conn) {
	if !s.engine.SupportsUDP() {
		s.reply(conn, socks5ReplyNotAllowed, "0.0.0.0", 0)
		return
	}
	relay, err := newUDPRelay(s.engine)
	if err != nil {
		s.reply(conn, socks5ReplyGeneralFail, "0.0.0.0", 0)
		return
	}
	s.udpMu.Lock()
	if s.closing {
		s.udpMu.Unlock()
		relay.close()
		return
	}
	s.relays[relay] = struct{}{}
	s.udpMu.Unlock()
	defer func() {
		s.udpMu.Lock()
		delete(s.relays, relay)
		s.udpMu.Unlock()
		relay.close()
	}()

	local := relay.socket.LocalAddr().(*net.UDPAddr)
	if err := s.reply(conn, socks5ReplySuccess, "127.0.0.1", local.Port); err != nil {
		return
	}
	// The TCP connection just paces the association's lifetime; the moment it
	// closes the relay goes away. The core never sends data on it.
	go relay.serve()
	_, _ = io.Copy(io.Discard, conn)
}

func (s *SOCKS5Front) reply(conn net.Conn, code byte, host string, port int) error {
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	var addrType byte = 0x01
	var raw []byte
	if v4 := ip.To4(); v4 != nil {
		raw = v4
	} else {
		addrType = 0x04
		raw = ip.To16()
	}
	reply := []byte{socks5Version, code, 0, addrType}
	reply = append(reply, raw...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	reply = append(reply, portBytes[:]...)
	_, err := conn.Write(reply)
	return err
}

// readSOCKS5Address reads the address body following the fixed request head.
func readSOCKS5Address(conn net.Conn, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 0x03: // domain
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	default:
		return "", 0, errors.New("bad atyp")
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBytes[:])), nil
}

// relay copies bytes both ways until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
