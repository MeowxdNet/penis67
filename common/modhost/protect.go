package modhost

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProtectFunc routes an outbound socket around the VPN tunnel by handing its
// fd to the host's protect service (Android VpnService.protect). On platforms
// without the service it is a no-op. The wire format: connect to the unix
// socket, send 1 byte plus the fd in SCM_RIGHTS, read a 1-byte ack.
type ProtectFunc func(fd int) error

// NoProtect is the identity protection used when no service path exists.
func NoProtect(int) error { return nil }

// NewProtect builds a [ProtectFunc] for the host service at [path]. When the
// path is empty the result is a no-op. Each call dials the service fresh —
// the host closes every accepted connection after one transaction.
func NewProtect(path string) ProtectFunc {
	if path == "" {
		return NoProtect
	}
	return func(fd int) error {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return fmt.Errorf("protect dial: %w", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		rights := unix.UnixRights(fd)
		if _, _, err := conn.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
			return fmt.Errorf("protect send: %w", err)
		}
		ack := make([]byte, 1)
		if _, err := io.ReadFull(conn, ack); err != nil {
			return fmt.Errorf("protect ack: %w", err)
		}
		if ack[0] != 1 {
			return errors.New("protect: host refused the socket")
		}
		return nil
	}
}

// Dialer is a net dialer whose sockets are protected from the VPN tunnel.
type Dialer struct {
	Protect ProtectFunc
	// Resolver resolves names; when nil the system resolver is used. Modules
	// must not resolve through the tunnel, so engines hand in the host's
	// physical-network resolver (see ProtectedResolver).
	Resolver *net.Resolver
}

// NewDialer builds a protected dialer. [protect] may be [NoProtect].
func NewDialer(protect ProtectFunc) *Dialer {
	if protect == nil {
		protect = NoProtect
	}
	return &Dialer{Protect: protect}
}

func (d *Dialer) control(network, address string, raw syscall.RawConn) error {
	return raw.Control(func(fd uintptr) {
		if err := d.Protect(int(fd)); err != nil {
			// A failed protect must not leave a loop-bound socket.
			_ = syscall.Shutdown(int(fd), syscall.SHUT_RDWR)
		}
	})
}

// DialContext dials a protected TCP connection.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := &net.Dialer{Control: d.control, Resolver: d.Resolver}
	return nd.DialContext(ctx, network, address)
}

// ListenUDP opens a protected UDP socket bound to an ephemeral port.
func (d *Dialer) ListenUDP(ctx context.Context) (*net.UDPConn, error) {
	lc := &net.ListenConfig{Control: d.control}
	pc, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ListenUDPPort opens a protected UDP socket on a fixed port.
func (d *Dialer) ListenUDPPort(ctx context.Context, port int) (*net.UDPConn, error) {
	lc := &net.ListenConfig{Control: d.control}
	pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort("0.0.0.0", fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ProtectedResolver builds a resolver that queries [servers] through
// protected sockets. An empty list yields nil (the system resolver).
func ProtectedResolver(protect ProtectFunc, servers []string) *net.Resolver {
	if protect == nil || len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var lastErr error
			for _, server := range servers {
				var conn net.Conn
				var err error
				switch network {
				case "tcp", "tcp4", "tcp6":
					d := &Dialer{Protect: protect}
					conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(server, "53"))
				default:
					conn, err = dialResolverUDP(ctx, protect, server)
				}
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("no resolver reachable: %w", lastErr)
		},
	}
}

// dialResolverUDP opens a connected UDP socket suitable for the resolver's
// Dial (the std resolver moves whole DNS datagrams over Read/Write).
func dialResolverUDP(ctx context.Context, protect ProtectFunc, server string) (net.Conn, error) {
	d := &Dialer{Protect: protect}
	pc, err := d.ListenUDP(ctx)
	if err != nil {
		return nil, err
	}
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, "53"))
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &udpConn{UDPConn: pc, peer: target}, nil
}

// udpConn adapts an unconnected UDP socket to a connected net.Conn by
// stamping the peer on every Write and accepting only the peer on Read.
type udpConn struct {
	*net.UDPConn
	peer *net.UDPAddr
}

func (c *udpConn) Write(b []byte) (int, error) { return c.UDPConn.WriteToUDP(b, c.peer) }

func (c *udpConn) Read(b []byte) (int, error) {
	for {
		n, from, err := c.UDPConn.ReadFromUDP(b)
		if err != nil {
			return 0, err
		}
		if from.IP.Equal(c.peer.IP) && from.Port == c.peer.Port {
			return n, nil
		}
	}
}

// TempDir returns a private temp dir under [base]; the host already points
// TMPDIR at an ephemeral per-run directory, this only adds a subfolder.
func TempDir(base string) string {
	dir := filepath.Join(base, "tmp")
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// TLSConfig is a baseline TLS config for engines that need one. Name
// resolution happens through the protected dialer, not this config.
func (d *Dialer) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
