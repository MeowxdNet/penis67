// Package engines defines the transport abstraction every protocol engine
// implements, plus the SOCKS5 front the sing-box core dials into.
package engines

import (
	"context"
	"errors"
	"net"
)

// errNoUDP is returned by TCP-only engines when a UDP path is requested.
var errNoUDP = errors.New("engine does not support UDP")

// Engine carries the data plane for one imported link. The SOCKS5 front
// calls DialContext per CONNECT and PacketConn per UDP flow.
//
// Engines must be safe for concurrent use. A dial that fails with a fatal
// engine error should return it directly — the front reports it and the
// caller (the core) retries through the module restart ladder.
type Engine interface {
	// DialContext opens a proxied TCP connection to address ("host:port").
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// SupportsUDP reports whether PacketConn is usable.
	SupportsUDP() bool
	// PacketConn opens a connected UDP path to address. Read/Write move whole
	// datagrams. Implementations may return an error when UDP is unsupported.
	PacketConn(ctx context.Context, address string) (net.PacketConn, error)
	// Close tears the engine down. The process exits right after.
	Close() error
}

// tcpOnlyEngine adapts a pure-TCP dial function into an Engine.
type tcpOnlyEngine struct {
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func TCPOnly(dial func(ctx context.Context, network, address string) (net.Conn, error)) Engine {
	return &tcpOnlyEngine{dial: dial}
}

func (t *tcpOnlyEngine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	return t.dial(ctx, network, address)
}
func (t *tcpOnlyEngine) SupportsUDP() bool                { return false }
func (t *tcpOnlyEngine) PacketConn(context.Context, string) (net.PacketConn, error) {
	return nil, errNoUDP
}
func (t *tcpOnlyEngine) Close() error { return nil }
