package p67

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestMuxCreditRepro is the deterministic core of the big-transfer test:
// two sessions over a TCP socketpair, echo handler, 128 KiB of
// data (small variant; net.Pipe is deliberately avoided).

func TestMuxCreditRepro(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type result struct {
		client net.Conn
		server net.Conn
	}
	pair := make(chan result, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			return
		}
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			_ = server.Close()
			return
		}
		pair <- result{client, server}
	}()
	clientSide, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	gotPair := <-pair
	clientConn, serverConn := clientSide, gotPair.server
	defer clientConn.Close()
	defer serverConn.Close()

	payload := make([]byte, 768*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	server := newSession(StreamConfig{
		Conn: serverConn,
		Pad:  PadOff,
		Log:  func(string) {},
		ServeStream: func(st *Stream, host string, port int, isUDP bool) {
			defer st.Close()
			// Single echo loop: read→write; FIN after the input ends.
			_, _ = io.Copy(st, st)
			_ = st.CloseWrite()
		},
	})
	defer server.Close()

	client := newSession(StreamConfig{Conn: clientConn, Pad: PadOff, Log: func(string) {}})
	defer client.Close()

	stream, err := client.Open("127.0.0.1", 9, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	done := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		done <- err
	}()

	got := make([]byte, len(payload))
	_ = stream.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read: %v (write err: %v)", err, <-done)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not finish")
	}
	if !bytes.Equal(got, payload) {
		t.Error("payload mismatch")
	}
}
