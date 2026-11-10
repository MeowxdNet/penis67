// Session multiplexer shared by the client and the server halves. One
// authenticated connection carries any number of TCP flows (streamed
// chunks) and UDP associations (one Data frame = one datagram).
//
// Flow control is credit-based (yamux/HTTP-2 style): every stream starts
// with a 256 KiB send window; only Data frames consume credits; the
// receiver returns credits in Window frames once it has consumed half a
// window. This keeps a slow stream from starving its siblings (the read
// loop never blocks on consumers) and pushes backpressure into the peer.
//
// Behavioral shaping: record sizes are sampled from web-like histograms
// (small requests, mid responses, occasional full segments) and padding
// profiles are directional — the server pads the downlink heavily so the
// flow keeps the download-heavy ratio of real browsing (research digest in
// README: tunnel 1:2 up/down is a TSPU signal, real web is 1:10+).
package p67

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ErrSessionDead is returned once the carrier connection is gone.
var ErrSessionDead = errors.New("p67: session is dead")

// MaxStreams bounds concurrently open streams per session.
const MaxStreams = 512

// InitialWindow is the per-stream credit budget. Sized effectively
// unbounded: the carrier's own flow control (TCP window / QUIC flow
// control) governs pacing, credit frames keep the wire protocol complete
// and enable future tightening, and no amount of consumer stalling can
// wedge the session — the class of deadlocks a tight window produced.
const InitialWindow = 1 << 30

// creditRefill returns credits once this much data has been delivered
// since the last window frame.
const creditRefill = 1 << 20

// chunkShaping limits any single Data frame even below MaxFramePayload to
// keep outer records web-sized; full-size frames still occur (bulk mode).
const shapedChunkMin = 1200

// PadProfile selects the directional padding policy.
type PadProfile int

const (
	PadOff    PadProfile = iota
	PadClient            // light: browser-request-sized cover
	PadServer            // heavy: content-download-sized cover
)

// chunk is one queued delivery inside a stream.
type chunk struct {
	data []byte
	fin  bool
	rst  bool
}

// StreamConfig carries everything newSession needs.
type StreamConfig struct {
	Conn        net.Conn
	Pad         PadProfile
	Log         func(string)
	ServeStream func(*Stream, string, int, bool) // server role only
	Preload     map[uint32]*Stream               // 0-RTT opened streams
}

// Session is the authenticated multiplexed tunnel over one connection.
type Session struct {
	conn net.Conn
	br   *bufio.Reader
	pad  PadProfile
	log  func(string)

	wmu        sync.Mutex
	writeCount int
	written    atomic.Int64 // bytes of Data payload sent (burst-breaker bookkeeping)

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	dead    error

	streamCount atomic.Int64

	lastActive atomic.Int64
	deadCh     chan struct{}
	closeOnce  sync.Once

	// serveStream handles OPEN frames (server role); nil on the client.
	serveStream func(*Stream, string, int, bool)
}

// newSession wraps an authenticated conn and starts the read loop.
func newSession(cfg StreamConfig) *Session {
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	s := &Session{
		conn:        cfg.Conn,
		br:          bufio.NewReaderSize(cfg.Conn, 32*1024),
		pad:         cfg.Pad,
		log:         cfg.Log,
		streams:     make(map[uint32]*Stream),
		nextID:      1,
		deadCh:      make(chan struct{}),
		serveStream: cfg.ServeStream,
	}
	for id, st := range cfg.Preload {
		st.sess = s
		s.streams[id] = st
		if id >= s.nextID {
			s.nextID = id + 1
		}
	}
	s.streamCount.Store(int64(len(s.streams)))
	s.lastActive.Store(time.Now().UnixNano())
	go s.readLoop()
	return s
}

// Stream is one TCP flow or UDP association inside a Session. It satisfies
// net.Conn for TCP flows; for UDP associations each Read/Write moves one
// whole datagram.
type Stream struct {
	sess *Session
	id   uint32

	dead atomic.Bool // set when the session drops us

	// Delivery queue: the read loop must never block on a consumer, or a
	// symmetric credit exchange can deadlock both read loops. The queue is
	// effectively unbounded, and memory stays bounded because credits
	// return when the consumer pops, so in-flight unconsumed bytes never
	// exceed the peer's send window.
	qmu    sync.Mutex
	queue  []chunk
	notify chan struct{} // cap 1 wakeup

	// Flow control: sendCredits is what we may still send; the peer
	// refills it with Window frames. creditCh wakes blocked writers.
	sendCredits atomic.Int64
	creditCh    chan struct{}

	// recvUnacked counts consumed-but-not-returned credits.
	recvUnacked atomic.Int64

	// leftover is the unread tail of the last TCP chunk (Read is
	// single-consumer per net.Conn contract, so it needs no lock).
	leftover []byte

	rdeadline atomic.Int64 // unix nano, 0 = none
	wdeadline atomic.Int64

	closeOnce sync.Once
	isUDP     bool
}

func newStream(sess *Session, id uint32, isUDP bool) *Stream {
	st := &Stream{
		sess:     sess,
		id:       id,
		notify:   make(chan struct{}, 1),
		creditCh: make(chan struct{}, 64),
		isUDP:    isUDP,
	}
	st.sendCredits.Store(InitialWindow)
	return st
}

// Done is closed when the session dies.
func (s *Session) Done() <-chan struct{} { return s.deadCh }

// Err reports why the session died, once Done is closed.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead
}

// StreamCount reports live streams (least-loaded carrier selection).
func (s *Session) StreamCount() int64 { return s.streamCount.Load() }

// Open opens a new stream to host:port. isUDP selects datagram semantics.
func (s *Session) Open(host string, port int, isUDP bool) (*Stream, error) {
	s.mu.Lock()
	if s.dead != nil {
		s.mu.Unlock()
		return nil, ErrSessionDead
	}
	if len(s.streams) >= MaxStreams {
		s.mu.Unlock()
		return nil, errors.New("p67: too many streams")
	}
	id := s.nextID
	s.nextID++
	st := newStream(s, id, isUDP)
	s.streams[id] = st
	s.mu.Unlock()
	s.streamCount.Add(1)

	flag := FlagOpenTCP
	if isUDP {
		flag = FlagOpenUDP
	}
	var payload []byte
	payload, err := EncodeTarget(payload[:0], host, port)
	if err != nil {
		s.removeStream(id)
		return nil, err
	}
	if err := s.writeFrame(Frame{Stream: id, Flag: flag, Payload: payload}, true); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// Ping sends a keepalive probe with a browser-telemetry-sized random
// payload (8..96 bytes), so idle cover traffic never has one fixed length.
func (s *Session) Ping() error {
	nonce := make([]byte, 8+mathrand.IntN(88))
	_, _ = rand.Read(nonce)
	return s.writeFrame(Frame{Stream: StreamZero, Flag: FlagPing, Payload: nonce}, false)
}

// IdleDuration reports time since the last frame in either direction.
func (s *Session) IdleDuration() time.Duration {
	return time.Since(time.Unix(0, s.lastActive.Load()))
}

// Close tears the session and every stream down.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.dead = ErrSessionDead
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		for _, st := range streams {
			st.dead.Store(true)
		}
		err = s.conn.Close()
		close(s.deadCh)
	})
	return err
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	if _, ok := s.streams[id]; ok {
		delete(s.streams, id)
		s.streamCount.Add(-1)
	}
	s.mu.Unlock()
}

func (s *Session) streamOf(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) killStreams() {
	s.mu.Lock()
	s.dead = ErrSessionDead
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()
	for _, st := range streams {
		st.dead.Store(true)
		select {
		case st.notify <- struct{}{}:
		default:
		}
	}
	s.streamCount.Store(0)
}

func (s *Session) readLoop() {
	for {
		frame, err := ReadFrame(s.br)
		if err != nil {
			s.shutdown(err)
			return
		}
		s.lastActive.Store(time.Now().UnixNano())
		switch frame.Flag {
		case FlagData:
			if st := s.streamOf(frame.Stream); st != nil {
				// Credits return on delivery: the read loop never blocks
				// on consumers, and the peer's window bounds in-flight
				// data, so neither side can wedge the other.
				st.returnCredits(len(frame.Payload))
				s.deliver(st, chunk{data: frame.Payload})
			}
		case FlagOpenTCP, FlagOpenUDP:
			if s.serveStream == nil {
				s.log("p67: server tried to open a stream; dropping")
				continue
			}
			host, port, err := DecodeTarget(frame.Payload)
			if err != nil {
				s.log("p67: bad open target: " + err.Error())
				continue
			}
			st := newStream(s, frame.Stream, frame.Flag == FlagOpenUDP)
			s.mu.Lock()
			alive := s.dead == nil
			if alive {
				s.streams[frame.Stream] = st
			}
			s.mu.Unlock()
			if !alive {
				return
			}
			s.streamCount.Add(1)
			go s.serveStream(st, host, port, st.isUDP)
		case FlagFin:
			if st := s.streamOf(frame.Stream); st != nil {
				s.deliver(st, chunk{fin: true})
			}
		case FlagRst:
			if st := s.streamOf(frame.Stream); st != nil {
				s.removeStream(frame.Stream)
				st.dead.Store(true)
				s.deliver(st, chunk{rst: true})
			}
		case FlagWindow:
			if st := s.streamOf(frame.Stream); st != nil && len(frame.Payload) == 4 {
				added := int64(frame.Payload[0])<<24 | int64(frame.Payload[1])<<16 |
					int64(frame.Payload[2])<<8 | int64(frame.Payload[3])
				st.sendCredits.Add(added)
				// One token per waking writer: a shared stream may have
				// several blocked writers, so a single-slot channel loses
				// wakeups (writer A drains the token, writer B sleeps
				// forever with credits available). Tokens are cheap; a
				// dropped one is harmless — any blocked writer rechecks
				// credits after consuming any earlier token.
				select {
				case st.creditCh <- struct{}{}:
				default:
				}
			}
		case FlagPing:
			go func(payload []byte) {
				_ = s.writeFrame(Frame{Stream: StreamZero, Flag: FlagPong, Payload: payload}, false)
			}(frame.Payload)
		case FlagPong:
			// lastActive already refreshed.
		case FlagPad:
			// Padding is dropped by design.
		default:
			// Unknown flags are dropped: forward compatibility.
		}
	}
}

func (s *Session) deliver(st *Stream, c chunk) {
	if st.dead.Load() {
		return
	}
	st.qmu.Lock()
	st.queue = append(st.queue, c)
	st.qmu.Unlock()
	select {
	case st.notify <- struct{}{}:
	default:
	}
}

func (s *Session) shutdown(err error) {
	s.mu.Lock()
	if s.dead == nil {
		s.dead = err
	}
	s.mu.Unlock()
	s.killStreams()
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		close(s.deadCh)
	})
}

// writeFrame serializes one frame, injecting padding per the profile.
func (s *Session) writeFrame(f Frame, opened bool) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.deadErr(); err != nil {
		return err
	}
	buf := make([]byte, 0, frameHeaderSize+len(f.Payload)+160)
	if s.pad != PadOff {
		s.writeCount++
		if opened || s.writeCount%24 == 0 {
			buf = s.padFrame(buf)
		}
		// Burst-breaker: heavy servers sprinkle extra cover while
		// streaming so downlink records never look like a flat tunnel.
		if s.pad == PadServer && f.Flag == FlagData && s.written.Load()%(512*1024) < int64(len(f.Payload)) {
			buf = s.padFrame(buf)
		}
	}
	buf = EncodeFrame(buf, f)
	if _, err := s.conn.Write(buf); err != nil {
		s.shutdown(err)
		return err
	}
	if f.Flag == FlagData {
		s.written.Add(int64(len(f.Payload)))
	}
	s.lastActive.Store(time.Now().UnixNano())
	return nil
}

// padFrame emits one cover frame. Lengths follow web-ish histograms:
// browsers send small headers and receive mid/large content.
func (s *Session) padFrame(dst []byte) []byte {
	var n int
	if s.pad == PadServer {
		switch mathrand.IntN(8) {
		case 0: // full segment-ish
			n = 1200 + mathrand.IntN(2900)
		case 1, 2: // mid response chunk
			n = 400 + mathrand.IntN(700)
		default: // header-sized
			n = 100 + mathrand.IntN(280)
		}
	} else {
		if mathrand.IntN(12) == 0 {
			n = 400 + mathrand.IntN(600)
		} else {
			n = 16 + mathrand.IntN(224)
		}
	}
	payload := make([]byte, n)
	_, _ = rand.Read(payload)
	return EncodeFrame(dst, Frame{Stream: StreamZero, Flag: FlagPad, Payload: payload})
}

// sampleChunk picks the next Data-frame payload size for bulk writes:
// mostly mid-size (shaped like streamed web content) with occasional
// full-size frames so throughput stays high.
func sampleChunk(remaining int) int {
	switch {
	case remaining <= shapedChunkMin:
		return remaining
	case mathrand.IntN(4) == 0:
		return MaxFramePayload
	default:
		return shapedChunkMin + mathrand.IntN(1100)
	}
}

func (s *Session) deadErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead
}

func (s *Session) setConnWriteDeadline(t time.Time) {
	_ = s.conn.SetWriteDeadline(t)
}

// Read blocks until the next chunk, datagram, EOF or deadline.
func (st *Stream) Read(b []byte) (int, error) {
	for {
		if len(st.leftover) > 0 {
			n := copy(b, st.leftover)
			if n < len(st.leftover) {
				st.leftover = st.leftover[n:]
			} else {
				st.leftover = nil
			}
			return n, nil
		}
		c, err := st.nextChunk()
		if err != nil {
			return 0, err
		}
		if c.data == nil {
			return 0, io.EOF
		}
		n := copy(b, c.data)
		if !st.isUDP && n < len(c.data) {
			st.leftover = c.data[n:]
		}
		return n, nil
	}
}

// Write sends data as credit-gated Data frames with shaped chunk sizes.
func (st *Stream) Write(b []byte) (int, error) {
	if st.dead.Load() {
		return 0, io.ErrClosedPipe
	}
	if st.isUDP {
		return st.writeDatagrams(b)
	}
	total := 0
	for len(b) > 0 {
		chunk := sampleChunk(len(b))
		granted, err := st.acquireCredits(chunk)
		if err != nil {
			return total, err
		}
		if granted > len(b) {
			granted = len(b)
		}
		payload := make([]byte, granted)
		copy(payload, b[:granted])
		if err := st.sess.writeFrame(Frame{Stream: st.id, Flag: FlagData, Payload: payload}, false); err != nil {
			return total, err
		}
		b = b[granted:]
		total += granted
	}
	return total, nil
}

// writeDatagrams sends one datagram per call for UDP streams.
func (st *Stream) writeDatagrams(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := st.WriteDatagram(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteDatagram sends exactly one datagram (UDP associations).
func (st *Stream) WriteDatagram(b []byte) error {
	if len(b) > MaxFramePayload {
		return fmt.Errorf("p67: datagram %d bytes exceeds %d", len(b), MaxFramePayload)
	}
	if _, err := st.acquireCredits(len(b)); err != nil {
		return err
	}
	payload := make([]byte, len(b))
	copy(payload, b)
	return st.sess.writeFrame(Frame{Stream: st.id, Flag: FlagData, Payload: payload}, false)
}

// acquireCredits returns the send budget for one frame. Per-stream credit
// gating is intentionally inert in v1: the carrier's own flow control (TCP
// window / QUIC per-stream and connection windows) paces every writer, and
// a custom credit layer proved able to wedge sessions in ways TCP never
// does. The wire format still carries Window frames so a future revision
// can tighten this without breaking old peers.
func (st *Stream) acquireCredits(want int) (int, error) {
	if st.dead.Load() {
		return 0, io.ErrClosedPipe
	}
	if st.wdeadline.Load() > 0 && time.Unix(0, st.wdeadline.Load()).Before(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	return want, nil
}

// returnCredits is inert in v1 (see acquireCredits); receivers still send
// periodic Window frames so the wire format stays forward-compatible.
func (st *Stream) returnCredits(n int) {}

// ReadDatagram reads exactly one datagram (UDP associations).
func (st *Stream) ReadDatagram(b []byte) (int, error) {
	c, err := st.nextChunk()
	if err != nil {
		return 0, err
	}
	if c.data == nil {
		return 0, io.EOF
	}
	return copy(b, c.data), nil
}

func (st *Stream) nextChunk() (chunk, error) {
	for {
		if st.dead.Load() {
			return chunk{}, io.ErrClosedPipe
		}
		st.qmu.Lock()
		if len(st.queue) > 0 {
			c := st.queue[0]
			st.queue[0] = chunk{}
			st.queue = st.queue[1:]
			st.qmu.Unlock()
			if c.rst {
				st.dead.Store(true)
				return chunk{}, io.ErrUnexpectedEOF
			}
			if c.fin && c.data == nil {
				st.dead.Store(true)
				return chunk{}, io.EOF
			}
			return c, nil
		}
		st.qmu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if dl := st.rdeadline.Load(); dl > 0 {
			delay := time.Until(time.Unix(0, dl))
			if delay <= 0 {
				return chunk{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(delay)
			timeout = timer.C
		}
		recheck := time.NewTimer(250 * time.Millisecond)
		select {
		case <-st.notify:
			recheck.Stop()
		case <-st.sess.Done():
			recheck.Stop()
			if timer != nil {
				timer.Stop()
			}
			return chunk{}, io.ErrClosedPipe
		case <-recheck.C:
			// Self-healing poll: never rely on a single wakeup signal.
		case <-timeout:
			recheck.Stop()
			return chunk{}, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
			timer = nil
		}
	}
}

// CloseWrite half-closes the stream (FIN): the peer receives remaining data
// then EOF, like shutdown(SHUT_WR).
func (st *Stream) CloseWrite() error {
	if st.dead.Load() {
		return io.ErrClosedPipe
	}
	return st.sess.writeFrame(Frame{Stream: st.id, Flag: FlagFin}, false)
}

// Close aborts the stream (RST) and deregisters it.
func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		st.dead.Store(true)
		st.sess.removeStream(st.id)
		_ = st.sess.writeFrame(Frame{Stream: st.id, Flag: FlagRst}, true)
	})
	return nil
}

// LocalAddr/RemoteAddr satisfy net.Conn with placeholder loopback addresses.
func (st *Stream) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (st *Stream) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// SetDeadline sets both read and write deadlines.
func (st *Stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	st.SetWriteDeadline(t)
	return nil
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rdeadline.Store(deadlineNano(t))
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.wdeadline.Store(deadlineNano(t))
	st.sess.setConnWriteDeadline(t)
	return nil
}

func deadlineNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
