package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// consumePreface reads the HTTP/2 connection preface that the daemon sends
// immediately after the 101 (it speaks H2 as the client on an upgraded
// connection). The preface must be forwarded to the CLI — buildx validates
// the peer's connection preface — but also consumed from the byte stream so
// the frame scanner does not mis-parse it. Returns the preface bytes (may be
// nil if nothing was buffered yet).
func consumePreface(r *bufio.Reader) []byte {
	b, err := r.Peek(len(http2.ClientPreface))
	if err == nil && string(b) == http2.ClientPreface {
		_, _ = r.Discard(len(http2.ClientPreface))
		return b
	}
	return nil
}

// serveSession handles an h2c upgrade request to dockerd's /session route.
//
// The connection is spliced raw in both directions (the daemon speaks HTTP/2
// on it, acting as the HTTP/2 client; the buildx client runs its session
// gRPC server on the other side). A frame-level scanner traces the two
// directions so we can rewrite the Dockerfile a buildx client serves to the
// daemon via FileSync/DiffCopy — the same content the client would otherwise
// send us in a Dockerfile upload.
//
// The daemon window-paces the stream, so injected messages larger than the
// negotiated send window are emitted over multiple frames gated on the
// daemon's SETTINGS / WINDOW_UPDATE (see writeMessage). Only the frames of
// the Dockerfile sync are buffered; everything else flows through in real
// time. Any structural surprise fails open to verbatim splicing.
func (p *HTTPProxy) serveSession(clientConn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	backendConn, err := dialUpstream(p.dockerSocket)
	if err != nil {
		log.Printf("[SESSION] failed to connect to docker: %v", err)
		return
	}
	defer backendConn.Close()

	if err := req.Write(backendConn); err != nil {
		log.Printf("[SESSION] failed to forward upgrade request: %v", err)
		return
	}
	if req.Body != nil {
		body, err := io.ReadAll(req.Body) //nolint:errcheck // body is tiny; failure still forwards correctly below
		if err != nil {
			log.Printf("[SESSION] failed to read downstream body: %v", err)
		}
		if len(body) > 0 {
			if _, err := backendConn.Write(body); err != nil {
				log.Printf("[SESSION] failed to write body: %v", err)
				return
			}
		}
	}

	backendReader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendReader, req)
	if err != nil {
		log.Printf("[SESSION] no response from daemon: %v", err)
		return
	}
	// For a 101 the body is the hijacked tunnel (reported as NoBody by
	// ReadResponse), so closing it never touches the connection.
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("[SESSION] daemon refused upgrade: %d", resp.StatusCode)
		_ = resp.Write(clientConn)
		return
	}
	if err := resp.Write(clientConn); err != nil {
		log.Printf("[SESSION] failed to write 101 to client: %v", err)
		return
	}

	// Defensive: some buildx clients send the `PRI * HTTP/2.0` preface in the
	// same write as the upgrade request (before our 101). It must be consumed
	// before the frame scanner starts.
	consumeClientPreface(clientConn, clientReader)

	// The daemon sends its HTTP/2 connection preface right after the 101.
	// Forward it to the CLI (buildx validates the peer preface) and consume it
	// locally so the frame scanner starts at the first real frame.
	if preface := consumePreface(backendReader); len(preface) > 0 {
		log.Printf("[SESSION] forwarding daemon PRI preface")
		if _, err := clientConn.Write(preface); err != nil {
			log.Printf("[SESSION] failed to forward preface: %v", err)
			return
		}
	}

	sp := &sessionSplice{
		p:       p,
		cliConn: clientConn,
		upConn:  backendConn,
		cliR:    clientReader,
		upR:     backendReader,
		snap:    p.snapshot(),
		targets: map[uint32]bool{},
		stat:    map[uint32]*fsutilStat{},
		buf:     map[uint32]*bytes.Buffer{},
	}
	sp.initWindows()
	log.Printf("[SESSION] session established, splicing with Dockerfile rewrite")
	sp.run()
}

// sessionSplice bridges one upgraded connection between a buildx client and
// the Docker daemon, tracing frames to rewrite the DiffCopy-served
// Dockerfile.
type sessionSplice struct {
	p       *HTTPProxy
	cliConn net.Conn
	upConn  net.Conn
	cliR    *bufio.Reader
	upR     *bufio.Reader
	snap    *rewriteSnapshot

	mu      sync.Mutex
	winCond *sync.Cond
	closed  bool
	targets map[uint32]bool
	// stat records the most recent fsutil Stat seen on each target stream, so
	// the following Data message can be recognised as the Dockerfile's.
	stat map[uint32]*fsutilStat
	buf  map[uint32]*bytes.Buffer

	// connWin is our budget for sending data toward the daemon on the whole
	// connection (RFC 7540 connection flow-control window). strmWin is the
	// same budget for the single target stream whose DiffCopy messages we
	// rewrite. Both start at defaultFlowWindow and grow only when the daemon
	// replenishes them via WINDOW_UPDATE / SETTINGS_INITIAL_WINDOW_SIZE; any
	// outbound DATA eats from connWin, and target-stream DATA also eats from
	// strmWin.
	connWin int
	strmWin int
	initWin int // daemon's SETTINGS_INITIAL_WINDOW_SIZE for new target streams
}

// initWindows initialises the send-window accounting. Must be called once
// before splicing; writeMessage and pumpDownstream block on winCond whenever
// connWin/strmWin cannot cover the next frame.
func (sp *sessionSplice) initWindows() {
	sp.winCond = sync.NewCond(&sp.mu)
	sp.connWin = defaultFlowWindow
	sp.initWin = defaultFlowWindow
}

func (sp *sessionSplice) isTarget(sid uint32) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.targets[sid]
}

func (sp *sessionSplice) markTarget(sid uint32) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.targets[sid] = true
	// A fresh stream starts with the daemon's current initial window.
	sp.strmWin = sp.initWin
}

// applyWindowUpdate credits the send budget when the daemon replenishes it.
func (sp *sessionSplice) applyWindowUpdate(sid uint32, inc uint32) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sid == 0 {
		sp.connWin += int(inc)
		sp.winCond.Broadcast()
		return
	}
	if sp.targets[sid] {
		sp.strmWin += int(inc)
		sp.winCond.Broadcast()
	}
}

// applySettings folds a daemon SETTINGS_INITIAL_WINDOW_SIZE change into the
// stream budget (RFC 7540 §6.9.2: all existing streams shift by the delta).
func (sp *sessionSplice) applySettings(payload []byte) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		if id == 0x4 { // SETTINGS_INITIAL_WINDOW_SIZE
			delta := int(val) - sp.initWin
			sp.initWin = int(val)
			sp.strmWin += delta
			sp.winCond.Broadcast()
		}
	}
}

// waitWindow blocks until both send windows can cover n bytes, or until the
// session is closing. Returns whether emission may proceed.
func (sp *sessionSplice) waitWindow(n int) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for sp.connWin < n || sp.strmWin < n {
		if sp.closed {
			return false
		}
		sp.winCond.Wait()
	}
	return !sp.closed
}

// spendWindow decrements the send budget for n bytes emitted toward the
// daemon on sid.
func (sp *sessionSplice) spendWindow(sid uint32, n int) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.connWin -= n
	if sp.targets[sid] {
		sp.strmWin -= n
	}
}

// markClosed wakes any waiter blocked on the send window; the session is
// ending and writeMessage must fail rather than stall.
func (sp *sessionSplice) markClosed() {
	sp.mu.Lock()
	sp.closed = true
	sp.winCond.Broadcast()
	sp.mu.Unlock()
}

// run pumps both directions until either side closes.
func (sp *sessionSplice) run() {
	done := make(chan struct{}, 2)
	go func() {
		sp.pumpUpstream()
		done <- struct{}{}
	}()
	go func() {
		sp.pumpDownstream()
		done <- struct{}{}
	}()
	<-done
	sp.upConn.Close()
	sp.cliConn.Close()
}

// h2f is one parsed HTTP/2 frame. raw is the full wire bytes (header +
// payload, padding included); payload is the frame body with trailing
// padding stripped.
type h2f struct {
	raw     []byte
	typ     byte
	flags   byte
	sid     uint32
	payload []byte
}

func (f *h2f) endHeaders() bool { return f.flags&0x04 != 0 }

// readH2F reads a complete HTTP/2 frame from r.
func readH2F(r *bufio.Reader) (*h2f, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	flen := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	raw := make([]byte, 9+flen)
	copy(raw, hdr[:])
	if _, err := io.ReadFull(r, raw[9:]); err != nil {
		return nil, err
	}
	f := &h2f{
		raw:   raw,
		typ:   hdr[3],
		flags: hdr[4],
		sid:   binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff,
	}
	body := raw[9:]
	if f.flags&0x08 != 0 && len(body) > 0 { // PADDED
		pad := int(body[0])
		if pad >= len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		f.payload = body[1 : len(body)-pad]
	} else {
		f.payload = body
	}
	return f, nil
}

// writeF writes raw HTTP/2 frame bytes; errors terminate the pump.
func (sp *sessionSplice) writeF(dst net.Conn, raw []byte) bool {
	if _, err := dst.Write(raw); err != nil {
		log.Printf("[SESSION] upstream write failed: %v", err)
		return false
	}
	return true
}

// pumpUpstream forwards daemon frames to the client verbatim, tracing DiffCopy
// Dockerfile streams so the downstream pump knows what to rewrite.
func (sp *sessionSplice) pumpUpstream() {
	defer sp.markClosed()
	hdlr := hpack.NewDecoder(4096, nil)
	var hb []byte // accumulated header block across HEADERS + CONTINUATION
	hbSid := uint32(0)
	for {
		f, err := readH2F(sp.upR)
		if err != nil {
			log.Printf("[SESSION] daemon side closed: %v", err)
			return
		}
		switch f.typ {
		case 0x1: // HEADERS
			if f.endHeaders() {
				sp.identify(hdlr, f.sid, f.payload)
			} else {
				hb = append(hb, f.payload...)
				hbSid = f.sid
			}
		case 0x9: // CONTINUATION
			if len(hb) > 0 {
				hb = append(hb, f.payload...)
				if f.endHeaders() {
					sp.identify(hdlr, hbSid, hb)
					hb = nil
				}
			}
		case 0x4: // SETTINGS
			if f.flags&0x1 == 0 { // skip ACK frames; params only apply otherwise
				sp.applySettings(f.payload)
			}
		case 0x8: // WINDOW_UPDATE
			if len(f.payload) >= 4 {
				sp.applyWindowUpdate(f.sid, binary.BigEndian.Uint32(f.payload)&0x7fffffff)
			}
		}
		if !sp.writeF(sp.cliConn, f.raw) {
			return
		}
	}
}

// identify decodes a header block and marks DiffCopy streams that sync the
// Dockerfile.
func (sp *sessionSplice) identify(hdlr *hpack.Decoder, sid uint32, block []byte) {
	hdrs, err := hdlr.DecodeFull(block)
	if err != nil {
		log.Printf("[SESSION] header decode error: %v", err)
		return
	}
	tpath := ""
	var follows []string
	for _, h := range hdrs {
		switch strings.ToLower(h.Name) {
		case ":path":
			tpath = h.Value
		case "followpaths":
			follows = append(follows, h.Value)
		}
	}
	if strings.HasSuffix(tpath, "/moby.filesync.v1.FileSync/DiffCopy") && dockerfileInFollows(follows) {
		sp.markTarget(sid)
		log.Printf("[SESSION] marking stream %d as Dockerfile DiffCopy (follows=%v)", sid, follows)
	}
}

// dockerfileInFollows reports whether the followpaths header selects a
// Dockerfile by name. buildx docker-driver syncs the Dockerfile together with
// its ignore file and the context dir on one stream; per-file targeting (via
// the fsutil Stat path in the response) decides what actually gets rewritten.
func dockerfileInFollows(follows []string) bool {
	for _, f := range follows {
		for p := range strings.SplitSeq(f, ",") {
			p = strings.TrimSpace(strings.Trim(p, `"`))
			if isDockerfileName([]byte(path.Base(p))) {
				return true
			}
		}
	}
	return false
}

// pumpDownstream forwards client frames to the daemon, rewriting target-stream
// DiffCopy messages live. The daemon window-paces the stream per gRPC message
// (sending WINDOW_UPDATE as it consumes each one), so messages must flow: we
// buffer only enough to assemble a complete gRPC message, emit it (rewriting
// the Dockerfile's Data message content in place; fsutil writes whatever Data
// bytes arrive and only uses Stat.Size for progress), and move on.
func (sp *sessionSplice) pumpDownstream() {
	defer sp.markClosed()
	for {
		f, err := readH2F(sp.cliR)
		if err != nil {
			log.Printf("[SESSION] client side closed: %v", err)
			return
		}
		if sp.isTarget(f.sid) && f.typ == 0x0 { // DATA
			sp.mu.Lock()
			b, ok := sp.buf[f.sid]
			if !ok {
				b = &bytes.Buffer{}
				sp.buf[f.sid] = b
			}
			b.Write(f.payload)
			if complete, ok := parseGRPCMessages(b.Bytes()); ok {
				b.Reset()
				sp.mu.Unlock()
				if !sp.emitMessages(f.sid, complete) {
					return
				}
				continue
			}
			sp.mu.Unlock()
			continue
		}
		// Every DATA frame goes toward the daemon's connection window; wait
		// for the daemon to replenish it before flooding past its budget.
		if f.typ == 0x0 && f.sid != 0 && len(f.payload) > 0 {
			if !sp.waitWindow(len(f.payload)) {
				return
			}
			sp.spendWindow(f.sid, len(f.payload))
		}
		if !sp.writeF(sp.upConn, f.raw) {
			return
		}
	}
}

// emitMessages forwards already-parsed gRPC messages, rewiring the Dockerfile
// Data message on target streams. sp.stat must hold the Stat that precedes the
// Data on the same stream.
func (sp *sessionSplice) emitMessages(sid uint32, msgs [][]byte) bool {
	for _, m := range msgs {
		if len(m) < 5 || m[0]&0x01 != 0 {
			if !sp.writeMessage(sid, m) {
				return false
			}
			continue
		}
		pk, ok := classifyPacket(m[5:])
		if !ok {
			if !sp.writeMessage(sid, m) {
				return false
			}
			continue
		}
		switch pk.kind {
		case 1:
			st := pk.st
			sp.mu.Lock()
			sp.stat[sid] = &st
			sp.mu.Unlock()
			sp.writeMessage(sid, m)
		case 2:
			out := m
			sp.mu.Lock()
			cur := sp.stat[sid]
			delete(sp.stat, sid)
			sp.mu.Unlock()
			if cur != nil {
				if np, o, n, changed := rewriteDiffCopyData(m[5:], cur, sp.snap.edit); changed {
					out = grpcFrame(m[0], np)
					log.Printf("[SESSION] diffcopy stream %d: injected %d -> %d bytes", sid, o, n)
				}
			}
			if !sp.writeMessage(sid, out) {
				return false
			}
		default:
			if !sp.writeMessage(sid, m) {
				return false
			}
		}
	}
	return true
}

// maxWriteFrameSize caps each HTTP/2 DATA frame we emit. Peers negotiate
// SETTINGS_MAX_FRAME_SIZE (protocol default 16384); a single frame above that
// — or an over-long declared frame length — is rejected with "frame too
// large". The rewritten Dockerfile can be arbitrarily large (inline CA
// bundles), so each gRPC message is split across frames of at most this size.
const maxWriteFrameSize = 16 << 10

// defaultFlowWindow is the initial send window the daemon advertises
// (SETTINGS_INITIAL_WINDOW_SIZE and the connection window both default to
// 65535 per RFC 7540 §6.5.2 / §6.9.2) before any WINDOW_UPDATE.
const defaultFlowWindow = 65535

// writeMessage emits one gRPC message as HTTP/2 DATA frames, preserving the
// message framing bytes. The message is split into frames of at most
// maxWriteFrameSize: the HTTP/2 frame length field is only 24 bits wide and
// peers refuse frames above their advertised maximum, so a message must never
// be sent as a single frame. Emission also respects the daemon's send window:
// once connWin/strmWin are exhausted we wait for the daemon's WINDOW_UPDATE
// (or SETTINGS) to replenish them before writing more, so a rewritten
// Dockerfile orders of magnitude larger than the original window is paced
// through without tripping the daemon's flow control.
func (sp *sessionSplice) writeMessage(sid uint32, m []byte) bool {
	for len(m) > 0 {
		n := min(len(m), maxWriteFrameSize)
		if !sp.waitWindow(n) {
			return false
		}
		raw := make([]byte, 9+n)
		raw[0] = byte(n >> 16 & 0xff)
		raw[1] = byte(n >> 8 & 0xff)
		raw[2] = byte(n & 0xff)
		raw[3] = 0x0 // DATA
		binary.BigEndian.PutUint32(raw[5:9], sid)
		copy(raw[9:], m[:n])
		if !sp.writeF(sp.upConn, raw) {
			return false
		}
		sp.spendWindow(sid, n)
		m = m[n:]
	}
	return true
}
