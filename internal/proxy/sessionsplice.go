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
// V1 does not re-implement HTTP/2 flow control: the daemon grants the
// client's send windows, the client respects them, and our insertion of a few
// dozen bytes into a tiny DiffCopy is well inside the slack. Only the frames
// of the Dockerfile sync are buffered; everything else flows through in real
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
	targets map[uint32]bool
	// stat records the most recent fsutil Stat seen on each target stream, so
	// the following Data message can be recognised as the Dockerfile's.
	stat map[uint32]*fsutilStat
	buf  map[uint32]*bytes.Buffer
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
		for _, p := range strings.Split(f, ",") {
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

// writeMessage emits one gRPC message as an HTTP/2 DATA frame, preserving the
// message framing bytes.
func (sp *sessionSplice) writeMessage(sid uint32, m []byte) bool {
	raw := make([]byte, 9+len(m))
	l := len(m)
	raw[1] = byte(l >> 8 & 0xff)
	raw[2] = byte(l & 0xff)
	raw[3] = 0x0 // DATA
	binary.BigEndian.PutUint32(raw[5:9], sid)
	copy(raw[9:], m)
	return sp.writeF(sp.upConn, raw)
}
