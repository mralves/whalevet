package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"github.com/mralves/whalevet/internal/tarutil"
)

// rewriteTarget describes how Dockerfile content is to be rewritten on one
// h2c connection. method is the upstream gRPC path of the current stream,
// used to pick an envelope; editFile maps original Dockerfile bytes to
// injected bytes and reports whether anything changed.
type rewriteTarget struct {
	method   string
	editFile func(content []byte) ([]byte, bool)
}

const (
	// maxGRPCBuffer caps how much of a single gRPC message (or a legacy tar
	// stream) we are willing to hold in memory while rewriting. Larger data
	// passes through untouched.
	maxGRPCBuffer = 64 << 20
)

// grpcRewriteReader wraps the request body of an h2c/gRPC stream. It
// reassembles gRPC messages ([flags][4-byte length][payload]), rewrites the
// ones that carry a Dockerfile, and re-emits them with corrected framing.
// Any structural surprise fails open: original bytes are passed through.
type grpcRewriteReader struct {
	next  io.Reader
	tgt   *rewriteTarget
	out   bytes.Buffer
	frame [5]byte
	done  bool
	// Legacy tar (BytesMessage) envelope: accumulate and rewrite on EOF.
	tarMode bool
	tarBuf  bytes.Buffer
	tarFail bool
}

func newGRPCRewriteReader(next io.Reader, tgt *rewriteTarget) *grpcRewriteReader {
	r := &grpcRewriteReader{next: next, tgt: tgt}
	if tgt != nil {
		r.tarMode = strings.Contains(tgt.method, "FileSend/DiffCopy")
	}
	return r
}

// Close satisfies io.ReadCloser; the underlying body is closed by the caller.
func (r *grpcRewriteReader) Close() error {
	return nil
}

func (r *grpcRewriteReader) Read(p []byte) (int, error) {
	for {
		if r.out.Len() > 0 {
			return r.out.Read(p)
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.nextMessage(); err != nil {
			if err == io.EOF {
				r.finishTar()
				r.done = true
				continue
			}
			return 0, err
		}
	}
}

// nextMessage reads one full gRPC message from next and emits its (possibly
// rewritten) bytes into out.
func (r *grpcRewriteReader) nextMessage() error {
	if _, err := io.ReadFull(r.next, r.frame[:]); err != nil {
		return err
	}
	flags := r.frame[0]
	msglen := int(binary.BigEndian.Uint32(r.frame[1:5]))
	if msglen < 0 || msglen > maxGRPCBuffer {
		r.done = true
		r.out.Write(r.frame[:])
		_, err := io.CopyN(&r.out, r.next, int64(msglen))
		return err
	}

	payload := make([]byte, msglen)
	if _, err := io.ReadFull(r.next, payload); err != nil {
		return err
	}

	if r.tarMode {
		return r.handleTarMessage(flags, payload)
	}

	out, _ := r.rewriteMessage(flags, payload)
	emitted := make([]byte, 5)
	emitted[0] = flags
	binary.BigEndian.PutUint32(emitted[1:5], uint32(len(out)))
	r.out.Write(emitted)
	r.out.Write(out)
	return nil
}

// handleTarMessage accumulates BytesMessage payloads; once the accumulated
// tar exceeds the cap it flushes what it has verbatim and streams the rest
// through unchanged.
func (r *grpcRewriteReader) handleTarMessage(flags byte, payload []byte) error {
	if r.tarFail {
		r.out.Write(r.frame[:])
		r.out.Write(payload)
		return nil
	}
	if r.tarBuf.Len()+len(payload) > maxGRPCBuffer {
		r.flushTarBuf()
		r.tarFail = true
		r.out.Write(r.frame[:])
		r.out.Write(payload)
		return nil
	}
	r.tarBuf.Write(payload)
	return nil
}

// flushTarBuf writes the held tar bytes verbatim as BytesMessage frames.
func (r *grpcRewriteReader) flushTarBuf() {
	for _, m := range chunkAsBytesMessages(r.tarBuf.Bytes()) {
		r.out.Write(m)
	}
	r.tarBuf.Reset()
}

// finishTar rewrites the accumulated tar (if any) at stream end.
func (r *grpcRewriteReader) finishTar() {
	if !r.tarMode || r.tarFail || r.tarBuf.Len() == 0 {
		return
	}
	data := r.tarBuf.Bytes()
	if rewritten := rewriteTar(data, r.tgt); !bytes.Equal(rewritten, data) {
		r.tarBuf.Reset()
		for _, m := range chunkAsBytesMessages(rewritten) {
			r.out.Write(m)
		}
		return
	}
	r.flushTarBuf()
}

// rewriteMessage rewrites one gRPC payload in place, returning the (possibly
// larger) replacement bytes. Compressed messages and envelope types we cannot
// safely rewrite are passed through untouched.
func (r *grpcRewriteReader) rewriteMessage(flags byte, payload []byte) ([]byte, bool) {
	if r.tgt == nil || flags&0x01 != 0 {
		return payload, false
	}
	// fsutil Packet streams (FileSync/DiffCopy, FileSync/TarStream) are a
	// bidirectional STAT/REQ/DATA protocol: the sender's STAT must carry the
	// final file size before content exists, so rewriting is not possible
	// without replaying the whole dance. Fail open (pass through).
	if strings.Contains(r.tgt.method, "FileSync/DiffCopy") ||
		strings.Contains(r.tgt.method, "FileSync/TarStream") {
		return payload, false
	}
	// Modern envelope: recursive protobuf walker looking for file records
	// {name=1, content=2, attrs=3} named like a Dockerfile.
	return rewriteRecords(payload, r.tgt)
}

// chunkAsBytesMessages splits raw bytes into framed BytesMessage gRPC
// messages (legacy FileSend/DiffCopy envelope).
func chunkAsBytesMessages(data []byte) [][]byte {
	const chunk = 32 << 10
	var out [][]byte
	for len(data) > 0 {
		n := chunk
		if len(data) < n {
			n = len(data)
		}
		msg := make([]byte, 5+n)
		binary.BigEndian.PutUint32(msg[1:5], uint32(n))
		copy(msg[5:], data[:n])
		out = append(out, msg)
		data = data[n:]
	}
	return out
}

// --- protobuf helpers ---

const (
	wtVarint  = 0
	wtFixed64 = 1
	wtLen     = 2
	wtFixed32 = 5
)

// varintAt decodes a varint starting at b[i], returning its value and length
// in bytes, or (0, 0) when truncated.
func varintAt(b []byte, i int) (uint64, int) {
	var v uint64
	var s uint
	for n := i; n < len(b); n++ {
		c := b[n]
		if c < 0x80 {
			if n-i+1 > 10 || s >= 64 {
				return 0, 0
			}
			return v | uint64(c)<<s, n - i + 1
		}
		v |= uint64(c&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

// appendVarint appends the base-128 varint encoding of v.
func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// encodeLenField encodes a length-delimited field (tag | length | value).
func encodeLenField(field uint64, val []byte) []byte {
	out := appendVarint(nil, field<<3|wtLen)
	out = append(out, appendVarint(nil, uint64(len(val)))...)
	return append(out, val...)
}

// isDockerfileName reports whether a protobuf string value is a Dockerfile
// file name (as opposed to surrounding context keys).
func isDockerfileName(s []byte) bool {
	switch string(s) {
	case "Dockerfile", "dockerfile", ".Dockerfile":
		return true
	}
	return false
}

// field is a parsed protobuf field at one message level. For length-
// delimited fields, orig spans the full field bytes (tag+len+value) and val
// is the value bytes. patched holds a re-encoded replacement when the field
// was rewritten.
type field struct {
	num     uint64
	wt      int
	orig    []byte
	val     []byte
	uval    uint64 // varint field value
	patched []byte
}

func (f *field) bytes() []byte {
	if f.patched != nil {
		return f.patched
	}
	return f.orig
}

// parseFields splits a protobuf message into its top-level fields, validating
// that the message is well-formed. Returns nil when unparsable (fail open).
func parseFields(m []byte) []field {
	var fs []field
	i := 0
	for i < len(m) {
		start := i
		tag, n := varintAt(m, i)
		if n == 0 {
			return nil
		}
		i += n
		num := tag >> 3
		wt := tag & 7
		var val []byte
		var uval uint64
		switch wt {
		case wtVarint:
			u, n := varintAt(m, i)
			if n == 0 {
				return nil
			}
			i += n
			uval = u
		case wtFixed64:
			if i+8 > len(m) {
				return nil
			}
			i += 8
		case wtFixed32:
			if i+4 > len(m) {
				return nil
			}
			i += 4
		case wtLen:
			l, ln := varintAt(m, i)
			if ln == 0 || l > uint64(len(m)) || i+ln+int(l) > len(m) {
				return nil
			}
			val = m[i+ln : i+ln+int(l)]
			i = i + ln + int(l)
		default:
			return nil
		}
		fs = append(fs, field{num: num, wt: int(wt), orig: m[start:i], val: val, uval: uval})
	}
	return fs
}

// rewriteRecords walks a protobuf message and replaces the content of any
// file record {name=1, content=2, attrs=3} whose name matches a Dockerfile
// filename, at any nesting depth. Enclosing lengths are re-encoded only on
// the changed path; every other byte is preserved verbatim. On any
// structural surprise the input is returned unchanged.
func rewriteRecords(m []byte, tgt *rewriteTarget) ([]byte, bool) {
	fs := parseFields(m)
	if fs == nil {
		return m, false
	}

	changed := false
	// Recurse first: length-delimited children may contain records.
	for i := range fs {
		if fs[i].wt != wtLen {
			continue
		}
		if sub, subChanged := rewriteRecords(fs[i].val, tgt); subChanged {
			fs[i].patched = encodeLenField(fs[i].num, sub)
			changed = true
		}
	}

	// Detect records at this level: field1 name, field2 content, field3 attrs.
	for i := 0; i < len(fs)-2; i++ {
		f1, f2, f3 := &fs[i], &fs[i+1], &fs[i+2]
		if f1.num != 1 || f1.wt != wtLen || !isDockerfileName(f1.val) {
			continue
		}
		if f2.num != 2 || f2.wt != wtLen {
			continue
		}
		if f3.num != 3 || f3.wt != wtLen {
			continue
		}
		newC, ok := tgt.editFile(f2.val)
		if !ok || bytes.Equal(newC, f2.val) {
			continue
		}
		f2.patched = encodeLenField(2, newC)
		changed = true
	}

	if !changed {
		return m, false
	}

	out := make([]byte, 0, len(m)+64)
	for i := range fs {
		out = append(out, fs[i].bytes()...)
	}
	return out, true
}

// rewriteTar replaces the Dockerfile inside a tar archive with injected
// content. `data` is the concatenated BytesMessage payloads of a legacy
// build-context upload. On any error the input is returned unchanged.
func rewriteTar(data []byte, tgt *rewriteTarget) []byte {
	if tgt == nil || tgt.editFile == nil {
		return data
	}
	path, content, entries, err := tarutil.ExtractDockerfile(bytes.NewReader(data), "")
	if err != nil || content == "" {
		return data
	}
	newC, ok := tgt.editFile([]byte(content))
	if !ok || bytes.Equal(newC, []byte(content)) {
		return data
	}
	r := tarutil.RebuildTar(entries, path, string(newC), nil)
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}
