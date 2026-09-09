package proxy

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
)

var realDockerfile = "# markertest_xyz-start\nFROM scratch\nCOPY test.txt /test.txt\n\n"

func testEdit() *rewriteTarget {
	return &rewriteTarget{
		method: "/moby.buildkit.v1.frontend.LLBBridge/Return",
		editFile: func(content []byte) ([]byte, bool) {
			if !bytes.Contains(content, []byte("FROM scratch")) {
				return content, false
			}
			out := append([]byte(nil), content...)
			return append(out, []byte("\nRUN echo injected > /marker\n")...), true
		},
	}
}

// framePayload splits a captured gRPC frame into its header and payload.
func framePayload(t *testing.T, b []byte) (byte, []byte) {
	t.Helper()
	if len(b) < 5 {
		t.Fatalf("frame too short")
	}
	return b[0], b[5 : 5+int(binary.BigEndian.Uint32(b[1:5]))]
}

// frame builds a gRPC frame.
func frame(flags byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload))) //nolint:gosec // len bounded by maxGRPCBuffer
	copy(out[5:], payload)
	return out
}

func TestRewriteRecordsRealEnvelope(t *testing.T) {
	raw, err := os.ReadFile("testdata/return_stream21.bin")
	if err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	_, payload := framePayload(t, raw)

	out, changed := rewriteRecords(payload, testEdit())
	if !changed {
		t.Fatalf("expected the captured Dockerfile record to be rewritten")
	}
	fs := parseFields(out)
	if fs == nil {
		t.Fatalf("rewritten message no longer parses")
	}
	if !bytes.Contains(out, []byte("RUN echo injected > /marker")) {
		t.Fatalf("rewritten message does not contain injected line")
	}
	if !bytes.Contains(out, []byte("Dockerfile")) {
		t.Fatalf("rewritten message lost the Dockerfile name")
	}
	// Rerunning with a no-op edit must be a clean passthrough.
	noop := &rewriteTarget{method: "x", editFile: func(c []byte) ([]byte, bool) { return c, false }}
	if out2, changed2 := rewriteRecords(payload, noop); changed2 || !bytes.Equal(out2, payload) {
		t.Fatalf("no-op edit should pass through byte-for-byte")
	}
}

func TestRewriteRecordsNested(t *testing.T) {
	// Build a synthetic modern envelope: gRPC payload = f1 LD { f3 LD {
	// f1 digest..., f2 LD record } }.
	record := bytes.Join([][]byte{
		encodeLenField(1, []byte("Dockerfile")),
		encodeLenField(2, []byte(realDockerfile)),
		encodeLenField(3, []byte("\x0a\x11local://dockerfile")),
	}, nil)
	inner := bytes.Join([][]byte{
		encodeLenField(1, []byte("# some digest filler")),
		encodeLenField(2, record),
	}, nil)
	payload := encodeLenField(3, inner)
	payload = encodeLenField(1, payload)

	out, changed := rewriteRecords(payload, testEdit())
	if !changed {
		t.Fatalf("expected nested record rewrite")
	}
	if !bytes.Contains(out, []byte("\nRUN echo injected > /marker")) {
		t.Fatalf("injected content missing")
	}
	if parseFields(out) == nil {
		t.Fatalf("output unparsable")
	}
}

func TestRewriteRecordsPassthrough(t *testing.T) {
	// Non-protobuf blob (e.g. containerimage.config JSON) must pass through.
	blob := []byte(`{"Platforms":[{"ID":"linux/amd64"}]}`)
	if out, changed := rewriteRecords(blob, testEdit()); changed || !bytes.Equal(out, blob) {
		t.Fatalf("non-protobuf blob should pass through")
	}
	// A message that parses but has no Dockerfile record must pass through.
	m := frame(0x0a, []byte("refs.platforms"))
	if out, changed := rewriteRecords(m, testEdit()); changed || !bytes.Equal(out, m) {
		t.Fatalf("string-looking message should pass through")
	}
}

type chunkReader struct {
	data []byte
	step int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(c.step, len(c.data), len(p))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func TestGrpcRewriteReaderStreaming(t *testing.T) {
	// Two messages: a Return envelope (rewritten) and a config blob
	// (untouched, compressed flag set so even content is passed through).
	rec := bytes.Join([][]byte{
		encodeLenField(1, []byte("Dockerfile")),
		encodeLenField(2, []byte(realDockerfile)),
		encodeLenField(3, []byte("\x0a\x11local://dockerfile")),
	}, nil)
	env := encodeLenField(1, rec)
	blob := []byte(`{"nested":"json object","opaque":true}`)

	want := new(strings.Builder)
	want.Write(frame(0, env))

	var got bytes.Buffer
	// Rebuild `env` with the injected line to compute the expected stream.
	filter := &rewriteTarget{method: "LLBBridge/Return", editFile: testEdit().editFile}
	outEnv, _ := rewriteRecords(env, filter)
	expected := frame(0, outEnv)
	expected = append(expected, frame(0x01, blob)...)

	r := newGRPCRewriteReader(&chunkReader{data: append(frame(0, env), frame(0x01, blob)...), step: 3}, filter)
	if _, err := io.Copy(&got, r); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(got.Bytes(), expected) {
		t.Fatalf("stream mismatch\n got %x\nwant %x", got.Bytes(), expected)
	}
	// The identity of message 2 must be preserved exactly.
	if !bytes.Contains(got.Bytes(), blob) {
		t.Fatalf("opaque blob lost")
	}
}

func TestTarEnvelopeRewrite(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := []struct {
		name string
		body string
	}{{"Dockerfile", realDockerfile}, {"notes.txt", "hello"}}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %q: %v", f.name, err)
		}
		tw.Write([]byte(f.body))
	}
	tw.Close()

	chunks := chunkAsBytesMessages(buf.Bytes())
	input := bytes.Join(chunks, nil)

	tgt := &rewriteTarget{method: "moby.filesync.v1.FileSend/DiffCopy", editFile: testEdit().editFile}
	filter := testReaderWithChunk(input, tgt)

	var got bytes.Buffer
	if _, err := io.Copy(&got, filter); err != nil {
		t.Fatalf("copy: %v", err)
	}

	// Decode the output back into gRPC frames and verify the tar content.
	var tarData bytes.Buffer
	for len(got.Bytes()) > 0 {
		b := got.Bytes()
		if len(b) < 5 {
			t.Fatalf("truncated frame")
		}
		l := int(binary.BigEndian.Uint32(b[1:5]))
		if 5+l > len(b) {
			t.Fatalf("bad frame length %d with %d bytes", l, len(b))
		}
		tarData.Write(b[5 : 5+l])
		got.Next(5 + l)
	}
	output := tarData.Bytes()
	if !bytes.Contains(output, []byte("RUN echo injected > /marker")) {
		t.Fatalf("injected line missing in rebuilt tar")
	}
	// Rebuild tar must remain readable.
	tr := tar.NewReader(bytes.NewReader(output))
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("output not a valid tar: %v", err)
		}
		names[h.Name] = true
	}
	if !names["Dockerfile"] || !names["notes.txt"] {
		t.Fatalf("tar entries lost: %v", names)
	}
}

func testReaderWithChunk(input []byte, tgt *rewriteTarget) *grpcRewriteReader {
	return newGRPCRewriteReader(&chunkReader{data: input, step: 7}, tgt)
}
