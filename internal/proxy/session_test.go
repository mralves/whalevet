package proxy

import (
	"bytes"
	"testing"
)

// liveStatMsg reproduces the fsutil Stat message captured on the /session
// conn (c1.11): path "Dockerfile", size 43 (field 5), plus mode/mtime.
func liveStatMsg(t *testing.T, path string, size int) []byte {
	t.Helper()
	out := []byte{0x0a, byte(len(path))} //nolint:gosec // test fixtures use short paths
	out = append(out, path...)
	// field 2 (mode) = 0x1a4
	out = append(out, 0x10, 0xa4, 0x03)
	// field 5 (size)
	out = append(out, 5<<3)
	out = appendVarint(out, uint64(size)) //nolint:gosec // test fixtures use non-negative sizes
	// field 6 (mtime) 9-byte varint
	out = append(out, 0x30, 0xae, 0x88, 0xb1, 0xf5, 0x86, 0xe2, 0xcb, 0xe9, 0x18)
	return out
}

// statPacket builds a fsutil Stat packet (field 2 = Stat message).
func statPacket(t *testing.T, path string, size int) []byte {
	t.Helper()
	st := liveStatMsg(t, path, size)
	pkt := appendVarint(nil, 2<<3|2)
	pkt = appendVarint(pkt, uint64(len(st)))
	pkt = append(pkt, st...)
	return pkt
}

// dataPacket builds a fsutil Data packet (field 1 = 2, field 4 = content).
func dataPacket(t *testing.T, content []byte) []byte {
	t.Helper()
	pkt := appendVarint(nil, 1<<3) // Type = 2
	pkt = append(pkt, 0x02)
	pkt = appendVarint(pkt, 4<<3|2)
	pkt = appendVarint(pkt, uint64(len(content)))
	pkt = append(pkt, content...)
	return pkt
}

// grpcStream concatenates gRPC messages.
func grpcStream(t *testing.T, msgs ...[]byte) []byte {
	t.Helper()
	var out []byte
	for _, m := range msgs {
		out = append(out, m...)
	}
	return out
}

// sizeOf reads the size field (5) out of a fsutil Stat message.
func statSize(t *testing.T, statMsg []byte) int {
	t.Helper()
	fs := parseFields(statMsg)
	if fs == nil {
		t.Fatalf("stat does not parse: %x", statMsg)
	}
	for _, f := range fs {
		if f.num == 5 && f.wt == wtVarint {
			return int(f.uval) //nolint:gosec // test fixtures use sizes that fit in int
		}
	}
	return -1
}

func sessionEdit() func([]byte) ([]byte, bool) {
	return func(content []byte) ([]byte, bool) {
		if !bytes.HasPrefix(content, []byte("FROM ")) {
			return content, false
		}
		out := append([]byte(nil), content...)
		return append(out, []byte("\nRUN echo whalevet-marker > /whalevet-marker\n")...), true
	}
}

// rewriteStream walks a parsed DiffCopy message sequence the way the live
// splice does (a Stat sets the current file; the following matching Data is
// rewritten; any other Data clears it) and returns the rewritten messages.
func rewriteStream(t *testing.T, msgs [][]byte, edit func([]byte) ([]byte, bool)) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(msgs))
	var cur *fsutilStat
	for _, m := range msgs {
		if len(m) < 5 {
			cur = nil
			out = append(out, m)
			continue
		}
		pk, ok := classifyPacket(m[5:])
		if !ok {
			cur = nil
			out = append(out, m)
			continue
		}
		switch pk.kind {
		case 1:
			st := pk.st
			cur = &st
			out = append(out, m)
		case 2:
			if cur != nil {
				if np, _, _, changed := rewriteDiffCopyData(m[5:], cur, edit); changed {
					out = append(out, grpcFrame(m[0], np))
					cur = nil
					continue
				}
			}
			cur = nil
			out = append(out, m)
		default:
			cur = nil
			out = append(out, m)
		}
	}
	return out
}

func TestRewriteDiffCopyDataInjectsIntoDockerfile(t *testing.T) {
	orig := []byte("FROM alpine:latest\nCOPY test.txt /test.txt\n")
	injected, _ := sessionEdit()(orig)
	payload := dataPacket(t, orig)

	out, o, n, changed := rewriteDiffCopyData(payload, &fsutilStat{path: "Dockerfile", size: len(orig)}, sessionEdit())
	if !changed {
		t.Fatalf("expected the Dockerfile to be rewritten")
	}
	if o != len(orig) || n != len(injected) {
		t.Fatalf("size report %d -> %d, want %d -> %d", o, n, len(orig), len(injected))
	}
	pk, ok := classifyPacket(out)
	if !ok || pk.kind != 2 || !bytes.Equal(pk.data, injected) {
		t.Fatalf("rewritten Data mismatch: %x", out)
	}
	// The Type field (1=2) must survive the rewrite.
	if !bytes.Contains(out, []byte{0x08, 0x02}) {
		t.Fatalf("Data packet Type field lost: %x", out)
	}
}

func TestRewriteDiffCopyDataLeavesStatUntouched(t *testing.T) {
	orig := []byte("FROM alpine:latest\n")
	// The splice rewrites only the Data message; the Stat (with the original
	// Size) passes through verbatim, since fsutil ignores Stat.Size on write.
	statMsg := liveStatMsg(t, "Dockerfile", len(orig))
	if size := statSize(t, statMsg); size != len(orig) {
		t.Fatalf("fixture stat size=%d want %d", size, len(orig))
	}
}

func TestRewriteDiffCopyDataMissizedChunkFailsOpen(t *testing.T) {
	orig := []byte("FROM alpine:latest\n")
	// A Stat whose Size does not match the following Data is either a
	// different file or a mid-stream chunk: never rewrite it.
	payload := dataPacket(t, orig[:len(orig)-2])
	out, _, _, changed := rewriteDiffCopyData(payload, &fsutilStat{path: "Dockerfile", size: len(orig)}, sessionEdit())
	if changed || !bytes.Equal(out, payload) {
		t.Fatalf("expected fail-open passthrough, changed=%v", changed)
	}
}

func TestRewriteDiffCopyDataNoChangeFailsOpen(t *testing.T) {
	orig := []byte("FROM alpine:latest\n")
	payload := dataPacket(t, orig)
	noop := func(content []byte) ([]byte, bool) { return content, false }
	out, _, _, changed := rewriteDiffCopyData(payload, &fsutilStat{path: "Dockerfile", size: len(orig)}, noop)
	if changed || !bytes.Equal(out, payload) {
		t.Fatalf("expected fail-open passthrough, changed=%v", changed)
	}
}

func TestRewriteDiffCopyDataOtherFile(t *testing.T) {
	orig := []byte("hello from test.txt\n")
	payload := dataPacket(t, orig)
	out, _, _, changed := rewriteDiffCopyData(payload, &fsutilStat{path: "test.txt", size: len(orig)}, sessionEdit())
	if changed {
		t.Fatalf("test.txt must not be rewritten")
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("bytes changed for non-Dockerfile stream")
	}
}

func TestRewriteDiffCopyDataGarbage(t *testing.T) {
	garbage := []byte{0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	out, _, _, changed := rewriteDiffCopyData(garbage, &fsutilStat{path: "Dockerfile"}, sessionEdit())
	if changed || !bytes.Equal(out, garbage) {
		t.Fatalf("expected fail-open passthrough, changed=%v", changed)
	}
}

// TestRewriteDiffCopyDataMultiFile rewrites only the Dockerfile among several
// files on one DiffCopy stream (the buildx docker-driver layout: Dockerfile +
// {Dockerfile}.dockerignore + a context directory named dockerfile).
func TestRewriteDiffCopyDataMultiFile(t *testing.T) {
	orig := []byte("FROM alpine:latest\nCOPY test.txt /test.txt\n")
	injected, _ := sessionEdit()(orig)
	ignore := []byte("**/*.md\n")
	msgs, ok := parseGRPCMessages(grpcStream(t,
		frame(0, statPacket(t, "Dockerfile", len(orig))),
		frame(0, dataPacket(t, orig)),
		frame(0, statPacket(t, "Dockerfile.dockerignore", len(ignore))),
		frame(0, dataPacket(t, ignore)),
		frame(0, statPacket(t, "dockerfile", 0)),
		frame(0, dataPacket(t, nil)),
		frame(0, []byte{0x08, 0x03}), // Finish
	))
	if !ok || len(msgs) != 7 {
		t.Fatalf("parse failed: ok=%v len=%d", ok, len(msgs))
	}
	stream := bytes.Join(rewriteStream(t, msgs, sessionEdit()), nil)
	if !bytes.Contains(stream, injected) {
		t.Fatalf("injected content missing")
	}
	if !bytes.Contains(stream, ignore) {
		t.Fatalf("dockerignore content lost")
	}
	if bytes.Count(stream, []byte("RUN echo whalevet-marker")) != 1 {
		t.Fatalf("injection expected exactly once, got %d", bytes.Count(stream, []byte("RUN echo whalevet-marker")))
	}
}

func TestRewriteDiffCopyDataParseHelpers(t *testing.T) {
	// parseFSUTILStat / classifyPacket must agree with the raw fixtures.
	st, ok := parseFSUTILStat(liveStatMsg(t, "Dockerfile", 43))
	if !ok || st.path != "Dockerfile" || st.size != 43 {
		t.Fatalf("stat parse: ok=%v path=%q size=%d", ok, st.path, st.size)
	}
	pk, ok := classifyPacket(dataPacket(t, []byte("x")))
	if !ok || pk.kind != 2 || !bytes.Equal(pk.data, []byte("x")) {
		t.Fatalf("data classify: ok=%v kind=%d", ok, pk.kind)
	}
	if pk, ok := classifyPacket([]byte{0x08, 0x03}); !ok || pk.kind != 0 {
		t.Fatalf("Finish must classify as kind 0, got ok=%v kind=%d", ok, pk.kind)
	}
}
