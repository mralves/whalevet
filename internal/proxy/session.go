package proxy

import (
	"bytes"
	"encoding/binary"
)

// Rewriting of the moby.filesync.v1.FileSync / DiffCopy response that carries
// a Dockerfile from a buildx client to the daemon over a /session connection.
//
// Observed wire format:
//
//	gRPC message   : [compressed 1B][length 4B BE][payload]
//	  fsutil Packet: proto{ 1 Type varint, 2 Stat len, 4 Data len }
//	     Type 2 = Data, 3 = Finish (Stat packets carry no explicit Type)
//	  fsutil Stat  : proto{ 1 Path string, 5 Size varint, ... }
//
// The Dockerfile DiffCopy is a dedicated one-file stream: the client sends a
// Stat packet (path "Dockerfile", exact Size, from a real lstat) followed
// directly by one Data packet holding the raw bytes. The splice rewrites that
// Data packet's content in place; fsutil's receiver writes whatever Data bytes
// arrive and only uses Stat.Size for progress, so the Stat is left untouched.
// gRPC and protobuf length fields are recomputed at every layer. Any
// structural surprise fails open: the message is forwarded unchanged.

// parseGRPCMessages splits one gRPC stream byte soup into framed messages
// ([5-byte header][payload] each).
func parseGRPCMessages(data []byte) ([][]byte, bool) {
	var out [][]byte
	i := 0
	for i < len(data) {
		if i+5 > len(data) {
			return nil, false
		}
		msglen := int(binary.BigEndian.Uint32(data[i+1 : i+5]))
		total := 5 + msglen
		if msglen < 0 || msglen > maxGRPCBuffer || i+total > len(data) {
			return nil, false
		}
		out = append(out, data[i:i+total])
		i += total
	}
	return out, true
}

// grpcFrame re-encodes a gRPC message.
func grpcFrame(flags byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// fsutilStat is the parsed piece of a fsutil Stat message we need.
type fsutilStat struct {
	path string
	size int // field 5; exact content length (real lstat)
}

// parseFSUTILStat inspects a fsutil Stat message for path (field 1) and size
// (field 5). ok=false if the shape is unexpected.
func parseFSUTILStat(m []byte) (fsutilStat, bool) {
	fs := parseFields(m)
	if fs == nil {
		return fsutilStat{}, false
	}
	var st fsutilStat
	for _, f := range fs {
		switch {
		case f.num == 1 && f.wt == wtLen:
			st.path = string(f.val)
		case f.num == 5 && f.wt == wtVarint:
			st.size = int(f.uval)
		}
	}
	return st, st.path != ""
}

// fsutilPkt classifies one fsutil Packet (gRPC payload): kind 1 = Stat,
// kind 2 = Data, kind 3 = other (Finish etc).
type fsutilPkt struct {
	kind int
	st   fsutilStat // kind 1
	data []byte     // kind 2
}

// classifyPacket parses a fsutil Packet payload. malformed reports an
// unknown or truncated structure.
func classifyPacket(payload []byte) (fsutilPkt, bool) {
	fs := parseFields(payload)
	if fs == nil {
		return fsutilPkt{}, false
	}
	for _, f := range fs {
		switch {
		case f.num == 2 && f.wt == wtLen: // Stat
			st, ok := parseFSUTILStat(f.val)
			if !ok {
				return fsutilPkt{}, false
			}
			return fsutilPkt{kind: 1, st: st}, true
		case f.num == 4 && f.wt == wtLen: // Data
			return fsutilPkt{kind: 2, data: f.val}, true
		}
	}
	return fsutilPkt{}, true
}

// patchLenField re-encodes a protobuf message with its length-delimited field
// `num` replaced by val. ok=false when the message is malformed or the field
// is not length-delimited.
func patchLenField(m []byte, num uint64, val []byte) ([]byte, bool) {
	fs := parseFields(m)
	if fs == nil {
		return nil, false
	}
	found := false
	for i := range fs {
		if fs[i].num != num {
			continue
		}
		if fs[i].wt != wtLen {
			return nil, false
		}
		fs[i].patched = encodeLenField(num, val)
		found = true
	}
	if !found {
		return nil, false
	}
	out := make([]byte, 0, len(m)+len(val)+8)
	for i := range fs {
		out = append(out, fs[i].bytes()...)
	}
	return out, true
}

// rewriteDiffCopyData rewrites one fsutil Data message of a target DiffCopy
// stream, given the Stat that preceded it on the same stream. The content is
// patched when the file is a Dockerfile name and the Data is a single chunk
// matching the Stat size; other files (a Dockerfile.dockerignore, a context
// directory named dockerfile, ...) pass through untouched. Returns the new
// payload and the old/new content lengths (for logging); fails open (returns
// the input unchanged, changed=false) on any structural surprise, compression,
// or an edit that reports no change.
func rewriteDiffCopyData(payload []byte, cur *fsutilStat, edit func([]byte) ([]byte, bool)) ([]byte, int, int, bool) {
	pk, ok := classifyPacket(payload)
	if !ok || pk.kind != 2 || edit == nil {
		return payload, len(pk.data), len(pk.data), false
	}
	if cur == nil || !isDockerfileName([]byte(cur.path)) || len(pk.data) != cur.size {
		return payload, len(pk.data), len(pk.data), false
	}
	nc, eok := edit(pk.data)
	if !eok || bytes.Equal(nc, pk.data) {
		return payload, len(pk.data), len(pk.data), false
	}
	np, ok := patchLenField(payload, 4, nc)
	if !ok {
		return payload, len(pk.data), len(pk.data), false
	}
	return np, len(pk.data), len(nc), true
}
