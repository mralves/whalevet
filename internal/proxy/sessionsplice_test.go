package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestWriteMessageChunksOversizedMessages guards the "http2: frame too large"
// regression: a rewritten Dockerfile larger than 64KB used to be emitted as a
// single DATA frame with a 16-bit length field, corrupting the HTTP/2 stream
// and making the daemon drop the build with "frame too large". Each emitted
// frame must now stay within maxWriteFrameSize, carry a correct 24-bit
// length, and reassemble into the original gRPC message.
func TestWriteMessageChunksOversizedMessages(t *testing.T) {
	up, peer := net.Pipe()
	defer up.Close()
	defer peer.Close()

	msg := bytes.Repeat([]byte{'x'}, 70<<10)
	sp := &sessionSplice{upConn: up, targets: map[uint32]bool{}}
	sp.initWindows()
	sp.markTarget(1)
	// No WINDOW_UPDATE will ever arrive from this naive peer; size the budget
	// so the whole message fits without flow-control blocking (that path is
	// exercised by TestWriteMessageFlowControlWait).
	sp.connWin = len(msg)
	sp.strmWin = len(msg)

	done := make(chan error, 1)
	go func() {
		r := bufio.NewReader(peer)
		var payload []byte
		for {
			f, err := readH2F(r)
			if err != nil {
				break // peer closed after the message was fully written
			}
			if f.typ != 0x0 {
				done <- fmt.Errorf("unexpected frame type 0x%x on sid %d", f.typ, f.sid)
				return
			}
			if len(f.raw) > 9+maxWriteFrameSize {
				done <- fmt.Errorf("emitted frame of %d bytes exceeds max %d", len(f.raw), maxWriteFrameSize)
				return
			}
			if f.sid != 1 {
				done <- fmt.Errorf("unexpected stream id %d", f.sid)
				return
			}
			payload = append(payload, f.payload...)
		}
		if !bytes.Equal(payload, msg) {
			done <- fmt.Errorf("reassembled payload %d bytes, want %d", len(payload), len(msg))
			return
		}
		done <- nil
	}()

	if !sp.writeMessage(1, msg) {
		t.Fatal("writeMessage returned false")
	}
	_ = peer.Close() // stop the reader loop
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestWriteMessageFlowControlWaits verifies writeMessage paces emission on
// the daemon's send window: it must stop writing once the initial 64KB budget
// is spent and only resume once WINDOW_UPDATE replenishes it, instead of
// blasting a multi-megabyte rewritten Dockerfile in one burst (which the
// daemon rejects by closing the connection).
func TestWriteMessageFlowControlWaits(t *testing.T) {
	up, peer := net.Pipe()
	defer up.Close()
	defer peer.Close()

	msg := bytes.Repeat([]byte{'d'}, 100<<10) // ~100KB, ~3x the initial window
	sp := &sessionSplice{upConn: up, targets: map[uint32]bool{}}
	sp.initWindows()
	sp.markTarget(1)

	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		if !sp.writeMessage(1, msg) {
			errCh <- errors.New("writeMessage returned false")
			close(done)
			return
		}
		close(done)
	}()

	var received int
	go func() {
		r := bufio.NewReader(peer)
		for {
			f, err := readH2F(r)
			if err != nil {
				return
			}
			if f.typ != 0x0 || f.sid != 1 {
				errCh <- fmt.Errorf("unexpected frame type 0x%x on sid %d", f.typ, f.sid)
				return
			}
			received += len(f.payload)
		}
	}()

	// Without any WINDOW_UPDATE the message must stall at the initial window.
	select {
	case <-done:
		t.Fatal("writeMessage completed despite an unreplenished 64KB window")
	case <-time.After(50 * time.Millisecond):
	}

	// Replenish the connection and stream budgets; the message must then flow
	// to completion.
	sp.applyWindowUpdate(0, defaultFlowWindow)
	sp.applyWindowUpdate(1, defaultFlowWindow)
	// The message still exceeds the two windows' combined reload; keep granting
	// until the writer finishes, mirroring the daemon consuming as it goes.
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
				sp.applyWindowUpdate(0, defaultFlowWindow)
				sp.applyWindowUpdate(1, defaultFlowWindow)
			}
		}
	}()
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writeMessage never completed after window updates")
	}

	_ = peer.Close()
	time.Sleep(20 * time.Millisecond) // let the reader drain the pipe
	if received != len(msg) {
		t.Fatalf("reader reassembled %d bytes, want %d", received, len(msg))
	}
}
