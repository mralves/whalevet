package proxy

import (
	"bufio"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// replayConn is a net.Conn whose Read first serves bytes already buffered
// by a bufio.Reader (an HTTP/2 preface + early frames on the client side, or
// a daemon SETTINGS frame after a 101), then falls through to the underlying
// connection. Writes go straight to the conn.
type replayConn struct {
	net.Conn
	mu sync.Mutex
	r  *bufio.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

// dialUpstream opens a plain connection to the daemon socket. The daemon
// speaks HTTP/2 by prior knowledge on the wire (a client preface + SETTINGS
// immediately handshake the connection), so no HTTP/1.1 upgrade round-trip is
// involved; the http2 client we hand the connection to performs that itself.
func dialUpstream(socket string) (net.Conn, error) {
	return net.Dial("unix", socket)
}

// consumeClientPreface drains a `PRI * HTTP/2.0` preface that a buildx client
// may have already sent on an upgraded connection (in the same write as the
// upgrade request, before our 101). It must be consumed before the local
// frame scanner / H2 server starts. A short bounded peek is invisible to
// clients that wait for our server SETTINGS.
func consumeClientPreface(conn net.Conn, r *bufio.Reader) {
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if b, err := r.Peek(len(http2.ClientPreface)); err == nil && string(b) == http2.ClientPreface {
		log.Printf("[PROXY] consuming client PRI preface")
		_, _ = r.Discard(len(http2.ClientPreface))
	}
	_ = conn.SetReadDeadline(time.Time{})
}
