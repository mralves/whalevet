package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"

	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
)

// rewriteSnapshot captures the rules and cert files that apply to one h2c
// connection, so config reloads mid-build cannot change behavior mid-stream.
type rewriteSnapshot struct {
	edit func(content []byte) ([]byte, bool)
}

// snapshot builds the editing function for one h2c connection.
func (p *HTTPProxy) snapshot() *rewriteSnapshot {
	cfg := p.Config()
	inj, err := config.ExpandEnvFiles(cfg.Injections, p.configDir())
	if err != nil {
		log.Printf("[H2C] env_file expansion failed (%v), using unexpanded rules", err)
		inj = cfg.Injections
	}
	certs := loadCertFilesForTar(inj)
	s := &rewriteSnapshot{}
	s.edit = func(content []byte) ([]byte, bool) {
		out := image.ModifyInline(string(content), inj, certs)
		if out == string(content) {
			return content, false
		}
		return []byte(out), true
	}
	return s
}

// serveH2C turns an h2c upgrade connection into an HTTP/2 reverse proxy that
// rewrites gRPC-embedded Dockerfiles. Any failure to establish the upstream
// connection falls back to the raw tunnel, preserving current behavior.
func (p *HTTPProxy) serveH2C(clientConn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	// Establish the upstream connection FIRST so we never promise the client
	// a 101 we cannot deliver. The daemon speaks HTTP/2 by prior knowledge,
	// so a plain connect is enough.
	upConn, err := dialUpstream(p.dockerSocket)
	if err != nil {
		log.Printf("[H2C] daemon connect failed (%v), falling back to raw tunnel", err)
		p.tunnelUpgrade(clientConn, clientReader, req)
		return
	}
	defer upConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")); err != nil {
		log.Printf("[H2C] failed to send 101: %v", err)
		return
	}

	snap := p.snapshot()

	var shared net.Conn = upConn
	var sharedOnce sync.Once
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var c net.Conn
			sharedOnce.Do(func() {
				if shared != nil {
					c = shared
					shared = nil
				}
			})
			if c != nil {
				return c, nil
			}
			return dialUpstream(p.dockerSocket)
		},
		MaxReadFrameSize: 16 << 10,
	}
	defer tr.CloseIdleConnections()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.proxyH2CStream(w, r, tr, snap)
	})

	server := &http2.Server{
		MaxConcurrentStreams: 256,
	}

	// Some buildx clients send the `PRI * HTTP/2.0` preface in the same write
	// as the upgrade request, before our 101; consume it before ServeConn
	// starts scanning frames (RFC-style clients wait for our SETTINGS and are
	// unaffected by the bounded peek).
	consumeClientPreface(clientConn, clientReader)

	server.ServeConn(&replayConn{Conn: clientConn, r: clientReader}, &http2.ServeConnOpts{
		Handler:          h,
		SawClientPreface: true,
	})
	log.Printf("[H2C] downstream connection ended")
}

// proxyH2CStream proxies one gRPC stream to the daemon, rewriting the request
// body through the Dockerfile filter.
func (p *HTTPProxy) proxyH2CStream(w http.ResponseWriter, r *http.Request, tr *http2.Transport, snap *rewriteSnapshot) {
	req2 := r.Clone(r.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = "docker"
	req2.RequestURI = ""

	tgt := &rewriteTarget{method: r.URL.Path, editFile: snap.edit}
	filter := newGRPCRewriteReader(r.Body, tgt)
	req2.Body = filter
	req2.ContentLength = -1
	req2.GetBody = nil
	req2.Header.Del("Content-Length")
	req2.Header.Del("Transfer-Encoding")
	log.Printf("[H2C] stream %s %s", r.Method, r.URL.Path)

	resp, err := tr.RoundTrip(req2)
	if err != nil {
		log.Printf("[H2C] upstream RPC failed for %s: %v", r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Echo response headers, then stream the body and trailers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	trailerKeys := make([]string, 0, len(resp.Trailer))
	for k := range resp.Trailer {
		trailerKeys = append(trailerKeys, k)
	}
	if len(trailerKeys) > 0 {
		for _, k := range trailerKeys {
			w.Header().Add("Trailer", k)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			w.Header()[http.CanonicalHeaderKey(k)] = append(w.Header()[http.CanonicalHeaderKey(k)], v)
		}
	}
	log.Printf("[H2C] stream done %s status=%d trailers=%d", r.URL.Path, resp.StatusCode, len(resp.Trailer))
}
