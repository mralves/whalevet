package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mralves/whalevet/internal/cache"
	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
	"github.com/mralves/whalevet/internal/tarutil"
)

// loadCertFilesForTar reads cert files from ca_certificates injections and
// returns them keyed by basename for injection into the build context tar.
func loadCertFilesForTar(injections []config.Injection) map[string][]byte {
	files := map[string][]byte{}
	for _, inj := range injections {
		if inj.Type != "ca_certificates" {
			continue
		}
		for _, certPath := range inj.Certificates {
			content, err := os.ReadFile(certPath) //nolint:gosec // cert paths come from the local trusted config
			if err != nil {
				log.Printf("[HTTP] Warning: could not read cert %s: %v", certPath, err)
				continue
			}
			files[filepath.Base(certPath)] = content
		}
	}
	return files
}

type HTTPProxy struct {
	mu           sync.RWMutex
	config       *config.Config
	dockerSocket string
	dockerClient *image.DockerClient
	imageCache   *cache.ImageCache
}

func NewHTTPProxy(cfg *config.Config, dockerClient *image.DockerClient, imgCache *cache.ImageCache) *HTTPProxy {
	return &HTTPProxy{
		config:       cfg,
		dockerSocket: cfg.Proxy.DockerSocket,
		dockerClient: dockerClient,
		imageCache:   imgCache,
	}
}

// Config returns the current configuration, safe for concurrent use with
// SetConfig (config reload).
func (p *HTTPProxy) Config() *config.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// SetConfig swaps the active configuration (used for SIGHUP reloads); the
// docker socket and cache are kept as constructed.
func (p *HTTPProxy) SetConfig(cfg *config.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg
}

// configDir returns the directory of the config file (for resolving relative
// env_file paths), or the current directory when the config has no path.
func (p *HTTPProxy) configDir() string {
	if cfg := p.Config(); cfg.Path != "" {
		return filepath.Dir(cfg.Path)
	}
	return "."
}

// apiPath strips a Docker API version prefix (/v1.55/build -> /build).
// Returns the path unchanged when no version prefix is present.
func apiPath(p string) string {
	if len(p) < 2 || p[0] != '/' {
		return p
	}
	// Match /v<digits>.<digits>(/...)
	i := 1
	if i < len(p) && p[i] == 'v' {
		i++
		start := i
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			i++
		}
		if i > start && i < len(p) && p[i] == '.' {
			i++
			numStart := i
			for i < len(p) && p[i] >= '0' && p[i] <= '9' {
				i++
			}
			if i > numStart && i < len(p) && p[i] == '/' {
				return p[i:]
			}
		}
	}
	return p
}

// ServeConn handles one client connection. HTTP/1.1 requests are inspected
// (/build and /containers/create are intercepted, everything else forwarded).
// Anything else (HTTP/2, upgrades) is tunneled to the Docker socket untouched.
func (p *HTTPProxy) ServeConn(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	peek, err := reader.Peek(24)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("[PROXY] Failed to peek: %v", err)
		return
	}

	// HTTP/2 preface is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".
	if len(peek) >= 24 && string(peek[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		log.Printf("[PROXY] Detected HTTP/2 connection, tunneling raw")
		// Consume the peeked bytes from the reader (forwarded as prefix).
		preface := append([]byte(nil), peek[:24]...)
		if _, err := reader.Discard(24); err != nil {
			log.Printf("[PROXY] Failed to discard preface: %v", err)
			return
		}
		p.tunnelRaw(clientConn, preface, reader)
		return
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		peeked, _ := reader.Peek(reader.Buffered()) //nolint:errcheck // Peek on exactly the buffered count cannot block or fail
		log.Printf("[PROXY] Non-HTTP/1.1 connection, tunneling raw")
		p.tunnelRaw(clientConn, peeked, reader)
		return
	}

	log.Printf("[HTTP] %s %s", req.Method, req.URL.Path)

	// Strip API version prefix (/v1.55/build -> /build) for endpoint matching.
	// Forwarding preserves the original path; only matching is normalized.
	path := apiPath(req.URL.Path)

	// H2C upgrades (buildx /grpc and /session): rewrite Dockerfiles inside
	// gRPC envelopes when possible; other upgrades tunnel opaquely.
	if isUpgradeRequest(req) {
		if strings.EqualFold(req.Header.Get("Upgrade"), "h2c") {
			// The docker CLI's buildx session transport registers an active
			// session by hitting dockerd's /session route, which hijacks the
			// HTTP/1.1 connection and speaks HTTP/2 on it raw. Forward the
			// request so the daemon sees the X-Docker-Expose-Session-* metadata
			// and splice, or the session is never registered. DiffCopy-served
			// Dockerfiles are rewritten by the session splice.
			if req.URL.Path == "/session" {
				log.Printf("[PROXY] h2c upgrade request %s, proxying via session splice", req.URL.Path)
				p.serveSession(clientConn, reader, req)
				return
			}
			log.Printf("[PROXY] h2c upgrade request %s, proxying via gRPC filter", req.URL.Path)
			p.serveH2C(clientConn, reader, req)
			return
		}
		log.Printf("[PROXY] Upgrade request %s, tunneling raw", req.URL.Path)
		p.tunnelUpgrade(clientConn, reader, req)
		return
	}

	if req.Method == http.MethodPost && path == "/build" {
		p.handleBuildConn(clientConn, req)
		return
	}

	if req.Method == http.MethodPost && path == "/containers/create" {
		p.handleContainerCreateConn(clientConn, req)
		return
	}

	if req.Method == http.MethodPost && path == "/images/create" {
		p.handleImageCreateConn(clientConn, req)
		return
	}

	p.forwardHTTPConn(clientConn, req, nil)
}

// writePolicyDenial replies directly with a 403 carrying a Docker-style JSON
// error body, so the client surfaces a sensible message.
func writePolicyDenial(clientConn net.Conn, ref, reason string) {
	payload := map[string]string{
		"message": fmt.Sprintf("image %s blocked by whalevet policy: %s", ref, reason),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"message":"image blocked by whalevet policy"}`)
	}
	fmt.Fprintf(clientConn, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body) //nolint:errcheck
}

func isUpgradeRequest(r *http.Request) bool {
	upgrade := r.Header.Get("Upgrade")
	connection := r.Header.Get("Connection")
	return upgrade != "" && strings.Contains(strings.ToLower(connection), "upgrade")
}

// copyToThenClose copies src to dst and then closes dst, so a client or backend
// that hangs up early unblocks the reverse tunnel copy instead of leaving both
// copies blocked forever.
func copyToThenClose(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src) //nolint:errcheck // teardown is signalled by closing dst either way
	_ = dst.Close()
}

// tunnelUpgrade forwards the HTTP upgrade request then tunnels raw bytes.
func (p *HTTPProxy) tunnelUpgrade(clientConn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	backendConn, err := net.Dial("unix", p.dockerSocket)
	if err != nil {
		log.Printf("[PROXY] Failed to connect to docker: %v", err)
		return
	}
	defer backendConn.Close()

	if err := req.Write(backendConn); err != nil {
		log.Printf("[PROXY] Failed to forward upgrade request: %v", err)
		return
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("[PROXY] Failed to read downstream body: %v", err)
		}
		if len(body) > 0 {
			backendConn.Write(body)
		}
	}

	go copyToThenClose(backendConn, clientReader)
	io.Copy(clientConn, backendConn) //nolint:errcheck // client is closed by the copier / deferred Close
}

// tunnelRaw forwards already-read bytes, then copies bidirectionally.
func (p *HTTPProxy) tunnelRaw(clientConn net.Conn, prefix []byte, clientReader *bufio.Reader) {
	backendConn, err := net.Dial("unix", p.dockerSocket)
	if err != nil {
		log.Printf("[PROXY] Failed to connect to docker: %v", err)
		return
	}
	defer backendConn.Close()

	if len(prefix) > 0 {
		if _, err := backendConn.Write(prefix); err != nil {
			log.Printf("[PROXY] Failed to forward prefix: %v", err)
			return
		}
	}

	go copyToThenClose(backendConn, clientReader)
	io.Copy(clientConn, backendConn) //nolint:errcheck // client is closed by the copier / deferred Close
}

// forwardHTTPConn forwards an HTTP/1.1 request and returns the response.
func (p *HTTPProxy) forwardHTTPConn(clientConn net.Conn, req *http.Request, bodyOverride []byte) {
	backendConn, err := net.Dial("unix", p.dockerSocket)
	if err != nil {
		log.Printf("[PROXY] Failed to connect to docker: %v", err)
		return
	}
	defer backendConn.Close()

	var body []byte
	if bodyOverride != nil {
		body = bodyOverride
	} else if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		if err != nil {
			log.Printf("[PROXY] Failed to read request body: %v", err)
		}
		req.Body.Close()
	}

	// A hijack upgrade (attach, exec stdio) needs its Upgrade headers
	// preserved and, after a 101, the connection tunneled raw.
	hijack := req.Header.Get("Upgrade") != ""

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: localhost\r\n", req.Method, req.URL.RequestURI())
	for key, values := range req.Header {
		// Skip hop-by-hop headers and Content-Length (always recomputed
		// below; the body may have been replaced, changing its size).
		lower := strings.ToLower(key)
		if lower == "keep-alive" || lower == "transfer-encoding" || lower == "content-length" {
			continue
		}
		if lower == "connection" && !hijack {
			continue
		}
		for _, value := range values {
			b.WriteString(key + ": " + value + "\r\n")
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	if !hijack {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	reqStr := b.String()

	if _, err := backendConn.Write([]byte(reqStr)); err != nil {
		log.Printf("[PROXY] Failed to write request: %v", err)
		return
	}
	if len(body) > 0 {
		if _, err := backendConn.Write(body); err != nil {
			log.Printf("[PROXY] Failed to write body: %v", err)
			return
		}
	}

	backendReader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendReader, req)
	if err != nil {
		log.Printf("[PROXY] Failed to read response: %v", err)
		return
	}

	if hijack && resp.StatusCode == http.StatusSwitchingProtocols {
		// Hijacked stdio: forward the 101, then copy raw both ways until
		// either side closes. backendReader may already hold buffered
		// bytes, so copy from it rather than backendConn.
		log.Printf("[PROXY] Hijack established for %s %q", req.Method, req.URL.Path) //nolint:gosec // client-controlled; %q quotes control chars, sink is local stderr
		if err := resp.Write(clientConn); err != nil {
			log.Printf("[PROXY] Failed to write 101: %v", err)
			return
		}
		go copyToThenClose(backendConn, clientConn)
		io.Copy(clientConn, backendReader) //nolint:errcheck // teardown signalled by closing backendConn via the client-side copier
		return
	}

	defer resp.Body.Close()
	if err := resp.Write(clientConn); err != nil {
		log.Printf("[PROXY] Failed to write response: %v", err)
	}
}

func (p *HTTPProxy) handleBuildConn(clientConn net.Conn, req *http.Request) {
	log.Printf("[HTTP] Intercepting build request: %q", req.URL.RawQuery) //nolint:gosec // client-controlled; %q quotes control chars, sink is local stderr

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("[HTTP] Failed to read build request body: %v", err)
	}
	req.Body.Close()

	// Honor the `dockerfile` query param (docker build -f <name>).
	dockerfileName := req.URL.Query().Get("dockerfile")
	dockerfilePath, dockerfileContent, entries, err := tarutil.ExtractDockerfile(bytes.NewReader(body), dockerfileName)
	if err != nil {
		log.Printf("[HTTP] Failed to extract dockerfile: %v, passing through", err)
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	if dockerfileContent == "" {
		log.Printf("[HTTP] No Dockerfile found, passing through")
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	log.Printf("[HTTP] Found Dockerfile at %q (%d bytes)", dockerfilePath, len(dockerfileContent)) //nolint:gosec // client-controlled; %q quotes control chars, sink is local stderr
	cfg := p.Config()
	inj, err := config.ExpandEnvFiles(cfg.Injections, p.configDir())
	if err != nil {
		log.Printf("[HTTP] env_file expansion failed (%v), using unexpanded rules", err)
		inj = cfg.Injections
	}
	modifiedContent := image.Modify(dockerfileContent, inj)
	log.Printf("[HTTP] Modified (%d -> %d bytes)", len(dockerfileContent), len(modifiedContent)) //nolint:gosec // byte-length counters, not client-controlled strings

	extraFiles := loadCertFilesForTar(inj)
	newTar := tarutil.RebuildTar(entries, dockerfilePath, modifiedContent, extraFiles)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, newTar); err != nil {
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	audit("build", "dockerfile", dockerfilePath, "rules", len(inj), "bytes_before", len(dockerfileContent), "bytes_after", len(modifiedContent))
	p.forwardHTTPConn(clientConn, req, buf.Bytes())
}

// replaceImage returns a copy of a container-create body with Image replaced,
// preserving every other field byte-for-byte (UseNumber keeps large ints and
// exponent-free literals intact; plain map decode would lossy-convert them
// through float64 and the daemon rejects the result).
func replaceImage(body []byte, image string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["Image"] = image
	return json.Marshal(m)
}

func (p *HTTPProxy) handleContainerCreateConn(clientConn net.Conn, req *http.Request) {
	log.Printf("[HTTP] Intercepting container create")

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("[HTTP] Failed to read container create body: %v", err)
	}
	req.Body.Close()

	var imageReq struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(body, &imageReq); err != nil || imageReq.Image == "" {
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	if allowed, reason := policyAllowed(p.Config(), imageReq.Image); !allowed {
		log.Printf("[HTTP] Policy denied image %q: %s", imageReq.Image, reason)
		audit("create_denied", "image", imageReq.Image, "reason", reason)
		writePolicyDenial(clientConn, imageReq.Image, reason)
		return
	}

	cfg := p.Config()
	var certInjection *config.Injection
	for _, inj := range cfg.Injections {
		if inj.Type == "ca_certificates" {
			certInjection = &inj
			break
		}
	}
	if certInjection == nil {
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	if proxyRef := p.imageCache.ProxyRefFor(imageReq.Image); proxyRef != "" {
		log.Printf("[HTTP] Image %s already intercepted, using %s", imageReq.Image, proxyRef)
		audit("container_create", "image", imageReq.Image, "proxy_ref", proxyRef, "cached", true)
		newBody, err := replaceImage(body, proxyRef)
		if err != nil {
			p.forwardHTTPConn(clientConn, req, body)
			return
		}
		p.forwardHTTPConn(clientConn, req, newBody)
		return
	}

	certContents := make(map[string][]byte)
	for _, certPath := range certInjection.Certificates {
		content, err := os.ReadFile(certPath) //nolint:gosec // cert paths come from the local trusted config
		if err != nil {
			log.Printf("[HTTP] Warning: could not read cert %s: %v", certPath, err)
			continue
		}
		certContents[certPath] = content
	}

	if len(certContents) == 0 {
		log.Printf("[HTTP] No cert files loaded, passing through")
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	// Certs are injected via the container archive API inside internal/image.
	caRules, err := config.ExpandEnvFiles(cfg.Injections, p.configDir())
	if err != nil {
		log.Printf("[HTTP] env_file expansion failed (%v), using unexpanded rules", err)
		caRules = cfg.Injections
	}
	var certRules []config.Injection
	for _, inj := range caRules {
		if inj.Type == "ca_certificates" {
			certRules = append(certRules, inj)
		}
	}
	proxyRef, err := image.InjectCertsViaCommit(p.dockerClient, imageReq.Image, certContents, certRules)
	if err != nil {
		log.Printf("[HTTP] Failed to inject certs: %v, passing through", err)
		p.forwardHTTPConn(clientConn, req, body)
		return
	}

	var certContentsList [][]byte
	for _, v := range certContents {
		certContentsList = append(certContentsList, v)
	}
	p.imageCache.Set(imageReq.Image, proxyRef, certContentsList)

	log.Printf("[HTTP] Replacing image %s with %s", imageReq.Image, proxyRef)
	audit("container_create", "image", imageReq.Image, "proxy_ref", proxyRef, "cached", false, "certs", len(certContentsList))
	newBody, err := replaceImage(body, proxyRef)
	if err != nil {
		p.forwardHTTPConn(clientConn, req, body)
		return
	}
	p.forwardHTTPConn(clientConn, req, newBody)
}

// handleImageCreateConn intercepts image pulls (POST /images/create). The
// policy allow/deny lists are evaluated against the requested reference; a
// denied image is answered with 403 instead of being forwarded to the daemon.
func (p *HTTPProxy) handleImageCreateConn(clientConn net.Conn, req *http.Request) {
	q := req.URL.Query()
	fromImage := q.Get("fromImage")
	tag := q.Get("tag")
	ref := fromImage
	if tag != "" {
		ref = fromImage + ":" + tag
	}

	log.Printf("[HTTP] Intercepting image create: %q", ref) //nolint:gosec // client-controlled; %q quotes control chars, sink is local stderr
	if allowed, reason := policyAllowed(p.Config(), ref); !allowed {
		log.Printf("[HTTP] Policy denied image %q: %s", ref, reason) //nolint:gosec
		audit("pull_denied", "image", ref, "reason", reason)
		writePolicyDenial(clientConn, ref, reason)
		return
	}

	p.forwardHTTPConn(clientConn, req, nil)
}
