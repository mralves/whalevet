package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // OpenSSL X509_NAME_hash (c_rehash) mandates SHA1
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/mralves/whalevet/internal/cache"
	"github.com/mralves/whalevet/internal/config"
)

type DockerClient struct {
	httpClient *http.Client
	socketPath string
}

func NewDockerClient(socketPath string) *DockerClient {
	return &DockerClient{
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
		socketPath: socketPath,
	}
}

type ContainerCreateResponse struct {
	Id       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

type ImageInspectResponse struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env,omitempty"`
	} `json:"Config"`
}

// HasProxyLabel checks if an image has the proxy injected label
func HasProxyLabel(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	return labels[cache.ProxyLabelKey] == "true"
}

// Well-known single-file CA bundles, probed in order. The first existing one
// wins; when none exist the first entry is created. Probed instead of
// OS-detected so no guest shell is needed (works on distroless/chiselled).
var bundleCandidates = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora/CentOS/Rocky/AlmaLinux
	"/etc/ssl/ca-bundle.pem",             // SUSE
}

// extraBundles are standalone bundle files pinned by specific images
// (e.g. curlimages/curl reads CURL_CA_BUNDLE=/cacert.pem). Extended when
// present, never created.
var extraBundles = []string{
	"/cacert.pem",
	"/etc/ssl/cert.pem",
}

// certBlob is one CA certificate: raw PEM text plus parsed DER
// (DER empty when unparseable; raw bytes are still appended).
type certBlob struct {
	raw []byte
	der []byte
}

func parseCerts(certFiles map[string][]byte) []certBlob {
	var out []certBlob
	for src, raw := range certFiles {
		var found bool
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			out = append(out, certBlob{raw: pem.EncodeToMemory(block), der: block.Bytes})
			found = true
		}
		if !found {
			if _, err := x509.ParseCertificate(raw); err == nil {
				out = append(out, certBlob{raw: raw, der: raw})
				found = true
			}
		}
		if !found {
			log.Printf("[commit] warning: skipping unparseable cert %s", src)
		}
	}
	return out
}

// bundleDERs returns the DER bytes of every certificate in a bundle.
func bundleDERs(bundle []byte) [][]byte {
	var out [][]byte
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	return out
}

// opensslSubjectHash returns the OpenSSL c_rehash link name (xxxxxxxx.0)
// for a certificate: hex of the first 4 SHA1(DER subject) bytes,
// little-endian assembled, matching X509_NAME_hash.
func opensslSubjectHash(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(cert.RawSubject) //nolint:gosec // legacy X509_NAME_hash
	return fmt.Sprintf("%08x.0", binary.LittleEndian.Uint32(sum[:4])), nil
}

// InjectCertsViaCommit creates a temporary container from the image, extends
// its CA bundles with the given certificates purely through the archive API
// (no shell, no package manager, no user tricks; works on distroless and
// chiselled images), and commits the result. The committed image's config is
// updated with the trust env vars (pointing at the extended bundle) plus any
// ca_certificates rule env, so the running container environment matches the
// env baked into images at build time. Returns the new image ref, or the
// original ref when it already contains the certificates.
func InjectCertsViaCommit(client *DockerClient, originalRef string, certFiles map[string][]byte, caRules []config.Injection) (string, error) {
	proxyRef := cache.MakeProxyRef(originalRef)

	inspect, err := inspectImage(client, originalRef)
	if err != nil {
		return "", fmt.Errorf("inspect image: %w", err)
	}

	if HasProxyLabel(inspect.Config.Labels) {
		return originalRef, nil
	}

	blobs := parseCerts(certFiles)
	if len(blobs) == 0 {
		return "", errors.New("no parseable certificates")
	}

	containerID, err := createTempContainer(client, originalRef, inspect)
	if err != nil {
		return "", fmt.Errorf("create temp container: %w", err)
	}
	defer removeContainer(client, containerID)

	changed, verified, bundlePath, err := extendBundles(client, containerID, blobs)
	if err != nil {
		return "", err
	}
	if !changed {
		if verified {
			log.Printf("[commit] image %s already contains the certificates", originalRef)
			return originalRef, nil
		}
		return "", fmt.Errorf("no usable CA store found in image %s", originalRef)
	}

	env := buildCommittedEnv(inspect.Config.Env, bundlePath, caRules)
	if err := commitContainer(client, containerID, proxyRef, originalRef, env); err != nil {
		return "", fmt.Errorf("commit container: %w", err)
	}

	return proxyRef, nil
}

// buildCommittedEnv merges the image config env with the trust vars pointing
// at the extended bundle plus the rendered ca_certificates rule env.
func buildCommittedEnv(imageEnv []string, bundlePath string, caRules []config.Injection) []string {
	var vars []string
	if bundlePath != "" {
		vars = append(vars, caCertEnvVars(bundlePath, filepath.Dir(bundlePath))...)
	}
	ctx := EnvContext{
		BundlePath: bundlePath,
		TrustDir:   filepath.Dir(bundlePath),
	}
	for _, rule := range caRules {
		vars = append(vars, renderEnvKVs(sortedEnvLines(rule.Env), ctx)...)
	}
	return mergeEnv(imageEnv, vars)
}

// anchorDirs are drop-in directories honored by the distros' update tools.
// Dropping our .crt files here as well means a later in-container
// update-ca-certificates / update-ca-trust regenerates WITH our certs.
var anchorDirs = []string{
	"/usr/local/share/ca-certificates",          // Debian/Ubuntu/Alpine
	"/etc/pki/ca-trust/source/anchors",          // RHEL/Fedora/CentOS/Rocky/AlmaLinux
	"/etc/ca-certificates/trust-source/anchors", // Arch
	"/usr/share/pki/trust/anchors",              // SUSE
}

// extendBundles appends missing certs to every existing system bundle (plus
// hash links), drops .crt files into existing anchor dirs, creates the
// default bundle when nothing exists, and extends present standalone
// bundles. Reports whether anything changed and the resolved path of the
// system bundle that received the certs (target of the first existing
// candidate; the created default when none existed). Symlinked bundle paths
// are followed to their targets.
func extendBundles(client *DockerClient, containerID string, blobs []certBlob) (changed, verified bool, bundlePath string, err error) {
	extend := func(bundlePath string, createDirs bool) (realPath string, err error) {
		realPath, content, exists, err := readBundleFile(client, containerID, bundlePath)
		if err != nil {
			return "", err
		}
		if !exists {
			if !createDirs {
				return "", nil
			}
			realPath = bundlePath
			content = nil
		} else {
			verified = true
		}

		known := bundleDERs(content)
		type missing struct {
			raw []byte
			der []byte
		}
		var miss []missing
		for _, b := range blobs {
			if len(b.der) == 0 {
				miss = append(miss, missing(b))
				continue
			}
			seen := false
			for _, d := range known {
				if bytes.Equal(d, b.der) {
					seen = true
					break
				}
			}
			if !seen {
				miss = append(miss, missing(b))
			}
		}
		if len(miss) == 0 {
			return realPath, nil
		}

		var buf bytes.Buffer
		buf.Write(content)
		links := map[string]string{}
		for _, m := range miss {
			buf.Write(m.raw)
			if !bytes.HasSuffix(m.raw, []byte("\n")) {
				buf.WriteByte('\n')
			}
			if len(m.der) > 0 {
				if h, err := opensslSubjectHash(m.der); err == nil {
					links[h] = path.Base(realPath)
				}
			}
		}
		files := map[string][]byte{path.Base(realPath): buf.Bytes()}
		if err := putFiles(client, containerID, path.Dir(realPath), files, links, !exists); err != nil {
			return "", err
		}
		changed = true
		return realPath, nil
	}

	// Drop .crt copies into existing anchor dirs so later in-container
	// update-ca-certificates / update-ca-trust runs keep our certs.
	dropAnchors := func() error {
		names := map[string][]byte{}
		for _, b := range blobs {
			if len(b.der) == 0 {
				continue
			}
			h, err := opensslSubjectHash(b.der)
			if err != nil {
				continue
			}
			_ = h
			names["proxy-"+hex.EncodeToString(b.der[:8])+".crt"] = b.raw
		}
		if len(names) == 0 {
			return nil
		}
		for _, dir := range anchorDirs {
			if _, exists, err := getArchive(client, containerID, dir); err != nil || !exists {
				continue
			}
			files := maps.Clone(names)
			if err := putFiles(client, containerID, dir, files, nil, false); err != nil {
				log.Printf("[commit] warning: anchors drop to %s failed: %v", dir, err)
				continue
			}
		}
		return nil
	}

	var chosen string
	for _, p := range bundleCandidates {
		rp, err := extend(p, false)
		if err != nil {
			return false, false, "", err
		}
		if chosen == "" && rp != "" {
			chosen = rp
		}
	}
	if !verified {
		// No usable system bundle anywhere: create the default one.
		rp, err := extend(bundleCandidates[0], true)
		if err != nil {
			return false, false, "", err
		}
		chosen = rp
	}
	for _, p := range extraBundles {
		if _, err := extend(p, false); err != nil {
			return false, false, "", err
		}
	}
	if err := dropAnchors(); err != nil {
		return false, false, "", err
	}
	return changed, verified, chosen, nil
}

// readBundleFile fetches a bundle path, following symlinks (distros commonly
// link /etc/ssl/certs/ca-certificates.crt at the real store). Returns the
// resolved path, its content, and whether it exists.
func readBundleFile(client *DockerClient, containerID, bundlePath string) (realPath string, content []byte, exists bool, err error) {
	seen := map[string]bool{}
	p := bundlePath
	for range 5 {
		if seen[p] {
			return "", nil, false, fmt.Errorf("symlink loop at %s", p)
		}
		seen[p] = true
		tarBytes, ok, err := getArchive(client, containerID, p)
		if err != nil {
			return "", nil, false, err
		}
		if !ok {
			return "", nil, false, nil
		}
		name, data, isLink, linkTarget, isReg := tarFirstEntry(tarBytes)
		_ = name
		if isLink {
			target := linkTarget
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(p), target)
			}
			log.Printf("[commit] following symlink %s -> %s", p, target)
			p = target
			continue
		}
		if !isReg {
			return "", nil, false, nil
		}
		return p, data, true, nil
	}
	return "", nil, false, fmt.Errorf("too many symlink levels at %s", bundlePath)
}

// tarFirstEntry describes the first tar entry: name, content (regular files),
// link target (symlinks), and kind flags.
func tarFirstEntry(tarBytes []byte) (name string, data []byte, isLink bool, linkTarget string, isReg bool) {
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	hdr, err := tr.Next()
	if err != nil {
		return "", nil, false, "", false
	}
	switch hdr.Typeflag {
	case tar.TypeReg:
		data, err = io.ReadAll(tr)
		if err != nil {
			return "", nil, false, "", false
		}
		return hdr.Name, data, false, "", true
	case tar.TypeSymlink:
		return hdr.Name, nil, true, hdr.Linkname, false
	default:
		return hdr.Name, nil, false, "", false
	}
}

// putFiles writes files (+ symlinks) under dir via one PUT. Parent dirs are
// included only when createDirs (never touching existing directories).
func putFiles(client *DockerClient, containerID, dir string, files map[string][]byte, links map[string]string, createDirs bool) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if createDirs {
		var acc strings.Builder
		for p := range strings.SplitSeq(strings.Trim(dir, "/"), "/") {
			acc.WriteByte('/')
			acc.WriteString(p)
			rel := strings.TrimPrefix(acc.String(), "/")
			if err := tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				return err
			}
		}
	}
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}
	for name, target := range links {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: target}); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("http://localhost/containers/%s/archive?path=%s", containerID, url.QueryEscape(dir)),
		&buf,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put archive %s returned %d: %s", dir, resp.StatusCode, string(b))
	}
	return nil
}

// getArchive fetches path from the container, returning tar bytes and whether
// the path exists (missing path yields exists=false, nil error).
func getArchive(client *DockerClient, containerID, containerPath string) (tarBytes []byte, exists bool, err error) {
	resp, err := client.httpClient.Get(fmt.Sprintf("http://localhost/containers/%s/archive?path=%s", containerID, url.QueryEscape(containerPath)))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("get archive %s returned %d: %s", containerPath, resp.StatusCode, string(b))
	}
	tarBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return tarBytes, true, nil
}

func inspectImage(client *DockerClient, ref string) (*ImageInspectResponse, error) {
	resp, err := client.httpClient.Get(fmt.Sprintf("http://localhost/images/%s/json", ref))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("inspect returned %d: %s", resp.StatusCode, string(body))
	}

	var inspect ImageInspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return nil, err
	}
	return &inspect, nil
}

func createTempContainer(client *DockerClient, imageRef string, inspect *ImageInspectResponse) (string, error) {
	payload := map[string]any{
		"Image": imageRef,
		"Labels": map[string]string{
			cache.ProxyLabelKey:    "temp",
			cache.ProxyOriginalKey: imageRef,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	resp, err := client.httpClient.Post(
		"http://localhost/containers/create",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create returned %d: %s", resp.StatusCode, string(b))
	}

	var createResp ContainerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return "", err
	}
	return createResp.Id, nil
}

// splitRef splits "repo[:tag]" (tag defaults to latest). Digest refs are
// stripped to repo:latest since a digest cannot be a commit target name.
func splitRef(ref string) (repo, tag string) {
	if i := strings.LastIndex(ref, "@"); i != -1 {
		ref = ref[:i]
	}
	repo, tag = ref, "latest"
	if i := strings.LastIndex(ref, ":"); i != -1 && !strings.Contains(ref[i:], "/") {
		repo, tag = ref[:i], ref[i+1:]
		if tag == "" {
			tag = "latest"
		}
	}
	return repo, tag
}

func commitContainer(client *DockerClient, containerID, newRef, originalRef string, env []string) error {
	repo, tag := splitRef(newRef)
	query := url.Values{}
	query.Set("container", containerID)
	query.Set("repo", repo)
	query.Set("tag", tag)

	payload := map[string]any{
		"Labels": map[string]string{
			cache.ProxyLabelKey:    "true",
			cache.ProxyOriginalKey: originalRef,
		},
	}
	if len(env) > 0 {
		payload["Config"] = map[string]any{"Env": env}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := client.httpClient.Post(
		"http://localhost/commit?"+query.Encode(),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("commit returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func removeContainer(client *DockerClient, containerID string) {
	req, _ := http.NewRequest(
		http.MethodDelete,
		fmt.Sprintf("http://localhost/containers/%s?force=true", containerID),
		nil,
	)
	resp, err := client.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
