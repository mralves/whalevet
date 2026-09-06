package frontend

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
)

//go:embed assets/Dockerfile
var embeddedDockerfile string

// BuiltAtLabel is the OCI image label recording the unix second at which a
// frontend image was built. setup uses it to rebuild only when the config file
// is newer than the image.
const BuiltAtLabel = "com.whalevet.built-at"

// dockerEnv returns the process environment for a docker CLI subprocess, with
// DOCKER_HOST adjusted so setup's own build/inspect calls never route through
// the proxy. When the inherited DOCKER_HOST points at the proxy's own listen
// socket (exported into the shell rc by a previous setup, but the proxy may
// not be running yet or may be mid-restart), it is cleared so the CLI falls
// back to its default endpoint; any other DOCKER_HOST is preserved as-is.
func dockerEnv(proxyListen string) []string {
	env := os.Environ()
	value, key, ok := findEnv(env, "DOCKER_HOST")
	if !ok || value == "" {
		return env
	}
	if sockPath(proxyListen) != sockPath(value) {
		return env
	}
	return append(append(env[:key], env[key+1:]...), "DOCKER_HOST=")
}

// CliEnv returns the environment for a docker CLI subprocess, neutralizing a
// DOCKER_HOST that points at the proxy's own listen socket. Exported for the
// operator commands (setup/build/uninstall/prune) so their docker calls never
// route through the possibly-stale or mid-restart proxy socket.
func CliEnv(proxyListen string) []string {
	return dockerEnv(proxyListen)
}

// findEnv locates a VAR=VALUE entry and returns its value, its index, and
// whether it was present.
func findEnv(env []string, name string) (value string, index int, ok bool) {
	prefix := name + "="
	for i, kv := range env {
		if rest, found := strings.CutPrefix(kv, prefix); found {
			return rest, i, true
		}
	}
	return "", -1, false
}

// sockPath reduces a DOCKER_HOST-style endpoint ("unix:///path" or a bare
// "/path") to its socket path for comparison.
func sockPath(host string) string {
	rest, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		return host
	}
	return rest
}

// BuildImage builds the whalevet wrapper frontend image, baking the
// injection rules and certificate contents from the given config.
//
// tag:          image tag to produce (e.g. whalevet:latest).
// frontendDir:  optional directory containing a frontend Dockerfile override.
//
//	When empty, the embedded wrapper Dockerfile is used; the repo
//	root (go.mod) is found by walking up from the current and
//	executable directories.
//
// cfgPath:      path to the proxy config file (used for rules + certs).
//
// The produced image is the BuildKit `# syntax=` target: its entrypoint runs
// this binary's `frontend` gateway command (Build).
func BuildImage(tag, frontendDir, cfgPath string) error {
	resolved, err := config.ResolvePath(cfgPath)
	if err != nil {
		return fmt.Errorf("resolve config path %q: %w", cfgPath, err)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		return fmt.Errorf("load config %q: %w", resolved, err)
	}
	rules, err := config.ExpandEnvFiles(cfg.Injections, filepath.Dir(resolved))
	if err != nil {
		return fmt.Errorf("expand env_file rules: %w", err)
	}

	dfPath, cleanup, err := resolveDockerfile(frontendDir)
	if err != nil {
		return err
	}
	defer cleanup()

	repoRoot, err := findRepoRoot(frontendDir)
	if err != nil {
		return err
	}

	certContents, err := loadCertContents(rules)
	if err != nil {
		return err
	}

	rulesJSON, certsJSON, err := encodeBuildArgs(rules, certContents)
	if err != nil {
		return err
	}

	log.Printf("Building frontend image %s with Dockerfile %s", tag, dfPath)
	log.Printf("Baking %d injection rules and %d CA certificates", len(rules), len(certContents))

	cmd := exec.Command("docker", "build", //nolint:gosec // running docker is the tool's purpose; args come from the trusted config
		"-t", tag,
		"-f", dfPath,
		"--build-arg", "RULES_JSON="+rulesJSON,
		"--build-arg", "CERTS_JSON="+certsJSON,
		"--label", BuiltAtLabel+"="+strconv.FormatInt(time.Now().Unix(), 10),
		repoRoot,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = dockerEnv(cfg.Proxy.Listen)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build failed: %w", err)
	}
	return nil
}

// ImageBuiltAt returns the unix-second build stamp of the given image tag, or
// an error when the image or its built-at label is missing.
func ImageBuiltAt(tag, proxyListen string) (int64, error) {
	cmd := exec.Command("docker", "image", "inspect", //nolint:gosec // label lookup for the operator-supplied fixed tag
		tag, "--format", `{{ index .Config.Labels "`+BuiltAtLabel+`" }}`)
	cmd.Env = dockerEnv(proxyListen)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	stamp := strings.TrimSpace(string(out))
	if stamp == "" {
		return 0, errors.New("image has no built-at label")
	}
	ts, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse built-at label %q: %w", stamp, err)
	}
	return ts, nil
}

func loadCertContents(injections []config.Injection) (map[string][]byte, error) {
	out := make(map[string][]byte)
	for _, inj := range injections {
		if inj.Type != "ca_certificates" {
			continue
		}
		for _, p := range inj.Certificates {
			content, err := os.ReadFile(p) //nolint:gosec // cert paths come from the local trusted config
			if err != nil {
				return nil, fmt.Errorf("read certificate %q: %w", p, err)
			}
			name := image.CertTargetName(p)
			out[name] = content
		}
	}
	return out, nil
}

func encodeBuildArgs(rules []config.Injection, certContents map[string][]byte) (string, string, error) {
	rulesBytes, err := json.Marshal(rules)
	if err != nil {
		return "", "", fmt.Errorf("marshal rules: %w", err)
	}

	certB64Map := make(map[string]string, len(certContents))
	for name, content := range certContents {
		certB64Map[name] = base64.StdEncoding.EncodeToString(content)
	}
	certsBytes, err := json.Marshal(certB64Map)
	if err != nil {
		return "", "", fmt.Errorf("marshal certs: %w", err)
	}

	return base64.StdEncoding.EncodeToString(rulesBytes),
		base64.StdEncoding.EncodeToString(certsBytes), nil
}

// resolveDockerfile returns the path to the wrapper Dockerfile to build with.
// When frontendDir is empty, the embedded copy is written to a temp dir (the
// cleanup func removes it); otherwise the Dockerfile inside frontendDir is
// used.
func resolveDockerfile(frontendDir string) (path string, cleanup func(), err error) {
	if frontendDir != "" {
		p := filepath.Join(frontendDir, "Dockerfile")
		if _, statErr := os.Stat(p); statErr != nil {
			return "", nil, fmt.Errorf("frontend Dockerfile not found in %q: %w", frontendDir, statErr)
		}
		return p, func() {}, nil
	}
	dir, mkErr := os.MkdirTemp("", "whalevet")
	if mkErr != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", mkErr)
	}
	p := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(p, []byte(embeddedDockerfile), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("write embedded Dockerfile: %w", err)
	}
	return p, func() { os.RemoveAll(dir) }, nil
}

// findRepoRoot locates the repository root containing go.mod. With a
// non-empty dir (a custom frontend directory) it walks up from there;
// otherwise it walks up from the current directory, falling back to the
// executable's directory (service managers often run with a bare CWD).
func findRepoRoot(dir string) (string, error) {
	if dir != "" {
		root, err := walkForGoMod(dir)
		if err != nil {
			return "", fmt.Errorf("repo root (go.mod) not found above %q", dir)
		}
		return root, nil
	}
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, c := range candidates {
		if root, err := walkForGoMod(c); err == nil {
			return root, nil
		}
	}
	return "", errors.New("repo root (go.mod) not found above current or executable directory")
}

// walkForGoMod walks up from dir looking for a directory containing go.mod.
func walkForGoMod(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path %q: %w", dir, err)
	}
	for cur := abs; cur != "/" && cur != filepath.VolumeName(cur)+"\\"; cur = filepath.Dir(cur) {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur, nil
		}
	}
	return "", fmt.Errorf("go.mod not found above %q", dir)
}
