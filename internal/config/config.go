package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

const (
	DefaultListen       = "unix:///tmp/whalevet/docker.sock"
	DefaultDockerSocket = "/var/run/docker.sock"
	DefaultFrontendTag  = "whalevet:latest"
)

type Config struct {
	Proxy      ProxyConfig    `toml:"proxy" mapstructure:"proxy"`
	BuildKit   BuildKitConfig `toml:"buildkit" mapstructure:"buildkit"`
	Policy     PolicyConfig   `toml:"policy,omitempty" mapstructure:"policy"`
	Injections []Injection    `toml:"injections,omitempty" mapstructure:"injections"`
	// Path is the absolute path of the loaded config file. Never persisted
	// (Load records it so consumers can resolve relative paths like env_file
	// against the config's directory).
	Path string `toml:"-" mapstructure:"-"`
}

type ProxyConfig struct {
	Listen       string `toml:"listen,omitempty" mapstructure:"listen"`
	DockerSocket string `toml:"docker_socket,omitempty" mapstructure:"docker_socket"`
}

type BuildKitConfig struct {
	FrontendTag string `toml:"frontend_tag,omitempty" mapstructure:"frontend_tag"`
}

// PolicyConfig holds image reference allow/deny patterns applied to pulls
// and container creates at the proxy. When Allow is non-empty, a ref must
// match at least one Allow pattern; a match against any Deny pattern always
// blocks regardless of Allow.
type PolicyConfig struct {
	Allow []string `toml:"allow,omitempty" mapstructure:"allow"`
	Deny  []string `toml:"deny,omitempty" mapstructure:"deny"`
}

type Injection struct {
	Type         string            `toml:"type" mapstructure:"type"`
	Certificates []string          `toml:"certificates,omitempty" mapstructure:"certificates"`
	Command      string            `toml:"command,omitempty" mapstructure:"command"`
	Position     string            `toml:"position,omitempty" mapstructure:"position"`
	Pattern      string            `toml:"pattern,omitempty" mapstructure:"pattern"`
	Replacement  string            `toml:"replacement,omitempty" mapstructure:"replacement"`
	Env          map[string]string `toml:"env,omitempty" mapstructure:"env"`
	// EnvFile points to a file of KEY=VALUE lines merged into Env. Any key
	// also set explicitly in Env keeps the inline value.
	EnvFile string `toml:"env_file,omitempty" mapstructure:"env_file"`
}

// ResolvePath turns a config path into an absolute path that must exist.
// Relative paths are tried against the current working directory first,
// then against the executable's directory (service managers often run with
// an unrelated CWD, which silently breaks bare relative paths).
func ResolvePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err != nil {
			return "", err
		}
		return path, nil
	}
	if abs, err := filepath.Abs(path); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		abs := filepath.Join(filepath.Dir(exe), path)
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}
	return "", fmt.Errorf("config file %q not found in working directory or executable directory", path)
}

// Load resolves path and parses the TOML config. Decoding goes through
// go-toml directly instead of viper: viper lowercases every map key, which
// would mangle case-sensitive env var names (the Injection.Env values emitted
// into images must keep their exact casing, e.g. HTTPS_PROXY or PIP_CERT).
func Load(path string) (*Config, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(resolved) //nolint:gosec // config path comes from the user's CLI flag, not remote input
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", resolved, err)
	}
	cfg.Path = resolved
	applyDefaults(&cfg)

	return &cfg, nil
}

// Write serializes cfg to TOML at path. The config directory is created if
// it does not exist yet. Uses go-toml directly (same casing reasons as Load).
func Write(path string, cfg *Config) error {
	b, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

// applyDefaults replaces empty proxy values with the built-in defaults.
func applyDefaults(cfg *Config) {
	if cfg.Proxy.Listen == "" {
		cfg.Proxy.Listen = DefaultListen
	}
	if cfg.Proxy.DockerSocket == "" {
		cfg.Proxy.DockerSocket = DefaultDockerSocket
	}
	if cfg.BuildKit.FrontendTag == "" {
		cfg.BuildKit.FrontendTag = DefaultFrontendTag
	}
}
