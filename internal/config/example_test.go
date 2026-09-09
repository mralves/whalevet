package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExampleTomlValid guards config-example.toml: it must parse with the real
// Load path and preserve the exact env var casing documented there.
func TestExampleTomlValid(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "config-example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("config-example.toml failed to parse: %v", err)
	}
	if len(cfg.Injections) != 7 {
		t.Fatalf("expected 7 injections, got %d", len(cfg.Injections))
	}
	ca := cfg.Injections[0]
	if ca.Type != "ca_certificates" {
		t.Fatalf("expected first rule ca_certificates, got %q", ca.Type)
	}
	if v := ca.Env["GIT_SSL_CAINFO"]; v != "{{.BundlePath}}" {
		t.Fatalf("template value not preserved with original casing: %+v", ca.Env)
	}
	if _, ok := ca.Env["HTTPS_PROXY"]; ok {
		t.Fatalf("unexpected key in ca rule: %+v", ca.Env)
	}
	envRule := cfg.Injections[5]
	if envRule.Type != "env" {
		t.Fatalf("expected injections[5] to be the env rule, got %q", envRule.Type)
	}
	// viper lowercases map keys when unmarshalling; env var names are
	// case-sensitive at runtime, so they must survive the round trip as-is.
	if v := envRule.Env["HTTPS_PROXY"]; v != "http://proxy.internal:8080" {
		t.Fatalf("env key casing not preserved (HTTPS_PROXY): %+v", envRule.Env)
	}
	if v := envRule.Env["NO_PROXY"]; v != "localhost,127.0.0.1" {
		t.Fatalf("env key casing not preserved (NO_PROXY): %+v", envRule.Env)
	}
}

// TestWriteRoundTripEnvCase guards the setup path as well: configs written by
// Write (whalevet setup) must keep env var casing.
func TestWriteRoundTripEnvCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	src := &Config{
		Proxy: ProxyConfig{
			Listen:       DefaultListen,
			DockerSocket: "/var/run/docker.sock",
		},
		Injections: []Injection{
			{
				Type:         "ca_certificates",
				Certificates: []string{"/etc/ssl/certs/corp-root.pem"},
				Env: map[string]string{
					"GIT_SSL_CAINFO": "{{.BundlePath}}",
					"PIP_CERT":       "{{.BundlePath}}",
				},
			},
		},
	}
	if err := Write(path, src); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Injections) != 1 || got.Injections[0].Type != "ca_certificates" {
		t.Fatalf("roundtrip injections mismatch: %+v", got.Injections)
	}
	if v := got.Injections[0].Env["GIT_SSL_CAINFO"]; v != "{{.BundlePath}}" {
		t.Fatalf("ca env key/value not preserved: %+v", got.Injections[0].Env)
	}
	if _, ok := got.Injections[0].Env["git_ssl_cainfo"]; ok {
		t.Fatalf("env key was lowercased: %+v", got.Injections[0].Env)
	}
}

func TestWriteCreatesDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "cfg", "config.toml")
	if err := Write(path, &Config{Proxy: ProxyConfig{Listen: "x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
