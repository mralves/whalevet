package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[proxy]\nlisten = \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Listen != "unix:///tmp/whalevet/docker.sock" {
		t.Fatalf("Listen = %q", cfg.Proxy.Listen)
	}
	if cfg.Proxy.DockerSocket != "/var/run/docker.sock" {
		t.Fatalf("DockerSocket = %q", cfg.Proxy.DockerSocket)
	}
	if cfg.BuildKit.FrontendTag != "whalevet:latest" {
		t.Fatalf("FrontendTag = %q", cfg.BuildKit.FrontendTag)
	}
}

func TestLoadInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[proxy\ninvalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	src := &Config{
		Proxy: ProxyConfig{
			Listen:       "unix:///a.sock",
			DockerSocket: "/d.sock",
		},
		BuildKit: BuildKitConfig{
			FrontendTag: "t:1",
		},
		Injections: []Injection{
			{Type: "run", Command: "apt-get update", Position: "after_from"},
		},
	}
	if err := Write(path, src); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proxy.Listen != src.Proxy.Listen || got.Proxy.DockerSocket != src.Proxy.DockerSocket || got.BuildKit.FrontendTag != src.BuildKit.FrontendTag {
		t.Fatalf("proxy/buildkit roundtrip mismatch: %+v %+v", got.Proxy, got.BuildKit)
	}
	if len(got.Injections) != 1 || got.Injections[0].Command != "apt-get update" {
		t.Fatalf("injections roundtrip mismatch: %+v", got.Injections)
	}
}

func TestResolvePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, err := ResolvePath(path); err == nil {
		t.Fatal("expected error for missing absolute path")
	}
	if err := os.WriteFile(path, []byte("[proxy]"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolvePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path {
		t.Fatalf("resolved = %q, want %q", resolved, path)
	}

	dir := filepath.Join(t.TempDir(), "sub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rel.toml"), []byte("[proxy]"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	resolved, err = ResolvePath("rel.toml")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(dir, "rel.toml") {
		t.Fatalf("relative resolved = %q", resolved)
	}
}
