package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseEnvFile(t *testing.T) {
	env, err := ParseEnvFile([]byte("# comment\n\nFOO=bar\nEMPTY=\n# another\nQUOTED=\"a b\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if env["FOO"] != "bar" || env["EMPTY"] != "" || env["QUOTED"] != "a b" {
		t.Fatalf("unexpected env map: %#v", env)
	}
	if len(env) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(env))
	}
}

func TestParseEnvFileRejectsBadLine(t *testing.T) {
	if _, err := ParseEnvFile([]byte("NOEQUALS\n")); err == nil {
		t.Fatal("expected error for line without =")
	}
}

func TestExpandEnvFilesMergesAndOverrides(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "vars.env"), "SHARED=file\nFROM_FILE=yes\n")

	rules, err := ExpandEnvFiles([]Injection{
		{Type: "env", EnvFile: "vars.env", Env: map[string]string{"SHARED": "inline"}},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := rules[0].Env["SHARED"]; got != "inline" {
		t.Fatalf("inline should win over env_file, got %q", got)
	}
	if got := rules[0].Env["FROM_FILE"]; got != "yes" {
		t.Fatalf("env_file key missing: %q", got)
	}
}

func TestExpandEnvFilesMissingFile(t *testing.T) {
	if _, err := ExpandEnvFiles([]Injection{{Type: "env", EnvFile: "missing.env"}}, t.TempDir()); err == nil {
		t.Fatal("expected error for missing env_file")
	}
}

func TestExpandEnvFilesKeepsUntouchedRules(t *testing.T) {
	orig := []Injection{{Type: "run", Command: "echo hi"}, {Type: "env", Env: map[string]string{"A": "b"}}}
	out, err := ExpandEnvFiles(orig, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Original slice must not be mutated.
	if orig[1].EnvFile != "" {
		t.Fatal("ExpandEnvFiles mutated the input slice")
	}
	if len(out) != 2 || out[1].Env["A"] != "b" {
		t.Fatalf("unexpected output: %#v", out)
	}
}

func TestLoadRecordsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[proxy]\nlisten = \"unix:///custom.sock\"\n"
	writeFile(t, path, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != path {
		t.Fatalf("Path = %q, want %q", cfg.Path, path)
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := &Config{
		Proxy: ProxyConfig{Listen: DefaultListen, DockerSocket: DefaultDockerSocket},
		Policy: PolicyConfig{
			Allow: []string{"docker.io/library/*", "registry.internal/**"},
			Deny:  []string{"**/untrusted/**"},
		},
	}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Policy.Allow) != 2 || loaded.Policy.Allow[1] != "registry.internal/**" {
		t.Fatalf("policy allow not round-tripped: %#v", loaded.Policy)
	}
	if len(loaded.Policy.Deny) != 1 || loaded.Policy.Deny[0] != "**/untrusted/**" {
		t.Fatalf("policy deny not round-tripped: %#v", loaded.Policy)
	}
}

func TestEnvFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := &Config{
		Proxy: ProxyConfig{Listen: DefaultListen, DockerSocket: DefaultDockerSocket},
		Injections: []Injection{
			{Type: "env", EnvFile: "vars.env", Env: map[string]string{"A": "b"}},
		},
	}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Injections[0].EnvFile != "vars.env" {
		t.Fatalf("env_file not round-tripped: %#v", loaded.Injections[0])
	}
}
