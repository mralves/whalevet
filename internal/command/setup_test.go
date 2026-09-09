package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mralves/whalevet/internal/config"
)

func TestEnsureConfigCreatesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg", "config.toml")
	resolved, err := ensureConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path {
		t.Fatalf("resolved = %q, want %q", resolved, path)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Listen == "" || cfg.Proxy.DockerSocket == "" {
		t.Fatalf("defaults not written/loadable: %+v", cfg.Proxy)
	}
	data, err := os.ReadFile(path) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "injections = []") {
		t.Fatalf("generated default config should not contain empty injections list:\n%s", data)
	}
}

func TestEnsureConfigPreservesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[proxy]\nlisten = \"unix:///custom.sock\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("existing config was modified:\n%s", data)
	}
}

func TestCurrentRCPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Setenv("SHELL", "/bin/zsh")
	if got := currentRCPath(); got != filepath.Join(home, ".zshrc") {
		t.Fatalf("zsh rc = %q", got)
	}
	t.Setenv("SHELL", "/bin/bash")
	if got := currentRCPath(); got != filepath.Join(home, ".bashrc") {
		t.Fatalf("bash rc = %q", got)
	}
	t.Setenv("SHELL", "/usr/bin/fish")
	if got := currentRCPath(); got != filepath.Join(home, ".bashrc") {
		t.Fatalf("unknown shell rc = %q, want .bashrc", got)
	}
}

func TestUpdateShellRCAppendsAndReplaces(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	rc := filepath.Join(home, ".zshrc")

	if err := updateShellRC("unix:///tmp/proxy.sock"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(rc) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `export DOCKER_HOST="unix:///tmp/proxy.sock"`) {
		t.Fatalf("export line missing:\n%s", data)
	}

	if err := updateShellRC("unix:///tmp/other.sock"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(rc) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Count(s, "# whalevet managed DOCKER_HOST") != 1 {
		t.Fatalf("marker duplicated:\n%s", s)
	}
	if !strings.Contains(s, `export DOCKER_HOST="unix:///tmp/other.sock"`) {
		t.Fatalf("new value missing:\n%s", s)
	}
	if strings.Contains(s, "/tmp/proxy.sock") {
		t.Fatalf("stale export remains:\n%s", s)
	}
}

func TestInstallSystemdService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	binDir, logPath := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	cfgPath := filepath.Join(home, "config.toml")
	if err := installSystemdService(cfgPath); err != nil {
		t.Fatal(err)
	}

	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	unit, err := os.ReadFile(unitPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), exe+" serve --config "+cfgPath) {
		t.Fatalf("ExecStart wrong:\n%s", unit)
	}

	inv, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"daemon-reload", "enable " + serviceName + ".service", "start " + serviceName + ".service", "restart " + serviceName + ".service"} {
		if !strings.Contains(string(inv), want) {
			t.Fatalf("systemctl not invoked with %q:\n%s", want, inv)
		}
	}
}

func setupIntegration(t *testing.T) {
	t.Helper()
	t.Chdir(repoRoot(t))

	sysDir, _ := fakeSystemctlEnv(t)
	prependPath(t, sysDir)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home))

	withAnswers(t, true, true)
	RunSetup(cfgPath, nil)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Listen != sockAddr(home) {
		t.Fatalf("proxy listen = %q, want %q", cfg.Proxy.Listen, sockAddr(home))
	}

	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	unit, err := os.ReadFile(unitPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "serve --config "+cfgPath) {
		t.Fatalf("unit ExecStart wrong:\n%s", unit)
	}

	rc, err := os.ReadFile(filepath.Join(home, ".zshrc")) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rc), `export DOCKER_HOST="`+sockAddr(home)+`"`) {
		t.Fatalf("rc missing DOCKER_HOST:\n%s", rc)
	}
}

func TestRunSetupIntegration(t *testing.T) {
	setupIntegration(t)
}
