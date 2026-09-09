package command

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runStatusCardinal(t *testing.T, withDaemon bool) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	binDir, _ := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	sockPath := filepath.Join(home, "dsp.sock")
	if withDaemon {
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, "unix://"+sockPath)

	// Create systemd unit so checkSystemd finds the file.
	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := updateShellRC("unix://" + sockPath); err != nil {
		t.Fatal(err)
	}

	return captureStdout(t, func() { RunStatus(cfgPath, nil) })
}

func TestRunStatusHealthy(t *testing.T) {
	out := runStatusCardinal(t, true)
	if !strings.Contains(out, "status: healthy") {
		t.Fatalf("expected healthy status, got:\n%s", out)
	}
	if strings.Contains(out, "[FAIL]") {
		t.Fatalf("unexpected failures:\n%s", out)
	}
}

func TestRunStatusDegraded(t *testing.T) {
	// No daemon, no unit, no rc → several checks fail.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, "unix:///nonexistent.sock")

	out := captureStdout(t, func() { RunStatus(cfgPath, nil) })
	if !strings.Contains(out, "status: degraded") {
		t.Fatalf("expected degraded status, got:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL]") {
		t.Fatalf("expected some failed checks:\n%s", out)
	}
}
