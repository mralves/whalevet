package command

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withAnswers stubs askConfirmation with a fixed answer queue; remaining asks
// fall back to their default.
func withAnswers(t *testing.T, answers ...bool) {
	t.Helper()
	orig := askConfirmation
	idx := 0
	askConfirmation = func(prompt string, defaultYes bool) bool {
		if idx < len(answers) {
			a := answers[idx]
			idx++
			return a
		}
		return defaultYes
	}
	t.Cleanup(func() { askConfirmation = orig })
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}

func writeFakeBin(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o700); err != nil { //nolint:gosec // executable fake bin: 0700 is the minimum that keeps the +x bit
		t.Fatal(err)
	}
}

func prependPath(t *testing.T, dirs ...string) {
	t.Helper()
	path := strings.Join(append(dirs, os.Getenv("PATH")), ":")
	t.Setenv("PATH", path)
}

// fakeSystemctlEnv installs a recording systemctl stub and returns its bin dir
// and log path.
func fakeSystemctlEnv(t *testing.T) (binDir, logPath string) {
	t.Helper()
	binDir = t.TempDir()
	logPath = filepath.Join(t.TempDir(), "systemctl.log")
	t.Setenv("FAKE_SYSTEMD_LOG", logPath)
	writeFakeBin(t, binDir, "systemctl", `#!/bin/sh
echo "$@" >> "$FAKE_SYSTEMD_LOG"
case "$2" in
  is-enabled) echo enabled;;
  is-active) echo active;;
  enable) echo "Created symlink for unit whalevet.service.";;
  start) echo "Started whalevet.service.";;
  daemon-reload) echo ok;;
  *) echo ok;;
esac
exit 0
`)
	return
}

func sockAddr(home string) string {
	return "unix://" + filepath.Join(home, "dsp.sock")
}

func writeTestConfig(t *testing.T, path, listen string) {
	t.Helper()
	content := `[proxy]
listen = "` + listen + `"
docker_socket = "/var/run/docker.sock"
`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	out := <-done
	os.Stdout = old
	return out
}
