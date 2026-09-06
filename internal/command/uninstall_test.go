package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stateful uninstall fake docker: answers label filters and logs rmi calls.
func uninstallFakeDocker(t *testing.T, logPath string) string {
	t.Helper()
	dir := t.TempDir()
	writeFakeBin(t, dir, "docker", `#!/bin/sh
echo "$@" >> "`+logPath+`"
if [ "$1" = "images" ] && [ "$4" = "label=com.whalevet.injected" ]; then
  echo "sha256:inj111"
  echo "sha256:inj222"
  exit 0
fi
if [ "$1" = "images" ] && [ "$4" = "label=com.whalevet.built-at" ]; then
  echo "sha256:front1"
  exit 0
fi
exit 0
`)
	return dir
}

func TestRemoveSystemdService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	binDir, _ := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	removeSystemdService()
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("unit file still exists: %v", err)
	}
}

func TestRemoveShellRC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	rc := filepath.Join(home, ".zshrc")
	original := "# user content\n"
	writeFile(t, rc, original)
	if err := updateShellRC("unix:///tmp/proxy.sock"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(rc) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "whalevet managed DOCKER_HOST") {
		t.Fatalf("precondition failed, marker missing:\n%s", data)
	}

	removeShellRC()

	data, err = os.ReadFile(rc) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, "whalevet") || strings.Contains(s, "DOCKER_HOST") {
		t.Fatalf("whalevet block not removed:\n%s", s)
	}
	if !strings.Contains(s, original) {
		t.Fatalf("user content lost:\n%s", s)
	}
}

func TestRunUninstallRemovesEverything(t *testing.T) {
	t.Chdir(repoRoot(t))

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	prependPath(t, fakeDocker(t))
	binDir, _ := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	logPath := filepath.Join(t.TempDir(), "docker.log")
	injectedDir := uninstallFakeDocker(t, logPath)
	prependPath(t, injectedDir)

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	if err := updateShellRC(sockAddr(home)); err != nil {
		t.Fatal(err)
	}

	withAnswers(t, true)
	RunUninstall(cfgPath, []string{"--yes"})

	logData, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	inv := string(logData)
	for _, want := range []string{
		"rmi --force sha256:inj111",
		"rmi --force sha256:inj222",
		"rmi --force sha256:front1",
	} {
		if !strings.Contains(inv, want) {
			t.Fatalf("docker not invoked with %q:\n%s", want, inv)
		}
	}

	if _, err := os.Stat(filepath.Join(home, ".zshrc")); err == nil {
		rc, _ := os.ReadFile(filepath.Join(home, ".zshrc")) //nolint:gosec // fixed temp path in test
		if strings.Contains(string(rc), "whalevet") {
			t.Fatalf("rc still contains whalevet block:\n%s", rc)
		}
	}
}

func TestRunUninstallAbortsWithoutConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	withAnswers(t, false)
	RunUninstall(cfgPath, nil)

	if _, err := os.Stat(filepath.Join(home, ".config", "systemd", "user", serviceName+".service")); !os.IsNotExist(err) {
		t.Fatalf("aborted uninstall should not create/remove units")
	}
}
