package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPruneRemovesInjected(t *testing.T) {
	t.Chdir(repoRoot(t))

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	logPath := filepath.Join(t.TempDir(), "docker.log")
	pdir := t.TempDir()
	writeFakeBin(t, pdir, "docker", `#!/bin/sh
echo "$@" >> "`+logPath+`"
if [ "$1" = "images" ] && [ "$2" = "--quiet" ]; then
  echo "sha256:inj000"
  exit 0
fi
exit 0
`)
	prependPath(t, pdir)

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home))

	withAnswers(t, true)
	RunPrune(cfgPath, []string{"--yes"})

	inv, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	s := string(inv)
	if !strings.Contains(s, "rmi --force sha256:inj000") {
		t.Fatalf("injected image not pruned:\n%s", s)
	}
}

func TestRunPruneAbortsWithoutConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home))

	withAnswers(t, false)
	RunPrune(cfgPath, nil)
	// Should not have reached docker: nothing to observe beyond exiting cleanly.
}
