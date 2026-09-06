package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaleFrontendTags(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	writeFakeBin(t, dir, "docker", `#!/bin/sh
echo "$@" >> "`+logPath+`"
if [ "$1" = "images" ]; then
  cat <<'EOF'
whalevet:latest
whalevet:v1
whalevet:v0
<none>:<none>
EOF
fi
exit 0
`)
	prependPath(t, dir)

	stale := staleFrontendTags("whalevet:latest", nil)
	if len(stale) != 2 {
		t.Fatalf("stale = %v, want 2 entries", stale)
	}
	for _, ref := range stale {
		if ref == "whalevet:latest" {
			t.Fatalf("current tag should be kept: %v", stale)
		}
	}
}

func TestRunPruneRemovesInjectedAndStale(t *testing.T) {
	t.Chdir(repoRoot(t))

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	prependPath(t, fakeDocker(t))

	logPath := filepath.Join(t.TempDir(), "docker.log")
	pdir := t.TempDir()
	writeFakeBin(t, pdir, "docker", `#!/bin/sh
echo "$@" >> "`+logPath+`"
if [ "$1" = "images" ] && [ "$2" = "--quiet" ]; then
  echo "sha256:inj000"
  exit 0
fi
if [ "$1" = "images" ] && [ "$2" = "--format" ]; then
  cat <<'EOF'
whalevet:latest
whalevet:v1
EOF
  exit 0
fi
exit 0
`)
	prependPath(t, pdir)

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "whalevet:latest")

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
	if !strings.Contains(s, "rmi --force whalevet:v1") {
		t.Fatalf("stale frontend tag not pruned:\n%s", s)
	}
	if strings.Contains(s, "rmi --force whalevet:latest") {
		t.Fatalf("current frontend tag must be kept:\n%s", s)
	}
}

func TestRunPruneAbortsWithoutConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "whalevet:latest")

	withAnswers(t, false)
	RunPrune(cfgPath, nil)
	// Should not have reached docker: nothing to observe beyond exiting cleanly.
}
