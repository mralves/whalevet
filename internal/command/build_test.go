package command

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mralves/whalevet/internal/config"
)

func TestRunBuild(t *testing.T) {
	t.Chdir(repoRoot(t))

	dockerDir := t.TempDir()
	dockerLog := filepath.Join(t.TempDir(), "docker.log")
	builtAtFile := filepath.Join(t.TempDir(), "built-at")
	writeFakeBin(t, dockerDir, "docker", `#!/bin/sh
echo "$@" >> "`+dockerLog+`"
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  [ -f "`+builtAtFile+`" ] && cat "`+builtAtFile+`"
  exit 0
fi
if [ "$1" = "build" ]; then
  date +%s > "`+builtAtFile+`"
  exit 0
fi
exit 0
`)
	prependPath(t, dockerDir)

	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	RunBuild(cfgPath, []string{"custom-tag"})

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BuildKit.FrontendTag != "custom-tag" {
		t.Fatalf("frontend_tag = %q, want custom-tag", cfg.BuildKit.FrontendTag)
	}
	if got := countDockerBuilds(t, dockerLog); got != 1 {
		t.Fatalf("builds = %d, want 1", got)
	}

	if _, err := os.Stat(filepath.Join(home, ".config", "systemd", "user", serviceName+".service")); !os.IsNotExist(err) {
		t.Fatalf("build must not install the systemd service: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".zshrc")); !os.IsNotExist(err) {
		t.Fatalf("build must not write the shell rc: %v", err)
	}
}

func TestRunBuildSkipsWhenImageCurrent(t *testing.T) {
	t.Chdir(repoRoot(t))

	dockerDir := t.TempDir()
	dockerLog := filepath.Join(t.TempDir(), "docker.log")
	builtAtFile := filepath.Join(t.TempDir(), "built-at")
	writeFakeBin(t, dockerDir, "docker", `#!/bin/sh
echo "$@" >> "`+dockerLog+`"
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  [ -f "`+builtAtFile+`" ] && cat "`+builtAtFile+`"
  exit 0
fi
if [ "$1" = "build" ]; then
  date +%s > "`+builtAtFile+`"
  exit 0
fi
exit 0
`)
	prependPath(t, dockerDir)

	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	RunBuild(cfgPath, nil)
	if got := countDockerBuilds(t, dockerLog); got != 1 {
		t.Fatalf("first build: %d builds, want 1", got)
	}

	RunBuild(cfgPath, nil)
	if got := countDockerBuilds(t, dockerLog); got != 1 {
		t.Fatalf("image current: %d builds, want 1", got)
	}
}
