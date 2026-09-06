package frontend

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const proxyListen = "unix:///tmp/whalevet/docker.sock"

func TestDockerEnvClearsProxyHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", proxyListen)
	t.Setenv("OTHER", "keep")

	env := dockerEnv(proxyListen)
	if !containsEnv(env, "DOCKER_HOST=") {
		t.Fatalf("DOCKER_HOST not cleared: %v", env)
	}
	if !containsEnv(env, "OTHER=keep") {
		t.Fatal("unrelated env dropped")
	}
}

func TestDockerEnvKeepsOtherHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")

	env := dockerEnv(proxyListen)
	if !containsEnv(env, "DOCKER_HOST=unix:///var/run/docker.sock") {
		t.Fatalf("foreign DOCKER_HOST was clobbered: %v", env)
	}
}

func TestDockerEnvNoHost(t *testing.T) {
	if err := os.Unsetenv("DOCKER_HOST"); err != nil {
		t.Fatal(err)
	}
	env := dockerEnv(proxyListen)
	for _, kv := range env {
		if strings.HasPrefix(kv, "DOCKER_HOST=") {
			t.Fatalf("unexpected DOCKER_HOST: %q", kv)
		}
	}
}

func TestDockerEnvBarePathCompare(t *testing.T) {
	t.Setenv("DOCKER_HOST", proxyListen)
	env := dockerEnv("/tmp/whalevet/docker.sock")
	if !containsEnv(env, "DOCKER_HOST=") {
		t.Fatalf("bare-path proxy listen not recognised: %v", env)
	}
}

func TestBuildImageIgnoresShellProxyHost(t *testing.T) {
	t.Chdir(repoRootFind(t))
	t.Setenv("DOCKER_HOST", proxyListen)

	dir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	fake := filepath.Join(dir, "docker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"DOCKER_HOST=$DOCKER_HOST\" >> \""+logPath+"\"\nexit 0\n"), 0o700); err != nil { //nolint:gosec // executable fake docker bin: 0700 keeps the +x bit
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	cfgPath := writeTmpConfig(t)
	if err := BuildImage("whalevet:latest", "", cfgPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "DOCKER_HOST=\n") {
		t.Fatalf("docker build did not get cleared DOCKER_HOST:\n%s", data)
	}
}

func containsEnv(env []string, want string) bool {
	return slices.Contains(env, want)
}

func writeTmpConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[proxy]\nlisten = \"" + proxyListen + "\"\ndocker_socket = \"/var/run/docker.sock\"\n\n[buildkit]\nfrontend_tag = \"whalevet:latest\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func repoRootFind(t *testing.T) string {
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
