package command

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/proxy"
)

func TestServeSocketArg(t *testing.T) {
	sock, err := serveSocketArg(nil)
	if err != nil || sock != "" {
		t.Fatalf("no args: sock=%q err=%v", sock, err)
	}
	sock, err = serveSocketArg([]string{"unix:///x.sock"})
	if err != nil || sock != "unix:///x.sock" {
		t.Fatalf("one arg: sock=%q err=%v", sock, err)
	}
	if _, err := serveSocketArg([]string{"a", "b"}); err == nil {
		t.Fatal("expected error for two args")
	}
}

func TestRunProxyServerLifecycle(t *testing.T) {
	home := t.TempDir()
	sockPath := filepath.Join(home, "dsp.sock")
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			Listen:       "unix://" + sockPath,
			DockerSocket: filepath.Join(home, "nonexistent.sock"),
		},
	}

	done := make(chan struct{})
	go func() {
		runProxyServer(cfg, "test-config.toml", "")
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			if conn, err := net.DialTimeout("unix", sockPath, time.Second); err == nil {
				conn.Close()
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start listening within timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down after SIGTERM")
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file not removed on shutdown: %v", err)
	}
}

func TestRunProxyServerCreatesSocketDir(t *testing.T) {
	home := t.TempDir()
	// Parent dir deliberately does not exist before the server starts.
	sockPath := filepath.Join(home, "nested", "whalevet", "dsp.sock")
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			Listen:       "unix://" + sockPath,
			DockerSocket: filepath.Join(home, "nonexistent.sock"),
		},
	}

	done := make(chan struct{})
	go func() {
		runProxyServer(cfg, "test-config.toml", "")
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			if conn, err := net.DialTimeout("unix", sockPath, time.Second); err == nil {
				conn.Close()
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not create socket dir %q and start listening", filepath.Dir(sockPath))
		}
		time.Sleep(20 * time.Millisecond)
	}

	if fi, err := os.Stat(filepath.Dir(sockPath)); err != nil || !fi.IsDir() {
		t.Fatalf("socket directory not created: %v", err)
	}

	// SIGHUP is a reload, not a shutdown: the server must keep running.
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if conn, err := net.DialTimeout("unix", sockPath, time.Second); err != nil {
		t.Fatalf("server stopped after SIGHUP: %v", err)
	} else {
		conn.Close()
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down after SIGTERM")
	}
}

func TestReloadProxyConfig(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	initial, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hp := proxy.NewHTTPProxy(initial, nil, nil)

	// Hermetic docker: records invocations, reports a never-built image so the
	// frontend rebuild always runs (like a config newer than the image would).
	logPath := filepath.Join(home, "docker.log")
	prependPath(t, loggingDocker(t, logPath))

	// Rewrite the config with a run injection and reload.
	writeFile(t, cfgPath, `[proxy]
listen = "unix:///tmp/dsp.sock"

[buildkit]
frontend_tag = "v2"

[[injections]]
type = "run"
command = "echo hi"
`)
	reloadProxyConfig(hp, cfgPath)

	logData, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "image inspect") || !strings.Contains(string(logData), "build") {
		t.Fatalf("config reload did not drive a frontend rebuild:\n%s", logData)
	}

	got := hp.Config()
	if got.BuildKit.FrontendTag != "v2" {
		t.Fatalf("frontend_tag after reload = %q, want v2", got.BuildKit.FrontendTag)
	}
	if len(got.Injections) != 1 || got.Injections[0].Command != "echo hi" {
		t.Fatalf("injections after reload = %#v", got.Injections)
	}
}

func TestReloadProxyConfigKeepsOldOnError(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home), "v1")

	initial, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hp := proxy.NewHTTPProxy(initial, nil, nil)

	writeFile(t, cfgPath, "this is not toml [")
	reloadProxyConfig(hp, cfgPath)

	if hp.Config().BuildKit.FrontendTag != "v1" {
		t.Fatalf("config changed despite failed reload: %#v", hp.Config())
	}
}

func waitForSocket(t *testing.T, path string, deadline time.Time) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
				conn.Close()
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %q not accepting connections in time", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitSocketGone(t *testing.T, path string, deadline time.Time) {
	t.Helper()
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %q still present", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunProxyServerReloadReopensSocket verifies that a config edit (detected
// by the file watcher) reloads the config and reopens the proxy socket at the
// new listen address, dropping the old one.
func TestRunProxyServerReloadReopensSocket(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.toml")
	sock1 := filepath.Join(home, "one.sock")
	sock2 := filepath.Join(home, "two.sock")
	writeTestConfig(t, cfgPath, "unix://"+sock1, "v1")

	initial, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Hermetic docker so the frontend rebuild during reload succeeds/reports.
	logPath := filepath.Join(home, "docker.log")
	prependPath(t, loggingDocker(t, logPath))

	done := make(chan struct{})
	go func() {
		runProxyServer(initial, cfgPath, "")
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	waitForSocket(t, sock1, deadline)

	// Change the listen address and let the watcher pick it up.
	writeTestConfig(t, cfgPath, "unix://"+sock2, "v2")
	waitForSocket(t, sock2, deadline)
	waitSocketGone(t, sock1, deadline)

	logData, err := os.ReadFile(logPath) //nolint:gosec // fixed temp path in test
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "image inspect") {
		t.Fatalf("config reload did not drive a frontend rebuild:\n%s", logData)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down after SIGTERM")
	}
	waitSocketGone(t, sock2, deadline)
}
