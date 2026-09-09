package command

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sockPath := filepath.Join(home, "dsp.sock")

	r := &report{ok: true}
	captureStdout(t, func() { checkServer(r, "unix://"+sockPath) })
	if r.ok {
		t.Fatal("missing socket should fail")
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	r = &report{ok: true}
	captureStdout(t, func() { checkServer(r, "unix://"+sockPath) })
	if !r.ok {
		t.Fatal("listening unix socket should pass")
	}

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	r = &report{ok: true}
	captureStdout(t, func() { checkServer(r, tcp.Addr().String()) })
	if !r.ok {
		t.Fatal("listening TCP should pass")
	}
}

func TestCheckSystemdMissingUnit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := &report{ok: true}
	out := captureStdout(t, func() { checkSystemd(r) })
	if r.ok {
		t.Fatal("missing unit file should fail")
	}
	if !strings.Contains(out, "systemd unit file not found") {
		t.Fatalf("unexpected message:\n%s", out)
	}
}

func TestCheckSystemdEnabledActive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	binDir, _ := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	r := &report{ok: true}
	captureStdout(t, func() { checkSystemd(r) })
	if !r.ok {
		t.Fatal("unit present with enabled/active systemctl should pass")
	}
}

func TestCheckSystemdFailedStates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "systemctl", `#!/bin/sh
case "$2" in
  is-enabled) echo disabled; exit 1 ;;
  is-active) echo failed; exit 3 ;;
  *) echo ok; exit 0 ;;
esac
`)
	prependPath(t, binDir)

	r := &report{ok: true}
	out := captureStdout(t, func() { checkSystemd(r) })
	if r.ok {
		t.Fatal("disabled/failed service should fail")
	}
	if !strings.Contains(out, "not enabled") || !strings.Contains(out, "not active") {
		t.Fatalf("missing failure messages:\n%s", out)
	}
}

func TestCheckShellRC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	listen := "unix:///tmp/proxy.sock"

	r := &report{ok: true}
	captureStdout(t, func() { checkShellRC(r, listen) })
	if r.ok {
		t.Fatal("missing rc should fail")
	}

	if err := updateShellRC(listen); err != nil {
		t.Fatal(err)
	}
	r = &report{ok: true}
	captureStdout(t, func() { checkShellRC(r, listen) })
	if !r.ok {
		t.Fatal("matching rc should pass")
	}

	r = &report{ok: true}
	captureStdout(t, func() { checkShellRC(r, "unix:///tmp/other.sock") })
	if r.ok {
		t.Fatal("mismatched rc should fail")
	}
}

func TestRunDoctorSuccess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	binDir, _ := fakeSystemctlEnv(t)
	prependPath(t, binDir)

	sockPath := filepath.Join(home, "dsp.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfgPath := filepath.Join(home, "config.toml")
	writeTestConfig(t, cfgPath, sockAddr(home))

	unitPath := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := updateShellRC(sockAddr(home)); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { RunDoctor(cfgPath, nil) })
	if !strings.Contains(out, "All checks passed.") {
		t.Fatalf("expected success, got:\n%s", out)
	}
	if strings.Contains(out, "[FAIL]") {
		t.Fatalf("unexpected failures:\n%s", out)
	}
}
