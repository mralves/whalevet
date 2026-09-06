package command

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
)

type report struct {
	ok bool
}

func RunDoctor(configPath string, args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: whalevet [--config PATH] doctor")
		os.Exit(2)
	}

	r := &report{ok: true}

	// 1. Config file
	resolvedPath, err := config.ResolvePath(configPath)
	if err != nil {
		r.fail("config file not found: %v", err)
	} else {
		cfg, err := config.Load(resolvedPath)
		if err != nil {
			r.fail("config file is invalid: %v", err)
		} else {
			r.pass("config file exists and is valid: %s", resolvedPath)

			// 2. Frontend image
			checkFrontendImage(r, cfg.BuildKit.FrontendTag)

			// 3. Proxy server / socket
			checkServer(r, cfg.Proxy.Listen)

			// 4. Systemd service
			checkSystemd(r)

			// 5. Shell rc DOCKER_HOST
			checkShellRC(r, cfg.Proxy.Listen)
		}
	}

	if r.ok {
		fmt.Println(color.GreenString("All checks passed."))
	} else {
		fmt.Println(color.RedString("\nSome checks failed. Fix the issues above and re-run doctor."))
		os.Exit(1)
	}
}

func checkFrontendImage(r *report, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "images", "-q", tag) //nolint:gosec // running docker is the tool's purpose; tag comes from the trusted config
	out, err := cmd.Output()
	if err != nil {
		r.fail("could not query docker images: %v", err)
		return
	}
	if strings.TrimSpace(string(out)) == "" {
		r.fail("frontend image %q is not built; run: whalevet setup", tag)
		return
	}
	r.pass("frontend image %q exists", tag)
}

func checkServer(r *report, listen string) {
	if rest, ok := strings.CutPrefix(listen, "unix:"); ok {
		sockPath := "/" + strings.TrimLeft(rest, "/")
		if _, err := os.Stat(sockPath); err != nil {
			r.fail("proxy socket %q does not exist (is the service running?)", sockPath)
			return
		}
		conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
		if err != nil {
			r.fail("proxy socket %q is present but not accepting connections", sockPath)
			return
		}
		conn.Close()
		r.pass("proxy socket %q is listening", sockPath)
		return
	}

	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		r.fail("proxy TCP listener %q is not reachable", listen)
		return
	}
	conn.Close()
	r.pass("proxy TCP listener %q is reachable", listen)
}

func checkSystemd(r *report) {
	unitDir, err := userUnitDir()
	if err != nil {
		r.fail("could not determine systemd user unit dir: %v", err)
		return
	}
	unitPath := filepath.Join(unitDir, serviceName+".service")
	if _, err := os.Stat(unitPath); err != nil {
		r.fail("systemd unit file not found at %s; run: whalevet setup", unitPath)
		return
	}
	r.pass("systemd unit file exists: %s", unitPath)

	enabledOut, _ := exec.Command("systemctl", "--user", "is-enabled", serviceName+".service").CombinedOutput()
	if strings.TrimSpace(string(enabledOut)) != "enabled" {
		r.fail("systemd service is not enabled (got %q)", strings.TrimSpace(string(enabledOut)))
	} else {
		r.pass("systemd service is enabled")
	}

	activeOut, _ := exec.Command("systemctl", "--user", "is-active", serviceName+".service").CombinedOutput()
	if strings.TrimSpace(string(activeOut)) != "active" {
		r.fail("systemd service is not active (got %q)", strings.TrimSpace(string(activeOut)))
	} else {
		r.pass("systemd service is active")
	}
}

func checkShellRC(r *report, listen string) {
	rcPath := currentRCPath()
	data, err := os.ReadFile(rcPath) //nolint:gosec // rc path is derived from the local user's SHELL, not remote input
	if err != nil {
		r.fail("could not read shell rc %s: %v", rcPath, err)
		return
	}
	expected := fmt.Sprintf("export DOCKER_HOST=%q", listen)
	if strings.Contains(string(data), expected) {
		r.pass("DOCKER_HOST set correctly in %s", rcPath)
	} else {
		r.fail("DOCKER_HOST not configured in %s; run: whalevet setup", rcPath)
	}
}

func (r *report) pass(format string, a ...any) {
	fmt.Printf("  %s  %s\n", color.GreenString("[OK]"), fmt.Sprintf(format, a...))
}

func (r *report) fail(format string, a ...any) {
	r.ok = false
	fmt.Printf("  %s %s\n", color.RedString("[FAIL]"), fmt.Sprintf(format, a...))
}
