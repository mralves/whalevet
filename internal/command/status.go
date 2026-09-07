package command

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
)

// RunStatus reports the current state of the whalevet installation: config,
// proxy socket, frontend image, systemd service and shell rc DOCKER_HOST.
// Informational only: unlike doctor it always exits 0, so scripts can poll it
// without tripping on a degraded-but-recoverable install.
func RunStatus(configPath string, args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: whalevet [--config PATH] status")
		os.Exit(2)
	}

	r := &report{ok: true}

	resolvedPath, err := config.ResolvePath(configPath)
	if err != nil {
		r.fail("config file not found: %v", err)
	} else {
		cfg, err := config.Load(resolvedPath)
		if err != nil {
			r.fail("config file is invalid: %v", err)
		} else {
			r.pass("config file valid: %s", resolvedPath)
			checkFrontendImage(r, cfg.BuildKit.FrontendTag)
			checkServer(r, cfg.Proxy.Listen)
			checkSystemd(r)
			checkShellRC(r, cfg.Proxy.Listen)
		}
	}

	fmt.Println()
	if r.ok {
		fmt.Println(color.GreenString("status: healthy"))
		return
	}
	fmt.Println(color.RedString("status: degraded (run `whalevet doctor` for fixes)"))
}
