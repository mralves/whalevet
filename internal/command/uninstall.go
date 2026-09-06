package command

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/frontend"
)

// RunUninstall reverses a previous setup: stops and removes the systemd user
// service, strips the managed DOCKER_HOST block from the shell rc, and removes
// the frontend image plus any whalevet-injected images. Requires a
// confirmation unless --yes/-y is passed.
func RunUninstall(configPath string, args []string) {
	force := false
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			force = true
			continue
		}
		log.Fatalf("usage: whalevet [--config PATH] uninstall [--yes]")
	}

	resolved, err := config.ResolvePath(configPath)
	if err != nil {
		log.Fatalf("Failed to resolve config: %v", err)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		log.Fatalf("Failed to load config %q: %v", resolved, err)
	}

	if !force && !askConfirmation("Remove the systemd service, shell rc entry, and all whalevet images?", false) {
		log.Printf("%s", color.YellowString("Aborted"))
		return
	}

	removeSystemdService()
	removeShellRC()
	removeImages(cfg)
	log.Printf("%s", color.GreenString("Uninstall complete"))
}

func removeSystemdService() {
	unitDir, err := userUnitDir()
	if err != nil {
		log.Printf("Could not determine systemd user unit dir: %v", err)
		return
	}
	unitPath := filepath.Join(unitDir, serviceName+".service")

	// Stop and disable best-effort; only the file removal is mandatory.
	for _, step := range [][]string{
		{"stop", serviceName + ".service"},
		{"disable", serviceName + ".service"},
	} {
		if _, err := runSystemctl(step...); err != nil {
			log.Printf("systemctl --user %s failed (continuing): %v", strings.Join(step, " "), err)
		}
	}
	if err := os.Remove(unitPath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Could not remove unit file %s: %v", unitPath, err)
			return
		}
	} else {
		log.Printf("%s", color.GreenString("Removed systemd unit file %s", unitPath))
	}
	if _, err := runSystemctl("daemon-reload"); err != nil {
		log.Printf("systemctl --user daemon-reload failed (continuing): %v", err)
	}
}

func removeShellRC() {
	rcPath := currentRCPath()
	data, err := os.ReadFile(rcPath) //nolint:gosec // rc path is derived from the local user's SHELL, not remote input
	if err != nil {
		log.Printf("No shell rc at %s: %v", rcPath, err)
		return
	}
	marker := "# whalevet managed DOCKER_HOST"
	var out strings.Builder
	skipNext := false
	for l := range strings.SplitSeq(string(data), "\n") {
		t := strings.TrimSpace(l)
		if t == marker {
			skipNext = true
			continue
		}
		if skipNext && strings.HasPrefix(strings.TrimSpace(l), "export DOCKER_HOST=") {
			skipNext = false
			continue
		}
		skipNext = false
		out.WriteString(l + "\n")
	}
	perm := os.FileMode(0o600)
	if fi, err := os.Stat(rcPath); err == nil {
		perm = fi.Mode().Perm()
	}
	if err := os.WriteFile(rcPath, []byte(out.String()), perm); err != nil {
		log.Printf("Could not update %s: %v", rcPath, err)
		return
	}
	log.Printf("%s", color.GreenString("Removed whalevet DOCKER_HOST block from %s", rcPath))
}

const injectedLabel = "com.whalevet.injected"

// dockerImagesByLabel returns the IDs of images carrying the given label.
func dockerImagesByLabel(label string, env []string) []string {
	cmd := exec.Command("docker", "images", "--quiet", "--filter", "label="+label) //nolint:gosec // label comes from the tool's own constants
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		log.Printf("docker images --filter label=%s failed: %v", label, err)
		return nil
	}
	var ids []string
	for l := range strings.SplitSeq(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ids = append(ids, l)
		}
	}
	return ids
}

func rmiImage(id string, env []string) {
	cmd := exec.Command("docker", "rmi", "--force", id) //nolint:gosec // removing tool-owned images is the command's purpose
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("docker rmi %s failed: %v (%s)", id, err, out)
		return
	}
	log.Printf("%s", color.GreenString("Removed image %s", id))
}

// removeImages deletes the configured frontend image (identified by its
// built-at label) and every whalevet-injected committed image.
func removeImages(cfg *config.Config) {
	env := frontend.CliEnv(cfg.Proxy.Listen)

	// 1. whalevet-injected commits: label com.whalevet.injected=true.
	for _, id := range dockerImagesByLabel(injectedLabel, env) {
		rmiImage(id, env)
	}

	// 2. frontend images built by this tool: have the built-at label. Remove
	// them all; uninstall is a full teardown of managed artifacts.
	for _, id := range dockerImagesByLabel(frontend.BuiltAtLabel, env) {
		rmiImage(id, env)
	}
}
