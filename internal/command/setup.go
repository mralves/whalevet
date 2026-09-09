package command

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	strings "strings"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
)

const serviceName = "whalevet"

// askConfirmation prompts the user for a yes/no decision on stdin before setup
// runs a side-effecting step. defaultYes is used when the input is empty.
// Overridable in tests.
var askConfirmation = func(prompt string, defaultYes bool) bool {
	suffix := "[y/N] "
	if defaultYes {
		suffix = "[Y/n] "
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s %s", color.HiCyanString(prompt), color.YellowString(suffix))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return defaultYes
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

func RunSetup(configPath string, args []string) {
	if len(args) > 0 {
		log.Fatalf("usage: whalevet [--config PATH] setup")
	}

	resolved, err := ensureConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to prepare config: %v", err)
	}

	if askConfirmation("Install and start the systemd user service?", false) {
		if err := installSystemdService(resolved); err != nil {
			log.Fatalf("Failed to install systemd service: %v", err)
		}
	} else {
		log.Printf("%s", color.YellowString("Skipped systemd service installation"))
	}

	cfg, err := config.Load(resolved)
	if err != nil {
		log.Fatalf("Failed to load config %q: %v", resolved, err)
	}
	if askConfirmation("Set DOCKER_HOST for this shell in your rc file?", false) {
		if err := updateShellRC(cfg.Proxy.Listen); err != nil {
			log.Fatalf("Failed to update shell rc: %v", err)
		}
	} else {
		log.Printf("%s", color.YellowString("Skipped shell rc update"))
	}

	log.Printf("%s", color.GreenString("Setup complete"))
	log.Printf("%s", color.HiCyanString("  Config:      %s", resolved))
	log.Printf("%s", color.HiCyanString("  Proxy socket:%s", cfg.Proxy.Listen))
}

func ensureConfig(configPath string) (string, error) {
	resolved, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve config path %q: %w", configPath, err)
	}
	if _, err := os.Stat(resolved); err == nil {
		return resolved, nil
	}
	if err := config.Write(resolved, &config.Config{
		Proxy: config.ProxyConfig{
			Listen:       config.DefaultListen,
			DockerSocket: config.DefaultDockerSocket,
		},
	}); err != nil {
		return "", fmt.Errorf("write default config %q: %w", resolved, err)
	}
	log.Printf("Created default config %s", resolved)
	return resolved, nil
}

func installSystemdService(configPath string) error {
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("absolute executable path: %w", err)
	}
	cfgAbs, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("absolute config path: %w", err)
	}

	unitDir, err := userUnitDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		return fmt.Errorf("create unit dir %q: %w", unitDir, err)
	}

	unitPath := filepath.Join(unitDir, serviceName+".service")
	unit := fmt.Sprintf(`[Unit]
Description=Docker Socket Proxy
After=network.target

[Service]
Type=simple
ExecStart=%s serve --config %s
Restart=on-failure

[Install]
WantedBy=default.target
`, bin, cfgAbs)
	if err := os.WriteFile(unitPath, []byte(unit), 0o600); err != nil {
		return fmt.Errorf("write unit file %q: %w", unitPath, err)
	}

	for _, step := range [][]string{
		{"daemon-reload"},
		{"enable", serviceName + ".service"},
		{"start", serviceName + ".service"},
	} {
		if _, err := runSystemctl(step...); err != nil {
			return fmt.Errorf("systemctl --user %s: %w", strings.Join(step, " "), err)
		}
	}
	log.Printf("%s", color.GreenString("Installed and started systemd user service %s", serviceName))

	// start is idempotent for an already-running unit, so restart explicitly
	// to make a repeated setup run take effect immediately.
	active, _ := runSystemctl("is-active", serviceName+".service") // non-zero exit means inactive/unknown; still informational
	if strings.TrimSpace(active) == "active" {
		if _, err := runSystemctl("restart", serviceName+".service"); err != nil {
			return fmt.Errorf("systemctl --user restart %s: %w", serviceName+".service", err)
		}
		log.Printf("%s", color.GreenString("Restarted running systemd user service %s", serviceName))
	}
	return nil
}

func runSystemctl(args ...string) (string, error) {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...) //nolint:gosec // driving systemd user units is the tool's purpose; args are a fixed list
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func userUnitDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

func currentRCPath() string {
	shell := filepath.Base(os.Getenv("SHELL"))
	if shell == "zsh" {
		return filepath.Join(mustHome(), ".zshrc")
	}
	return filepath.Join(mustHome(), ".bashrc")
}

func mustHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return os.Getenv("HOME")
	}
	return home
}

func updateShellRC(listen string) error {
	rcPath := currentRCPath()
	marker := "# whalevet managed DOCKER_HOST"
	line := fmt.Sprintf("export DOCKER_HOST=%q", listen)

	var existing []byte
	data, err := os.ReadFile(rcPath) //nolint:gosec // rc path is derived from the local user's SHELL, not remote input
	switch {
	case err == nil:
		existing = data
	case os.IsNotExist(err): // first install: no rc yet, keep existing empty
	default:
		return fmt.Errorf("read shell rc %q: %w", rcPath, err)
	}

	found := false
	var out strings.Builder
	for l := range strings.SplitSeq(string(existing), "\n") {
		t := strings.TrimSpace(l)
		if t == marker {
			out.WriteString(marker + "\n")
			out.WriteString(line + "\n")
			found = true
			continue
		}
		if found && strings.HasPrefix(strings.TrimSpace(l), "export DOCKER_HOST=") {
			continue
		}
		out.WriteString(l + "\n")
	}
	s := out.String()
	if !found {
		s += marker + "\n" + line + "\n"
	}
	perm := os.FileMode(0o600)
	if fi, err := os.Stat(rcPath); err == nil {
		perm = fi.Mode().Perm()
	}
	if err := os.WriteFile(rcPath, []byte(s), perm); err != nil {
		return fmt.Errorf("write %q: %w", rcPath, err)
	}
	log.Printf("%s", color.GreenString("Updated DOCKER_HOST in %s", rcPath))
	return nil
}
