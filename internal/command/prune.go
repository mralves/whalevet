package command

import (
	"log"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/frontend"
)

// RunPrune removes unused whalevet-managed images: whalevet-injected
// commits and stale frontend wrapper tags (any built-at tagged image other
// than the configured frontend_tag). Requires --yes/-y or confirmation.
func RunPrune(configPath string, args []string) {
	force := false
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			force = true
			continue
		}
		log.Fatalf("usage: whalevet [--config PATH] prune [--yes]")
	}

	resolved, err := config.ResolvePath(configPath)
	if err != nil {
		log.Fatalf("Failed to resolve config: %v", err)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		log.Fatalf("Failed to load config %q: %v", resolved, err)
	}

	if !force && !askConfirmation("Prune whalevet-injected images and stale frontend tags?", false) {
		log.Printf("%s", color.YellowString("Aborted"))
		return
	}

	env := frontend.CliEnv(cfg.Proxy.Listen)

	// 1. whalevet-injected commits: label com.whalevet.injected=true.
	injected := dockerImagesByLabel(injectedLabel, env)
	log.Printf("Found %d whalevet-injected image(s)", len(injected))
	for _, id := range injected {
		rmiImage(id, env)
	}

	// 2. Stale frontend tags: built-at labeled refs != the configured tag.
	stale := staleFrontendTags(cfg.BuildKit.FrontendTag, env)
	log.Printf("Found %d stale frontend tag(s)", len(stale))
	for _, ref := range stale {
		rmiImage(ref, env)
	}

	if len(injected) == 0 && len(stale) == 0 {
		log.Printf("%s", color.YellowString("Nothing to prune"))
	}
}

// staleFrontendTags lists refs carrying the built-at label that are not the
// configured frontend_tag. The filter output is repo:tag, so dangling
// (untagged) frontend images are left alone.
func staleFrontendTags(current string, env []string) []string {
	cmd := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "label="+frontend.BuiltAtLabel) //nolint:gosec // label comes from the tool's own constants
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		log.Printf("docker images --filter label=%s failed: %v", frontend.BuiltAtLabel, err)
		return nil
	}
	var stale []string
	for line := range strings.SplitSeq(string(out), "\n") {
		ref := strings.TrimSpace(line)
		if ref == "" || strings.HasPrefix(ref, "<none>:") {
			continue
		}
		if ref != current {
			stale = append(stale, ref)
		}
	}
	return stale
}
