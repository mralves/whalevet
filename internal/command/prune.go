package command

import (
	"log"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
)

// RunPrune removes whalevet-injected committed images (label
// com.whalevet.injected=true). Requires --yes/-y or confirmation.
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

	if !force && !askConfirmation("Prune whalevet-injected images?", false) {
		log.Printf("%s", color.YellowString("Aborted"))
		return
	}

	env := dockerEnv(cfg.Proxy.Listen)

	injected := dockerImagesByLabel(injectedLabel, env)
	log.Printf("Found %d whalevet-injected image(s)", len(injected))
	for _, id := range injected {
		rmiImage(id, env)
	}

	if len(injected) == 0 {
		log.Printf("%s", color.YellowString("Nothing to prune"))
	}
}
