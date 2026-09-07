package command

import "log"

// RunBuild builds the frontend wrapper image for the configured frontend_tag,
// or for the optional tag argument (persisted as frontend_tag in the config).
// It is the image-build half of setup, without the systemd service and shell
// rc changes.
func RunBuild(configPath string, args []string) {
	tag, err := setupTagArg(args)
	if err != nil {
		log.Fatalf("%v", err)
	}
	resolved, err := ensureConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to prepare config: %v", err)
	}
	if _, err := rebuildFrontend(resolved, tag); err != nil {
		log.Fatalf("Failed to build frontend: %v", err)
	}
}
