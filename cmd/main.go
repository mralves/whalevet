package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mralves/whalevet/internal/command"
)

func main() {
	configPath, rest, err := parseGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		usage()
		os.Exit(2)
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}

	switch rest[0] {
	case "frontend":
		command.RunFrontend(rest[1:])
	case "serve":
		command.RunServe(configPath, rest[1:])
	case "setup":
		command.RunSetup(configPath, rest[1:])
	case "build":
		command.RunBuild(configPath, rest[1:])
	case "doctor":
		command.RunDoctor(configPath, rest[1:])
	case "validate":
		command.RunValidate(configPath, rest[1:])
	case "status":
		command.RunStatus(configPath, rest[1:])
	case "version":
		command.RunVersion(rest[1:])
	case "uninstall":
		command.RunUninstall(configPath, rest[1:])
	case "prune":
		command.RunPrune(configPath, rest[1:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", rest[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: whalevet [--config PATH] <command> [args]

Commands:
  serve [socket]   Start the proxy server. Optional socket overrides the
                   listen address from the config file. Reloads the config
                   on SIGHUP.
  setup [tag]      Build the frontend wrapper image, install a systemd user
                   service, and configure DOCKER_HOST in the shell rc.
                   Optional tag overrides frontend_tag from the config file.
  build [tag]      Build the frontend wrapper image only. Optional tag
                   overrides frontend_tag from the config file.
  validate         Check the config file (rule syntax, certs, templates,
                   positions, policy) and exit non-zero on problems.
  status           Show the state of the install (config, socket, image,
                   service, shell rc). Always exits 0.
  version          Print the whalevet version and exit.
  doctor           Verify that setup was done correctly and report mistakes.
  uninstall        Remove the systemd service, shell rc entry, and all
                   whalevet images. Confirms unless --yes is passed.
  prune            Remove whalevet-injected images and stale frontend
                   tags. Confirms unless --yes is passed.

Global flags:
  --config PATH    Path to the config file (default: %s)
`, defaultConfigPath())
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		// No user config dir (e.g. HOME unset): fall back to a bare relative path.
		return "whalevet.toml"
	}
	return filepath.Join(dir, "whalevet", "config.toml")
}

func parseGlobalFlags(args []string) (configPath string, rest []string, err error) {
	configPath = defaultConfigPath()
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--config" || a == "-config" {
			if i+1 >= len(args) {
				return "", nil, errors.New("--config requires a value")
			}
			configPath = args[i+1]
			i++
			continue
		}
		if after, ok := strings.CutPrefix(a, "--config="); ok {
			configPath = after
			continue
		}
		rest = append(rest, a)
	}
	return configPath, rest, nil
}
