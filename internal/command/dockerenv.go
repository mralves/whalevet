package command

import (
	"os"
	"strings"
)

// dockerEnv returns the process environment for a docker CLI subprocess, with
// DOCKER_HOST adjusted so the operator commands' docker calls never route
// through the proxy. When the inherited DOCKER_HOST points at the proxy's own
// listen socket (exported into the shell rc by a previous setup, but the proxy
// may not be running yet or may be mid-restart), it is cleared so the CLI
// falls back to its default endpoint; any other DOCKER_HOST is preserved
// as-is.
func dockerEnv(proxyListen string) []string {
	env := os.Environ()
	value, key, ok := findEnv(env, "DOCKER_HOST")
	if !ok || value == "" {
		return env
	}
	if sockPath(proxyListen) != sockPath(value) {
		return env
	}
	return append(append(env[:key], env[key+1:]...), "DOCKER_HOST=")
}

// findEnv locates a VAR=VALUE entry and returns its value, its index, and
// whether it was present.
func findEnv(env []string, name string) (value string, index int, ok bool) {
	prefix := name + "="
	for i, kv := range env {
		if rest, found := strings.CutPrefix(kv, prefix); found {
			return rest, i, true
		}
	}
	return "", -1, false
}

// sockPath reduces a DOCKER_HOST-style endpoint ("unix:///path" or a bare
// "/path") to its socket path for comparison.
func sockPath(host string) string {
	rest, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		return host
	}
	return rest
}
