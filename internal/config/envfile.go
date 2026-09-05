package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseEnvFile parses KEY=VALUE lines (blank lines and # comments ignored).
// Values may be single- or double-quoted; quotes are stripped.
func ParseEnvFile(content []byte) (map[string]string, error) {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return nil, fmt.Errorf("line %q is not KEY=VALUE", trimmed)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		if key == "" {
			return nil, fmt.Errorf("line %q has an empty key", trimmed)
		}
		out[key] = value
	}
	return out, nil
}

// ExpandEnvFiles returns a copy of rules whose EnvFile entries have been
// merged into rule.Env. Inline Env values win over file entries. Relative
// env_file paths are resolved against baseDir (usually the config dir); a
// missing or unparseable file is an error.
func ExpandEnvFiles(rules []Injection, baseDir string) ([]Injection, error) {
	out := make([]Injection, len(rules))
	copy(out, rules)
	for i, rule := range out {
		if rule.EnvFile == "" {
			continue
		}
		path := rule.EnvFile
		if !filepath.IsAbs(path) && baseDir != "" {
			path = filepath.Join(baseDir, path)
		}
		content, err := os.ReadFile(path) //nolint:gosec // env_file path comes from the local trusted config, not remote input
		if err != nil {
			return nil, fmt.Errorf("read env_file %q: %w", rule.EnvFile, err)
		}
		fileEnv, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("parse env_file %q: %w", rule.EnvFile, err)
		}
		if out[i].Env == nil {
			out[i].Env = map[string]string{}
		}
		for k, v := range fileEnv {
			if _, ok := out[i].Env[k]; !ok {
				out[i].Env[k] = v
			}
		}
	}
	return out, nil
}
