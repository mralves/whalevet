package image

import (
	"sort"
	"strings"
	"text/template"
)

// EnvContext supplies values for template placeholders in injected env vars.
// Placeholders allow a single config to map onto both the build path (OS
// detected from the Dockerfile FROM line) and the container-inject path (CA
// bundle probed inside the actual image), so the container environment
// matches the baked-in image environment.
type EnvContext struct {
	// BundlePath is the single-file CA bundle that received the injected
	// certificates (e.g. /etc/ssl/certs/ca-certificates.crt).
	BundlePath string
	// TrustDir is the hashed certificate directory (for SSL_CERT_DIR).
	TrustDir string
	// CertDir is the drop-in anchor directory cert .crt files are copied to.
	CertDir string
}

// RenderEnvValue renders one env value against ctx. Plain values pass through
// unchanged; unresolvable templates fall back to the raw text.
func RenderEnvValue(value string, ctx EnvContext) string {
	if !strings.Contains(value, "{{") {
		return value
	}
	tmpl, err := template.New("env").Parse(value)
	if err != nil {
		return value
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, ctx); err != nil {
		return value
	}
	return sb.String()
}

// renderEnvKVs renders "KEY=value" lines, templating the value part only.
func renderEnvKVs(kvs []string, ctx EnvContext) []string {
	out := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			out = append(out, kv)
			continue
		}
		out = append(out, kv[:i+1]+RenderEnvValue(kv[i+1:], ctx))
	}
	return out
}

// mergeEnv folds overrides into a base env list (later keys win). Keys already
// present in base keep their position with the overridden value; new keys are
// appended in sorted order for deterministic output.
func mergeEnv(base, overrides []string) []string {
	over := map[string]string{}
	for _, kv := range overrides {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		over[k] = v
	}

	var merged []string
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			merged = append(merged, kv)
			continue
		}
		if v, ok := over[k]; ok {
			delete(over, k)
			merged = append(merged, k+"="+v)
		} else {
			merged = append(merged, kv)
		}
	}

	keys := make([]string, 0, len(over))
	for k := range over {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		merged = append(merged, k+"="+over[k])
	}
	return merged
}
