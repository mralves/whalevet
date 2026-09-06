package frontend

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
)

// Injection rules are baked into the wrapper image at build time
// (docker build --build-arg RULES_JSON=... --build-arg CERTS_JSON=...)
// because per-build FrontendOpts do not survive to directive-triggered
// frontends. CERTS_JSON maps cert basename -> base64 content.
const (
	rulesEnv = "PROXY_RULES_JSON"
	certsEnv = "PROXY_CERTS_JSON"
)

// applyProxyRules decodes baked-in injection rules and applies line-based
// rules (run, from) plus inline CA certs. Returns data unchanged when no
// rules are baked in.
func applyProxyRules(data []byte, opts map[string]string) []byte {
	_ = opts
	encoded := os.Getenv(rulesEnv)
	if encoded == "" {
		return data
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("[wrapper] failed to decode rules: %v", err)
		return data
	}

	var rules []config.Injection
	if err := json.Unmarshal(raw, &rules); err != nil {
		log.Printf("[wrapper] failed to parse rules: %v", err)
		return data
	}

	certs := decodeProxyCerts()
	log.Printf("[wrapper] applying %d rules to Dockerfile (%d bytes)", len(rules), len(data))
	modified := image.ModifyInline(string(data), rules, certs)
	log.Printf("[wrapper] Dockerfile modified (%d -> %d bytes)", len(data), len(modified))
	return []byte(modified)
}

// decodeProxyCerts returns cert basename -> content from the baked env.
func decodeProxyCerts() map[string][]byte {
	encoded := os.Getenv(certsEnv)
	if encoded == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("[wrapper] failed to decode certs: %v", err)
		return nil
	}
	var b64map map[string]string
	if err := json.Unmarshal(raw, &b64map); err != nil {
		log.Printf("[wrapper] failed to parse certs: %v", err)
		return nil
	}
	out := make(map[string][]byte, len(b64map))
	for name, b64 := range b64map {
		content, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Printf("[wrapper] failed to decode cert %s: %v", name, err)
			continue
		}
		out[name] = content
	}
	return out
}
