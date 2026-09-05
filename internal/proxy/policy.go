package proxy

import (
	"strings"

	"github.com/mralves/whalevet/internal/cache"
	"github.com/mralves/whalevet/internal/config"
)

// policyAllowed evaluates the config's [policy] allow/deny patterns for an
// image reference. A match against any Deny pattern blocks; otherwise an
// non-empty Allow list must match at least one pattern. Refs already produced
// by the proxy (whalevet-injected/...) are always allowed. Returns whether
// the ref passes and, when denied, why.
func policyAllowed(cfg *config.Config, ref string) (bool, string) {
	if strings.HasPrefix(ref, cache.ProxyImagePrefix) {
		return true, ""
	}
	if matchAny(cfg.Policy.Deny, ref) {
		return false, "matches a deny pattern"
	}
	if len(cfg.Policy.Allow) > 0 {
		if matchAny(cfg.Policy.Allow, ref) {
			return true, ""
		}
		return false, "does not match any allow pattern"
	}
	return true, ""
}

func matchAny(patterns []string, ref string) bool {
	for _, p := range patterns {
		if globMatch(p, ref) {
			return true
		}
	}
	return false
}

// globMatch reports whether ref matches pattern. `*` matches any run of
// non-'/' characters, `**` any run including '/', `?` a single non-'/'
// character. Everything else matches literally.
func globMatch(pattern, ref string) bool {
	for {
		if pattern == "" {
			return ref == ""
		}
		switch pattern[0] {
		case '*':
			if strings.HasPrefix(pattern, "**") {
				rest := pattern[2:]
				for i := 0; i <= len(ref); i++ {
					if globMatch(rest, ref[i:]) {
						return true
					}
				}
				return false
			}
			rest := pattern[1:]
			for i := 0; i <= len(ref); i++ {
				if globMatch(rest, ref[i:]) {
					return true
				}
				if i < len(ref) && ref[i] == '/' {
					break
				}
			}
			return false
		case '?':
			if ref == "" || ref[0] == '/' {
				return false
			}
			pattern, ref = pattern[1:], ref[1:]
		default:
			if ref == "" || pattern[0] != ref[0] {
				return false
			}
			pattern, ref = pattern[1:], ref[1:]
		}
	}
}
