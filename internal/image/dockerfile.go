package image

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mralves/whalevet/internal/config"
)

type InjectionPosition int

const (
	PositionAfterBase InjectionPosition = iota
	PositionBeforeEntrypoint
)

func ParsePosition(s string) InjectionPosition {
	switch strings.ToLower(s) {
	case "before_entrypoint":
		return PositionBeforeEntrypoint
	default:
		return PositionAfterBase
	}
}

// sortedEnvLines renders env map entries as deterministic "KEY=value" lines
// (keys sorted) so generated Dockerfiles are stable.
func sortedEnvLines(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+env[k])
	}
	return lines
}

type parsedLine struct {
	raw     string
	isFROM  bool
	isCMD   bool
	isENTRY bool
}

func parseDockerfile(content string) []parsedLine {
	var lines []parsedLine
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		pl := parsedLine{raw: line}
		if strings.ToUpper(strings.TrimLeft(trimmed, " ")) == "FROM" ||
			strings.HasPrefix(strings.ToUpper(trimmed), "FROM ") ||
			strings.HasPrefix(strings.ToUpper(trimmed), "FROM\t") {
			pl.isFROM = true
		}
		if strings.ToUpper(trimmed) == "CMD" || strings.HasPrefix(strings.ToUpper(trimmed), "CMD ") {
			pl.isCMD = true
		}
		if strings.ToUpper(trimmed) == "ENTRYPOINT" || strings.HasPrefix(strings.ToUpper(trimmed), "ENTRYPOINT ") {
			pl.isENTRY = true
		}
		lines = append(lines, pl)
	}
	return lines
}

func Modify(content string, rules []config.Injection) string {
	return modify(content, rules, nil, false)
}

// ModifyInline applies rules like Modify, but CA certificates are embedded
// inline (cert name -> content) instead of COPYed, for frontends that cannot
// add files to the build context.
func ModifyInline(content string, rules []config.Injection, certContents map[string][]byte) string {
	return modify(content, rules, certContents, true)
}

// ModifyCopy applies rules like Modify with certificate contents available,
// so the legacy COPY path can split multi-cert bundles into one COPY per
// certificate (see ExpandCertFilesForContext). certFiles maps the build
// context entry name (the COPY source, which the caller must place in the
// context tar) to its PEM content.
func ModifyCopy(content string, rules []config.Injection, certFiles map[string][]byte) string {
	return modify(content, rules, certFiles, false)
}

func modify(content string, rules []config.Injection, certContents map[string][]byte, inline bool) string {
	parsed := parseDockerfile(content)

	var fromReplacements []config.Injection
	var caCerts []string
	var runAfterBase []string
	var runBeforeEntrypoint []string
	var envAfterBase []string
	var envBeforeEntrypoint []string
	var extraCAEnv []string

	for _, rule := range rules {
		switch rule.Type {
		case "from":
			fromReplacements = append(fromReplacements, rule)
		case "ca_certificates":
			caCerts = append(caCerts, rule.Certificates...)
			extraCAEnv = append(extraCAEnv, sortedEnvLines(rule.Env)...)
		case "run":
			pos := ParsePosition(rule.Position)
			switch pos {
			case PositionBeforeEntrypoint:
				runBeforeEntrypoint = append(runBeforeEntrypoint, rule.Command)
			default:
				runAfterBase = append(runAfterBase, rule.Command)
			}
		case "env":
			pos := ParsePosition(rule.Position)
			for _, kv := range sortedEnvLines(rule.Env) {
				switch pos {
				case PositionBeforeEntrypoint:
					envBeforeEntrypoint = append(envBeforeEntrypoint, kv)
				default:
					envAfterBase = append(envAfterBase, kv)
				}
			}
		}
	}

	certLines := func(fromLine string) []string {
		if len(caCerts) == 0 {
			return nil
		}
		os := DetectOSFromFROM(fromLine)
		if inline {
			return GenerateCACertInlineLines(certContents, os)
		}
		return GenerateCACertDockerfileLines(dockerfileCertFiles(caCerts, certContents), os)
	}

	var result []string
	injectedAfterBase := false
	injectedCerts := false
	var envCtx EnvContext

	for i, pl := range parsed {
		line := pl.raw

		if pl.isFROM {
			for _, fr := range fromReplacements {
				re := regexp.MustCompile(fr.Pattern)
				line = re.ReplaceAllString(line, fr.Replacement)
			}
		}

		result = append(result, line)

		// After the first FROM, inject "run after base" commands, ENV vars
		// and CA certs
		if pl.isFROM && !injectedAfterBase {
			injectedAfterBase = true
			os := DetectOSFromFROM(line)
			cfg := GetCACertConfig(os)
			envCtx = EnvContext{
				BundlePath: cfg.BundlePath,
				TrustDir:   cfg.TrustDir,
				CertDir:    cfg.CertDir,
			}
			for _, cmd := range runAfterBase {
				result = append(result, "# --- injected by whalevet ---")
				result = append(result, "RUN "+cmd)
			}
			for _, kv := range renderEnvKVs(envAfterBase, envCtx) {
				result = append(result, "# --- injected by whalevet ---")
				result = append(result, "ENV "+kv)
			}
			if len(caCerts) > 0 && !injectedCerts {
				injectedCerts = true
				result = append(result, certLines(line)...)
				for _, kv := range renderEnvKVs(extraCAEnv, envCtx) {
					result = append(result, "# --- injected by whalevet ---")
					result = append(result, "ENV "+kv)
				}
			}
		}

		// Before ENTRYPOINT/CMD, inject "run before entrypoint" commands and
		// ENV vars
		if (pl.isENTRY || pl.isCMD) && (len(runBeforeEntrypoint) > 0 || len(envBeforeEntrypoint) > 0) {
			for _, cmd := range runBeforeEntrypoint {
				result = append(result, "# --- injected by whalevet ---")
				result = append(result, "RUN "+cmd)
			}
			runBeforeEntrypoint = nil // only inject once
			for _, kv := range renderEnvKVs(envBeforeEntrypoint, envCtx) {
				result = append(result, "# --- injected by whalevet ---")
				result = append(result, "ENV "+kv)
			}
			envBeforeEntrypoint = nil // only inject once
		}

		_ = i
	}

	if len(runBeforeEntrypoint) > 0 || len(envBeforeEntrypoint) > 0 {
		for _, cmd := range runBeforeEntrypoint {
			result = append(result, "# --- injected by whalevet ---")
			result = append(result, "RUN "+cmd)
		}
		for _, kv := range renderEnvKVs(envBeforeEntrypoint, envCtx) {
			result = append(result, "# --- injected by whalevet ---")
			result = append(result, "ENV "+kv)
		}
	}

	if !injectedCerts && len(caCerts) > 0 {
		if inline {
			result = append(result, GenerateCACertInlineLines(certContents, OSUnknown)...)
		} else {
			result = append(result, GenerateCACertDockerfileLines(dockerfileCertFiles(caCerts, certContents), OSUnknown)...)
		}
		for _, kv := range extraCAEnv {
			result = append(result, "# --- injected by whalevet ---")
			result = append(result, "ENV "+kv)
		}
	}

	return strings.Join(result, "\n")
}

// dockerfileCertFiles returns the cert file set for the legacy COPY path:
// the provided contents when available, otherwise a name-only set keyed by
// each certificate's basename (kept whole, never split, since no content is
// available to split from).
func dockerfileCertFiles(caCerts []string, certFiles map[string][]byte) map[string][]byte {
	if certFiles != nil {
		return certFiles
	}
	files := make(map[string][]byte, len(caCerts))
	for _, cert := range caCerts {
		files[filepath.Base(cert)] = nil
	}
	return files
}
