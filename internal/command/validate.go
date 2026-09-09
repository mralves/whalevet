package command

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
)

// RunValidate loads the config and checks every injection rule for syntax,
// referenced certs, env templates and position/ordering clashes, plus the
// policy patterns. Exits non-zero when the config cannot be trusted as-is.
func RunValidate(configPath string, args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: whalevet [--config PATH] validate")
		os.Exit(2)
	}

	resolved, err := config.ResolvePath(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s config file not found: %v\n", color.RedString("FAIL"), err)
		os.Exit(1)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s config is invalid: %v\n", color.RedString("FAIL"), err)
		os.Exit(1)
	}

	ok := true
	fmt.Printf("%s\n", color.CyanString("Checking config %s", resolved))

	for i := range cfg.Injections {
		if err := validateInjection(&cfg.Injections[i], filepath.Dir(resolved)); err != nil {
			ok = false
			fmt.Printf("  %s injection[%d]: %v\n", color.RedString("[FAIL]"), i, err)
			continue
		}
		fmt.Printf("  %s   injection[%d]: %s", color.GreenString("[OK]"), i, cfg.Injections[i].Type)
		if cfg.Injections[i].EnvFile != "" {
			fmt.Printf(" (env_file=%s)", cfg.Injections[i].EnvFile)
		}
		fmt.Println()
	}

	if err := validatePositionClashes(cfg.Injections); err != nil {
		ok = false
		fmt.Printf("  %s injections: %v\n", color.RedString("[FAIL]"), err)
	}

	if err := validatePolicy(cfg.Policy); err != nil {
		ok = false
		fmt.Printf("  %s policy: %v\n", color.RedString("[FAIL]"), err)
	} else if len(cfg.Policy.Allow) > 0 || len(cfg.Policy.Deny) > 0 {
		fmt.Printf("  %s   policy: %d allow / %d deny patterns\n",
			color.GreenString("[OK]"), len(cfg.Policy.Allow), len(cfg.Policy.Deny))
	}

	if ok {
		fmt.Println(color.GreenString("Validation passed."))
		return
	}
	fmt.Println(color.RedString("\nValidation failed."))
	os.Exit(1)
}

var knownTypes = map[string]bool{
	"ca_certificates": true,
	"run":             true,
	"from":            true,
	"env":             true,
}

var validPositions = map[string]bool{
	"after_base":        true,
	"before_entrypoint": true,
}

func validateInjection(inj *config.Injection, baseDir string) error {
	if !knownTypes[inj.Type] {
		return fmt.Errorf("unknown type %q (want ca_certificates, run, from or env)", inj.Type)
	}

	if inj.Position != "" && !validPositions[inj.Position] {
		return fmt.Errorf("invalid position %q (want after_base or before_entrypoint)", inj.Position)
	}

	switch inj.Type {
	case "ca_certificates":
		if len(inj.Certificates) == 0 && len(inj.Env) == 0 && inj.EnvFile == "" {
			return errors.New("ca_certificates needs at least one certificate or env var")
		}
		for _, p := range inj.Certificates {
			if err := validateCertFile(p); err != nil {
				return err
			}
		}
	case "run":
		if strings.TrimSpace(inj.Command) == "" {
			return errors.New("run needs a non-empty command")
		}
	case "from":
		if inj.Pattern == "" {
			return errors.New("from needs a non-empty pattern")
		}
		if _, err := regexp.Compile(inj.Pattern); err != nil {
			return fmt.Errorf("from pattern %q does not compile: %w", inj.Pattern, err)
		}
		if inj.Replacement == "" {
			return errors.New("from needs a non-empty replacement")
		}
	case "env":
		if len(inj.Env) == 0 && inj.EnvFile == "" {
			return errors.New("env needs env vars or an env_file")
		}
	}

	if inj.EnvFile != "" {
		path := inj.EnvFile
		if !filepath.IsAbs(path) && baseDir != "" {
			path = filepath.Join(baseDir, path)
		}
		content, err := os.ReadFile(path) //nolint:gosec // env_file path comes from the local trusted config
		if err != nil {
			return fmt.Errorf("env_file %q not readable: %w", inj.EnvFile, err)
		}
		if _, err := config.ParseEnvFile(content); err != nil {
			return fmt.Errorf("env_file %q: %w", inj.EnvFile, err)
		}
	}

	// Validate env template placeholders (values may use {{.BundlePath}} etc.).
	for k, v := range inj.Env {
		if err := validateEnvTemplate(k, v); err != nil {
			return err
		}
	}
	return nil
}

func validateEnvTemplate(key, value string) error {
	if !strings.Contains(value, "{{") {
		return nil
	}
	tmpl, err := template.New("env").Parse(value)
	if err != nil {
		return fmt.Errorf("env %s value %q is not a valid template: %w", key, value, err)
	}
	// A zero EnvContext resolves every documented placeholder; missing fields
	// would fail execution and are reported here.
	var sink strings.Builder
	if err := tmpl.Execute(&sink, image.EnvContext{}); err != nil {
		return fmt.Errorf("env %s value %q fails when rendered: %w", key, value, err)
	}
	return nil
}

// validatePositionClashes flags conflicting values for the same env key
// injected after the base image: the generated Dockerfile keeps only the last
// ENV line, so divergent values are almost certainly a mistake.
func validatePositionClashes(rules []config.Injection) error {
	values := map[string]string{}
	for _, r := range rules {
		pos := r.Position
		if pos == "" {
			pos = "after_base"
		}
		if pos != "after_base" {
			continue
		}
		for k, v := range r.Env {
			if prev, ok := values[k]; ok && prev != v {
				return fmt.Errorf("env key %q has conflicting after_base values %q vs %q", k, prev, v)
			}
			values[k] = v
		}
	}
	return nil
}

func validateCertFile(path string) error {
	content, err := os.ReadFile(path) //nolint:gosec // cert path comes from the local trusted config
	if err != nil {
		return fmt.Errorf("certificate %q not readable: %w", path, err)
	}
	found := false
	for rest := content; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			found = true
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return fmt.Errorf("certificate %q does not parse: %w", path, err)
			}
		}
	}
	if !found {
		return fmt.Errorf("certificate %q contains no PEM CERTIFICATE blocks", path)
	}
	return nil
}

func validatePolicy(p config.PolicyConfig) error {
	patterns := append(append([]string{}, p.Allow...), p.Deny...)
	for _, pat := range patterns {
		if strings.TrimSpace(pat) == "" {
			return errors.New("empty pattern in allow/deny list")
		}
	}
	return nil
}
