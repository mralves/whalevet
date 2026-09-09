package command

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mralves/whalevet/internal/config"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeCert(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "whalevet-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateInjectionValid(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	writeCert(t, cert)
	writeFile(t, filepath.Join(dir, "vars.env"), "FROM_FILE=yes\n")

	cases := []config.Injection{
		{Type: "ca_certificates", Certificates: []string{cert}},
		{Type: "run", Command: "apt-get update", Position: "after_base"},
		{Type: "from", Pattern: "^ubuntu:", Replacement: "mirror/ubuntu:"},
		{Type: "env", Env: map[string]string{"A": "b"}},
		{Type: "env", Env: map[string]string{"B": "{{.BundlePath}}"}, EnvFile: "vars.env"},
	}
	for _, c := range cases {
		if err := validateInjection(&c, dir); err != nil {
			t.Errorf("injection %#v: unexpected error %v", c, err)
		}
	}
}

func TestValidateInjectionInvalid(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	writeCert(t, cert)

	cases := []config.Injection{
		{Type: "bogus"},
		{Type: "ca_certificates"},
		{Type: "ca_certificates", Certificates: []string{filepath.Join(dir, "missing.pem")}},
		{Type: "ca_certificates", Certificates: []string{cert}, Position: "sideways"},
		{Type: "run", Command: "  "},
		{Type: "from", Pattern: "(", Replacement: "x"},
		{Type: "from", Pattern: "ubuntu", Replacement: ""},
		{Type: "env"},
		{Type: "env", Env: map[string]string{"A": "b"}, EnvFile: "missing.env"},
		{Type: "env", EnvFile: "bad.env"},
		{Type: "env", Env: map[string]string{"X": "{{.Nope}}"}},
	}
	writeFile(t, filepath.Join(dir, "bad.env"), "NOEQUALS\n")
	for _, c := range cases {
		if err := validateInjection(&c, dir); err == nil {
			t.Errorf("injection %#v: expected error, got nil", c)
		}
	}
}

func TestValidatePositionClashes(t *testing.T) {
	if err := validatePositionClashes([]config.Injection{
		{Type: "env", Env: map[string]string{"K": "a"}},
		{Type: "env", Env: map[string]string{"K": "a"}},
	}); err != nil {
		t.Fatalf("identical values should not clash: %v", err)
	}
	if err := validatePositionClashes([]config.Injection{
		{Type: "env", Env: map[string]string{"K": "a"}},
		{Type: "env", Env: map[string]string{"K": "b"}},
	}); err == nil {
		t.Fatal("conflicting after_base values should be flagged")
	}
}

func TestRunValidateSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeCert(t, filepath.Join(dir, "ca.pem"))
	content := `[proxy]
listen = "unix:///tmp/dsp.sock"

[[injections]]
type = "ca_certificates"
certificates = ["` + dir + `/ca.pem"]
`
	writeFile(t, cfgPath, content)

	out := captureStdout(t, func() { RunValidate(cfgPath, nil) })
	if !strings.Contains(out, "Validation passed.") {
		t.Fatalf("expected success, got:\n%s", out)
	}
}

func TestValidateEnvTemplateRenders(t *testing.T) {
	// Documented placeholders must resolve against a zero EnvContext.
	for _, val := range []string{"{{.BundlePath}}", "x{{.TrustDir}}y", "{{.CertDir}}"} {
		if err := validateEnvTemplate("K", val); err != nil {
			t.Errorf("value %q: %v", val, err)
		}
	}
}
