package image

import (
	"strings"
	"testing"

	"github.com/mralves/whalevet/internal/config"
)

func TestModifyCACertSetsTrustEnvVars(t *testing.T) {
	in := "FROM debian:12\n"
	got := Modify(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	})

	wantEnv := []string{
		"ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"ENV SSL_CERT_DIR=/etc/ssl/certs",
		"ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		"ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		"ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt",
		"ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt",
	}
	for _, w := range wantEnv {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in output:\n%s", w, got)
		}
	}
}

func TestModifyCACertAlpineBundlePath(t *testing.T) {
	in := "FROM alpine:3.19\n"
	got := Modify(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	})
	if !strings.Contains(got, "ENV SSL_CERT_FILE=/etc/ssl/cert.pem") {
		t.Errorf("alpine should use /etc/ssl/cert.pem bundle:\n%s", got)
	}
	if !strings.Contains(got, "RUN apk add --no-cache --no-check-certificate ca-certificates") {
		t.Errorf("alpine install command missing:\n%s", got)
	}
}

func TestModifyInlineCACertSetsTrustEnvVars(t *testing.T) {
	in := "FROM centos:7\n"
	got := ModifyInline(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	}, map[string][]byte{"root.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")})

	if !strings.Contains(got, "ENV SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt") {
		t.Errorf("centos should use RHEL bundle:\n%s", got)
	}
	if !strings.Contains(got, "RUN yum install -y --nogpgcheck --setopt=sslverify=0 ca-certificates") {
		t.Errorf("centos install command missing:\n%s", got)
	}
}

func TestGenerateCACertInlineLinesAppendsToBundleAfterUpdate(t *testing.T) {
	certs := map[string][]byte{"root.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")}
	out := strings.Join(GenerateCACertInlineLines(certs, OSFedora), "\n")

	// The append must run after the store update, since update commands
	// overwrite the bundle.
	if !strings.Contains(out, "RUN update-ca-trust extract\n# --- injected by whalevet: ensure certs appear in CA bundles ---\nRUN for __b") {
		t.Errorf("bundle append should follow the store update:\n%s", out)
	}
	if !strings.Contains(out, "'/etc/pki/tls/certs/ca-bundle.crt'") {
		t.Errorf("RHEL BundlePath missing from append targets:\n%s", out)
	}
	// The dedupe must use a body-line marker, not the shared BEGIN header.
	if strings.Contains(out, "head -c 64") {
		t.Errorf("dedupe must not use head -c 64 (matches every cert):\n%s", out)
	}
	if !strings.Contains(out, "sed -n '2p'") {
		t.Errorf("dedupe marker should be the first base64 body line:\n%s", out)
	}
}

func TestGenerateCACertDockerfileLinesAppendsBundlePath(t *testing.T) {
	out := strings.Join(GenerateCACertDockerfileLines([]string{"root.pem"}, OSArch), "\n")

	if !strings.Contains(out, "'/etc/ssl/certs/ca-certificates.crt'") {
		t.Errorf("arch BundlePath missing from append targets:\n%s", out)
	}
	if !strings.Contains(out, "RUN trust extract-compat\n# --- injected by whalevet: ensure certs appear in CA bundles ---") {
		t.Errorf("arch append should follow trust extract-compat:\n%s", out)
	}
}

func TestAppendExtraBundlesCmdUsesBodyMarker(t *testing.T) {
	cmd := AppendExtraBundlesCmd([]string{"/etc/pki/ca-trust/source/anchors/root.crt"}, "/etc/pki/tls/certs/ca-bundle.crt")

	if strings.Contains(cmd, "head -c") {
		t.Errorf("dedupe must not rely on the shared PEM header:\n%s", cmd)
	}
	for _, want := range []string{"'/cacert.pem'", "'/etc/ssl/cert.pem'", "'/etc/pki/tls/certs/ca-bundle.crt'", "sed -n '2p'", "cut -c1-40"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("append snippet missing %q:\n%s", want, cmd)
		}
	}
}
