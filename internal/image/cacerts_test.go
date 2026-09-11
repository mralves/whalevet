package image

import (
	"encoding/base64"
	"regexp"
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

func TestGenerateCACertInlineLinesLargeMultiCertBundleSplitsPerCert(t *testing.T) {
	// ~200KB of PEM (multi-cert bundle): single-line embedding exceeds
	// BuildKit's per-line cap and the /bin/sh -c argument cap
	// (MAX_ARG_STRLEN), which is what killed the build with "line greater than
	// max allowed size of 65535" / exit 255.
	const blocks = 2500
	large := strings.Repeat("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n", blocks)
	out := strings.Join(GenerateCACertInlineLines(map[string][]byte{
		"big.pem": []byte(large),
	}, OSDebian), "\n")

	for i, line := range strings.Split(out, "\n") {
		if len(line) > 65535 {
			t.Fatalf("line %d is %d bytes, exceeding BuildKit's 65535 cap", i, len(line))
		}
	}

	// Every `printf '%s' '<chunk>'` write must be base64: collecting all chunk
	// payloads and decoding them must reproduce the original certificate.
	chunkPat := regexp.MustCompile(`RUN (?:mkdir -p [^ ]+ && )?printf '%s' '([^']*)' (?:>|>>)`)
	var chunks []string
	for _, m := range chunkPat.FindAllStringSubmatch(out, -1) {
		chunks = append(chunks, m[1])
	}
	if len(chunks) < 2 {
		t.Fatalf("expected the payload to be chunked, got %d chunk(s)", len(chunks))
	}
	joined := strings.Join(chunks, "")
	decoded, err := base64.StdEncoding.DecodeString(joined)
	if err != nil {
		t.Fatalf("chunk payload is not valid base64: %v", err)
	}
	if string(decoded) != large {
		t.Fatalf("decoded payload differs from original: got %d bytes, want %d", len(decoded), len(large))
	}

	// Multi-cert bundles must be split into one file per certificate, fed
	// through awk, and the append step must sweep the cert dir with a glob
	// (never a literal per-file list, which would exceed the line cap).
	if !strings.Contains(out, "awk -v D=") {
		t.Fatalf("missing per-cert awk split for multi-cert bundle:\n%s", out)
	}
	if !strings.Contains(out, "for __f in /usr/local/share/ca-certificates/*.crt") {
		t.Fatalf("append step must use a glob over the cert dir:\n%s", out)
	}
	if strings.Contains(out, "base64 -d /usr/local/share/ca-certificates/big.crt.b64 >") {
		t.Fatalf("multi-cert bundle must not be written as a single .crt file:\n%s", out)
	}
}

func TestGenerateCACertInlineLinesSingleCertWritesFileWhole(t *testing.T) {
	single := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
	out := strings.Join(GenerateCACertInlineLines(map[string][]byte{
		"root.pem": []byte(single),
	}, OSDebian), "\n")

	// Single-cert content keeps the whole-file path: direct base64 -d to the
	// .crt target, no awk split.
	if !strings.Contains(out, "&& rm /usr/local/share/ca-certificates/root.crt.b64 && chmod 644 /usr/local/share/ca-certificates/root.crt") {
		t.Fatalf("single-cert bundle should be written whole:\n%s", out)
	}
	if strings.Contains(out, "awk -v D=") {
		t.Fatalf("single-cert bundle must not be awk-split:\n%s", out)
	}
	if !strings.Contains(out, "for __f in /usr/local/share/ca-certificates/*.crt") {
		t.Fatalf("append step must sweep the cert dir:\n%s", out)
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
	cmd := AppendExtraBundlesCmd([]string{"/etc/pki/ca-trust/source/anchors/*.crt"}, "/etc/pki/tls/certs/ca-bundle.crt")

	if strings.Contains(cmd, "head -c") {
		t.Errorf("dedupe must not rely on the shared PEM header:\n%s", cmd)
	}
	for _, want := range []string{"'/cacert.pem'", "'/etc/ssl/cert.pem'", "'/etc/pki/tls/certs/ca-bundle.crt'", "sed -n '2p'", "cut -c1-40"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("append snippet missing %q:\n%s", want, cmd)
		}
	}
	// Globs stay unquoted so they expand at shell runtime, and unmatched
	// globs are guarded by the -f check.
	if !strings.Contains(cmd, "/etc/pki/ca-trust/source/anchors/*.crt") {
		t.Errorf("cert glob should be emitted unquoted:\n%s", cmd)
	}
	if !strings.Contains(cmd, "[ -f \"$__f\" ] || continue") {
		t.Errorf("unmatched globs must be guarded:\n%s", cmd)
	}
}
