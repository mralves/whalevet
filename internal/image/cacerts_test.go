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

// TestModifyCACertDistroDetectionIndependent verifies injection no longer
// depends on the image name: a custom base image still gets the in-container
// distro detection script, the canonical bundle env, and the detected
// install/update RUN lines.
func TestModifyCACertDistroDetectionIndependent(t *testing.T) {
	in := "FROM mycorp/private-base:v3\n"
	got := Modify(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	})

	for _, w := range []string{
		"RUN . /etc/wv-ccenv.sh && eval \"$WV_INSTALL\"",
		"RUN . /etc/wv-ccenv.sh && eval \"$WV_UPDATE\"",
		"ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"ENV SSL_CERT_DIR=/etc/ssl/certs",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in output:\n%s", w, got)
		}
	}
}

func TestModifyCACertAlpineNoNameBasedBundlePath(t *testing.T) {
	// Alpine-specific names must no longer drive the bundle path: env always
	// points at the canonical bundle committed to the image.
	in := "FROM alpine:3.19\n"
	got := Modify(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	})
	if strings.Contains(got, "ENV SSL_CERT_FILE=/etc/ssl/cert.pem") {
		t.Errorf("alpine must not use a name-derived bundle path:\n%s", got)
	}
	if !strings.Contains(got, "ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt") {
		t.Errorf("env must point at the canonical bundle:\n%s", got)
	}
	if !strings.Contains(got, "RUN . /etc/wv-ccenv.sh && eval \"$WV_INSTALL\"") {
		t.Errorf("install must run via in-container detection:\n%s", got)
	}
}

func TestModifyInlineCACertSetsTrustEnvVars(t *testing.T) {
	in := "FROM centos:7\n"
	got := ModifyInline(in, []config.Injection{
		{Type: "ca_certificates", Certificates: []string{"root.pem"}},
	}, map[string][]byte{"root.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")})

	if !strings.Contains(got, "ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt") {
		t.Errorf("env must point at the canonical bundle:\n%s", got)
	}
	if !strings.Contains(got, "RUN . /etc/wv-ccenv.sh && eval \"$WV_INSTALL\"") {
		t.Errorf("install must run via in-container detection:\n%s", got)
	}
}

func TestGenerateCACertInlineLinesAppendsToBundleAfterUpdate(t *testing.T) {
	certs := map[string][]byte{"root.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")}
	out := strings.Join(GenerateCACertInlineLines(certs), "\n")

	// The append must run after the store update, since update commands
	// overwrite the bundle.
	if !strings.Contains(out, "RUN . /etc/wv-ccenv.sh && eval \"$WV_UPDATE\"\n# --- injected by whalevet: ensure certs appear in CA bundles ---\nRUN . /etc/wv-ccenv.sh && __wv_append") {
		t.Errorf("bundle append should follow the store update:\n%s", out)
	}
	if !strings.Contains(out, "'/etc/ssl/certs/ca-certificates.crt'") {
		t.Errorf("canonical BundlePath missing from append targets:\n%s", out)
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
	}), "\n")

	for i, line := range strings.Split(out, "\n") {
		if len(line) > 65535 {
			t.Fatalf("line %d is %d bytes, exceeding BuildKit's 65535 cap", i, len(line))
		}
	}

	// Every `printf '%s' '<chunk>'` write must be base64: collecting all chunk
	// payloads per target file and decoding them must reproduce the original
	// certificate.
	chunkPat := regexp.MustCompile(`RUN (?:mkdir -p [^ ]+ && )?printf '%s' '([^']*)' (?:>|>>) ([^ ]+\.b64)`)
	chunksByFile := map[string]string{}
	for _, m := range chunkPat.FindAllStringSubmatch(out, -1) {
		chunksByFile[m[2]] += m[1]
	}
	if len(chunksByFile) < 2 {
		t.Fatalf("expected the payload to be chunked, got %d file(s) with chunks", len(chunksByFile))
	}
	decoded, err := base64.StdEncoding.DecodeString(chunksByFile["/etc/whalevet-cacert/big.pem.b64"])
	if err != nil {
		t.Fatalf("chunk payload is not valid base64: %v", err)
	}
	if string(decoded) != large {
		t.Fatalf("decoded payload differs from original: got %d bytes, want %d", len(decoded), len(large))
	}

	// Multi-cert bundles must be split into one file per certificate, fed
	// through awk, and the append step must sweep the cert dir with a glob
	// (never a literal per-file list, which would exceed the line cap).
	if !strings.Contains(out, "awk -v D=\"$WV_CERTDIR\"") {
		t.Fatalf("missing per-cert awk split for multi-cert bundle:\n%s", out)
	}
	if !strings.Contains(out, "for __f in $WV_CERTDIR/*.crt") {
		t.Fatalf("append step must use a glob over the cert dir:\n%s", out)
	}
	if strings.Contains(out, "base64 -d /usr/local/share/ca-certificates/big.crt.b64 >") {
		t.Fatalf("multi-cert bundle must not be written as a single .crt file:\n%s", out)
	}
}

func TestGenerateCACertInlineLinesSingleCertDecodesIntoDetectedDir(t *testing.T) {
	single := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
	out := strings.Join(GenerateCACertInlineLines(map[string][]byte{
		"root.pem": []byte(single),
	}), "\n")

	// Single-cert content keeps the whole-file path: direct base64 -d to the
	// runtime-detected "$WV_CERTDIR" target, no awk split.
	if !strings.Contains(out, "base64 -d /etc/whalevet-cacert/root.pem.b64 > \"$WV_CERTDIR/root.crt\"") {
		t.Fatalf("single-cert bundle should be decoded whole into $WV_CERTDIR:\n%s", out)
	}
	if strings.Contains(out, "awk -v D=") {
		t.Fatalf("single-cert bundle must not be awk-split:\n%s", out)
	}
	if !strings.Contains(out, "for __f in $WV_CERTDIR/*.crt") {
		t.Fatalf("append step must sweep the cert dir:\n%s", out)
	}
}

func TestGenerateCACertDockerfileLinesAppendsBundlePath(t *testing.T) {
	out := strings.Join(GenerateCACertDockerfileLines(map[string][]byte{
		"root.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	}), "\n")

	if !strings.Contains(out, "'/etc/ssl/certs/ca-certificates.crt'") {
		t.Errorf("canonical BundlePath missing from append targets:\n%s", out)
	}
	if !strings.Contains(out, "RUN . /etc/wv-ccenv.sh && eval \"$WV_UPDATE\"\n# --- injected by whalevet: ensure certs appear in CA bundles ---") {
		t.Errorf("append should follow the store update:\n%s", out)
	}
}

func TestGenerateCACertDockerfileLinesCopiesToStagingThenDetectedDir(t *testing.T) {
	bundle := "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	out := strings.Join(GenerateCACertDockerfileLines(map[string][]byte{
		"combined.pem": []byte(bundle),
	}), "\n")

	// Certificates are COPYed into the staging dir, then moved into the
	// runtime-detected "$WV_CERTDIR"; a multi-cert bundle must be COPYed per
	// certificate.
	for _, want := range []string{
		"COPY combined-0001.crt /etc/whalevet-cacert/combined-0001.crt",
		"COPY combined-0002.crt /etc/whalevet-cacert/combined-0002.crt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing per-cert copy %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "COPY combined.pem") {
		t.Errorf("multi-cert bundle must not be copied whole:\n%s", out)
	}
	if !strings.Contains(out, "mv \"$__f\" \"$WV_CERTDIR/\"") {
		t.Errorf("staging certs must be moved into the detected cert dir:\n%s", out)
	}
	if !strings.Contains(out, "for __f in $WV_CERTDIR/*.crt") {
		t.Errorf("append must use a glob over the cert dir:\n%s", out)
	}
}

func TestExpandCertFilesForContext(t *testing.T) {
	single := "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n"
	multi := "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

	got := ExpandCertFilesForContext(map[string][]byte{
		"single.pem": []byte(single),
		"multi.pem":  []byte(multi),
	})

	if got["single.pem"] == nil {
		t.Errorf("single-cert file must keep its basename:\n%#v", got)
	}
	if string(got["multi-0001.crt"]) != string([]byte("-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n")) {
		t.Errorf("multi-0001.crt should hold the first certificate:\n%#v", got)
	}
	if string(got["multi-0002.crt"]) != string([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")) {
		t.Errorf("multi-0002.crt should hold the second certificate:\n%#v", got)
	}
	if got["multi.pem"] != nil {
		t.Errorf("multi-cert bundle must be replaced by its split entries:\n%#v", got)
	}
}

func TestAppendExtraBundlesCmdUsesBodyMarker(t *testing.T) {
	cmd := AppendExtraBundlesCmd([]string{"$WV_CERTDIR/*.crt"}, "/etc/ssl/certs/ca-certificates.crt")

	if strings.Contains(cmd, "head -c") {
		t.Errorf("dedupe must not rely on the shared PEM header:\n%s", cmd)
	}
	for _, want := range []string{"'/cacert.pem'", "'/etc/ssl/cert.pem'", "'/etc/ssl/certs/ca-certificates.crt'", "sed -n '2p'", "cut -c1-40"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("append snippet missing %q:\n%s", want, cmd)
		}
	}
	// Globs stay unquoted so they expand at shell runtime, and unmatched
	// globs are guarded by the -f check.
	if !strings.Contains(cmd, "$WV_CERTDIR/*.crt") {
		t.Errorf("cert glob should be emitted unquoted:\n%s", cmd)
	}
	if !strings.Contains(cmd, "[ -f \"$__f\" ] || continue") {
		t.Errorf("unmatched globs must be guarded:\n%s", cmd)
	}
}
