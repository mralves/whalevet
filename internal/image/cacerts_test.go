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

	wantEnv := "ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" +
		" SSL_CERT_DIR=/etc/ssl/certs" +
		" CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt" +
		" REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt" +
		" PIP_CERT=/etc/ssl/certs/ca-certificates.crt" +
		" NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt"
	if !strings.Contains(got, wantEnv) {
		t.Errorf("missing folded trust ENV %q in output:\n%s", wantEnv, got)
	}
	// One ENV instruction, not six: fewer layers for the same environment.
	if n := strings.Count(got, "\nENV "); n != 1 {
		t.Errorf("expected exactly one folded ENV line, got %d:\n%s", n, got)
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
		"eval \"$WV_UPDATE\"",
		"ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/etc/ssl/certs",
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

	// The append must run after the store update in the same RUN, since
	// update commands overwrite the bundle.
	if !strings.Contains(out, "RUN . /etc/wv-ccenv.sh && eval \"$WV_UPDATE\" && __wv_append") {
		t.Errorf("bundle append should follow the store update in one RUN:\n%s", out)
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
	if !strings.Contains(out, "eval \"$WV_UPDATE\" && __wv_append") {
		t.Errorf("append should follow the store update in one RUN:\n%s", out)
	}
}

func TestGenerateCACertDockerfileLinesSingleCopyInContainerSplit(t *testing.T) {
	bundle := "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	single := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
	out := strings.Join(GenerateCACertDockerfileLines(map[string][]byte{
		"combined.pem": []byte(bundle),
		"single.pem":   []byte(single),
	}), "\n")

	// One COPY carries every file; splitting happens inside the container so
	// the Dockerfile stays short no matter how many certificates a file
	// holds. Sources are sorted for deterministic output.
	if !strings.Contains(out, "COPY combined.pem single.pem /etc/whalevet-cacert/") {
		t.Errorf("missing single sorted COPY:\n%s", out)
	}
	if strings.Contains(out, "COPY combined-0001.crt") {
		t.Errorf("must not emit per-certificate COPYs:\n%s", out)
	}
	// Multi-cert bundle: awk-split with the same <base>-NNNN naming as the
	// inline path, then drop the staged bundle.
	for _, want := range []string{
		`awk -v D="$WV_CERTDIR" -v P='combined'`,
		`sprintf("%s/%s-%04d.crt",D,P,n)`,
		`rm '/etc/whalevet-cacert/combined.pem'`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing in-container split %q:\n%s", want, out)
		}
	}
	// Single-cert file: installed under its .crt target name (store updaters
	// ignore non-.crt names).
	if !strings.Contains(out, `mv '/etc/whalevet-cacert/single.pem' "$WV_CERTDIR"/'single.crt'`) {
		t.Errorf("single-cert file must be installed as .crt:\n%s", out)
	}
	// Install, update and append share one RUN, in that order.
	updateIdx := strings.Index(out, `eval "$WV_UPDATE"`)
	appendIdx := strings.Index(out, "__wv_append")
	if updateIdx < 0 || appendIdx < 0 || updateIdx > appendIdx {
		t.Errorf("update must precede the bundle append:\n%s", out)
	}
	installRun := ""
	for line := range strings.Lines(out) {
		if strings.Contains(line, `eval "$WV_UPDATE"`) {
			installRun = line
		}
	}
	for _, want := range []string{`mkdir -p "$WV_CERTDIR"`, `rm -rf /etc/whalevet-cacert`} {
		if !strings.Contains(installRun, want) {
			t.Errorf("install RUN missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "for __f in $WV_CERTDIR/*.crt") {
		t.Errorf("append must use a glob over the cert dir:\n%s", out)
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
