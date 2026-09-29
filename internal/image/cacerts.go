package image

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// wvCACertScriptPath is where the in-container distro detection script is
// written. Every later injected RUN sources it to get WV_INSTALL / WV_UPDATE
// / WV_CERTDIR for whatever the base image actually is, so injection works
// even when the image name does not match a known distro (e.g. custom app
// images built FROM a varied base).
const wvCACertScriptPath = "/etc/wv-ccenv.sh"

// wvStagingDir is a fixed path for certificate payloads before the detected
// cert dir is known: COPY (legacy) targets it and base64 chunks (inline)
// land in it, then a later RUN moves/decodes them into "$WV_CERTDIR".
const wvStagingDir = "/etc/whalevet-cacert"

// canonicalBundlePath / canonicalTrustDir are the fixed ENV targets used by
// every generated ENV line. The append step guarantees this bundle exists in
// the finished image (creating it when the distro has no native one), so
// runtimes reading SSL_CERT_FILE / SSL_CERT_DIR always find a populated
// bundle regardless of the base image.
const (
	canonicalBundlePath = "/etc/ssl/certs/ca-certificates.crt"
	canonicalTrustDir   = "/etc/ssl/certs"
)

// caCertDetectScript is a POSIX-sh script that, when sourced, sets
// WV_INSTALL / WV_UPDATE / WV_CERTDIR from the package manager actually
// present in the build container. Distro is detected at build time instead of
// guessed from the FROM line, so a base image whose name differs from the
// well-known distro names still gets the correct package manager, cert dir
// and store updater.
const caCertDetectScript = `# WhaleVet CA-cert environment: detect distro at build time
if command -v apk >/dev/null 2>&1; then WV_PM=alpine
elif command -v apt-get >/dev/null 2>&1; then WV_PM=apt
elif command -v dnf >/dev/null 2>&1; then WV_PM=dnf
elif command -v yum >/dev/null 2>&1; then WV_PM=yum
elif command -v pacman >/dev/null 2>&1; then WV_PM=pacman
elif command -v zypper >/dev/null 2>&1; then WV_PM=zypper
else WV_PM=apt; fi
case $WV_PM in
alpine)
  WV_INSTALL='apk add --no-cache --no-check-certificate ca-certificates'
  WV_CERTDIR='/usr/local/share/ca-certificates'
  WV_UPDATE='update-ca-certificates';;
apt)
  WV_INSTALL='apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false update && apt-get install -y --allow-unauthenticated -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false ca-certificates'
  WV_CERTDIR='/usr/local/share/ca-certificates'
  WV_UPDATE='update-ca-certificates';;
dnf)
  WV_INSTALL='dnf install -y --nogpgcheck --setopt=sslverify=0 ca-certificates'
  WV_CERTDIR='/etc/pki/ca-trust/source/anchors'
  WV_UPDATE='update-ca-trust extract';;
yum)
  WV_INSTALL='yum install -y --nogpgcheck --setopt=sslverify=0 ca-certificates'
  WV_CERTDIR='/etc/pki/ca-trust/source/anchors'
  WV_UPDATE='update-ca-trust extract';;
pacman)
  WV_INSTALL='pacman -Sy --noconfirm ca-certificates'
  WV_CERTDIR='/etc/ca-certificates/trust-source/anchors'
  WV_UPDATE='trust extract-compat';;
zypper)
  WV_INSTALL='zypper --non-interactive install ca-certificates'
  WV_CERTDIR='/usr/share/pki/trust/anchors'
  WV_UPDATE='update-ca-certificates';;
esac
`

// caCertEnvVars sets environment variables that make language runtimes trust
// the OS CA bundle regenerated with the injected certificates:
//   - SSL_CERT_FILE / SSL_CERT_DIR: Python (ssl, urllib, requests), Go,
//     Rust (native-tls / rustls-native-certs), curl, git
//   - CURL_CA_BUNDLE: curl's alternative override
//   - REQUESTS_CA_BUNDLE: Python requests (certifi replacement)
//   - PIP_CERT: pip
//   - NODE_EXTRA_CA_CERTS: Node.js (additive to its bundled roots)
func caCertEnvVars(bundlePath, trustDir string) []string {
	return []string{
		"SSL_CERT_FILE=" + bundlePath,
		"SSL_CERT_DIR=" + trustDir,
		"CURL_CA_BUNDLE=" + bundlePath,
		"REQUESTS_CA_BUNDLE=" + bundlePath,
		"PIP_CERT=" + bundlePath,
		"NODE_EXTRA_CA_CERTS=" + bundlePath,
	}
}

func caCertEnvLines(bundlePath, trustDir string) []string {
	// All trust variables fold into a single ENV instruction (one layer
	// instead of six). Values are fixed store paths without whitespace, so
	// Dockerfile's space-separated ENV pairs need no quoting.
	return []string{"ENV " + strings.Join(caCertEnvVars(bundlePath, trustDir), " ")}
}

// detectScriptLines emits the RUN steps that install caCertDetectScript into
// the image at wvCACertScriptPath. The payload is base64-chunked exactly
// like certificate payloads, so the generated lines stay under BuildKit's
// per-line and per-argument caps.
func detectScriptLines() []string {
	return inlineWritePayloadLines(wvCACertScriptPath, []byte(caCertDetectScript))
}

// inlineWritePayloadLines writes content as base64 chunks into wvStagingDir
// and decodes it to target in a final step, mirroring the certificate write
// path.
func inlineWritePayloadLines(target string, content []byte) []string {
	var lines []string
	tmp := wvStagingDir + "/" + filepath.Base(target) + ".b64"
	b64 := base64.StdEncoding.EncodeToString(content)
	for j := 0; j < len(b64); j += inlineChunkSize {
		chunk := b64[j:min(j+inlineChunkSize, len(b64))]
		if j == 0 {
			lines = append(lines, fmt.Sprintf("RUN mkdir -p %s && printf '%%s' '%s' > %s", wvStagingDir, chunk, tmp))
		} else {
			lines = append(lines, fmt.Sprintf("RUN printf '%%s' '%s' >> %s", chunk, tmp))
		}
	}
	lines = append(lines, fmt.Sprintf("RUN base64 -d %s > %s && rm %s && chmod 644 %s", tmp, target, tmp, target))
	return lines
}

// awkSplitProg splits PEM input into one file per certificate under the -v D
// directory, named <P>-NNNN.crt. Store updaters reject any .crt holding more
// than one certificate ("does not contain exactly one certificate or CRL:
// skipping"), so multi-cert bundles must go through this split, on both the
// inline and the legacy COPY paths.
const awkSplitProg = `/-----BEGIN CERTIFICATE-----/{n++;on=1;f=sprintf("%s/%s-%04d.crt",D,P,n)} on{print > f} /-----END CERTIFICATE-----/{on=0}`

// inlineCertWriteLines emits the RUN steps that base64-chunk content into
// wvStagingDir, then decode it into the runtime-detected "$WV_CERTDIR" as one
// .crt per certificate (or the whole file for single-cert / non-cert content).
func inlineCertWriteLines(name string, content []byte) []string {
	var lines []string
	tmp := wvStagingDir + "/" + name + ".b64"
	b64 := base64.StdEncoding.EncodeToString(content)
	for j := 0; j < len(b64); j += inlineChunkSize {
		chunk := b64[j:min(j+inlineChunkSize, len(b64))]
		if j == 0 {
			lines = append(lines, fmt.Sprintf("RUN mkdir -p %s && printf '%%s' '%s' > %s", wvStagingDir, chunk, tmp))
		} else {
			lines = append(lines, fmt.Sprintf("RUN printf '%%s' '%s' >> %s", chunk, tmp))
		}
	}

	if certBlockCount(content) >= 2 {
		// Split the decoded stream into per-cert files; each gets a
		// deterministic <base>-NNNN.crt name in the cert dir. Store
		// updaters reject any .crt containing more than one certificate
		// ("does not contain exactly one certificate or CRL: skipping").
		prefix := strings.TrimSuffix(CertTargetName(name), ".crt")
		lines = append(lines, fmt.Sprintf(
			"RUN . %s && mkdir -p \"$WV_CERTDIR\" && base64 -d %s | awk -v D=\"$WV_CERTDIR\" -v P=%s '%s' && rm %s",
			wvCACertScriptPath, tmp, shQuote(prefix), awkSplitProg, tmp))
	} else {
		// Single block or non-cert content (e.g. a CRL): install the file
		// whole.
		lines = append(lines, fmt.Sprintf("RUN . %s && mkdir -p \"$WV_CERTDIR\" && base64 -d %s > \"$WV_CERTDIR/%s\" && rm %s && chmod 644 \"$WV_CERTDIR/%s\"",
			wvCACertScriptPath, tmp, CertTargetName(name), tmp, CertTargetName(name)))
	}
	return lines
}

// GenerateCACertInlineLines emits install + inline-write + update RUN lines.
// Cert content is embedded base64 (no COPY, no context files needed), for
// frontends that receive rules but cannot add files to the build context.
//
// The distro is detected inside the build container (see caCertDetectScript),
// not guessed from the image name, so injection works for any base image.
//
// Multi-cert bundles are split into one .crt file per certificate so store
// updaters (update-ca-certificates / update-ca-trust) process each block
// instead of skipping the whole file ("does not contain exactly one
// certificate or CRL: skipping").
//
// Each RUN line is kept far under both limits the daemon's BuildKit frontend
// enforces: per-line 65535 bytes, and per-command MAX_ARG_STRLEN (the exec
// of `/bin/sh -c <cmd>` fails with exit 255 when the command exceeds the
// kernel's single-argument cap, e.g. ~128KB). Large bundles are therefore
// written across several RUN steps appending bounded base64 chunks to the
// target file, each chunk small enough on its own.
func GenerateCACertInlineLines(certContents map[string][]byte) []string {
	if len(certContents) == 0 {
		return nil
	}
	names := make([]string, 0, len(certContents))
	for name := range certContents {
		names = append(names, name)
	}
	sort.Strings(names)

	var lines []string

	lines = append(lines, detectScriptLines()...)

	lines = append(lines, "# --- injected by whalevet: install ca-certificates package ---")
	lines = append(lines, "RUN . "+wvCACertScriptPath+" && eval \"$WV_INSTALL\"")

	lines = append(lines, "# --- injected by whalevet: install custom CA certificates (inline) ---")
	for _, name := range names {
		lines = append(lines, inlineCertWriteLines(name, certContents[name])...)
	}

	// Some store updaters (update-ca-trust on RHEL-family, trust extract on
	// Arch/OpenSUSE) only include certs with CA basicConstraints, so CA:FALSE
	// certs would silently vanish from the regenerated BundlePath. Append them
	// after the update so they always land in the bundles OpenSSL/curl read.
	// Every *.crt we dropped into $WV_CERTDIR is appended (glob-expanded at
	// shell runtime, so the Dockerfile line stays short for large bundles);
	// the canonical target bundle is created when missing.
	// Update and append share one RUN: both invalidate together on cert
	// change, and the append must follow the update in the same shell because
	// the updaters overwrite the bundle.
	lines = append(lines, "# --- injected by whalevet: update certificate store and CA bundles ---")
	lines = append(lines, "RUN . "+wvCACertScriptPath+" && eval \"$WV_UPDATE\" && "+AppendExtraBundlesCmd([]string{"$WV_CERTDIR/*.crt"}, canonicalBundlePath))

	lines = append(lines, "# --- injected by whalevet: set CA bundle env vars ---")
	lines = append(lines, caCertEnvLines(canonicalBundlePath, canonicalTrustDir)...)

	return lines
}

// inlineChunkSize bounds each generated RUN write. With ~500 bytes of shell
// wrapper and paths, a 56KB chunk keeps every emitted line below BuildKit's
// 65535-byte-per-line ceiling and the whole `/bin/sh -c` argument well under
// the kernel MAX_ARG_STRLEN (~128KB) that otherwise kills the exec with
// exit 255.
const inlineChunkSize = 56 << 10

// CertTargetName returns the filename under which a cert must be installed:
// basename with a .crt extension, since update-ca-certificates (and its
// counterparts) only pick up *.crt files.
func CertTargetName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base)) + ".crt"
}

// certBlockCount returns the number of `-----BEGIN CERTIFICATE-----` blocks
// in a PEM payload. Block detection mirrors what update-ca-certificates
// itself matches (a .crt file must contain exactly one of these to be
// processed).
func certBlockCount(content []byte) int {
	var n int
	body := string(content)
	for {
		i := strings.Index(body, "-----BEGIN CERTIFICATE-----")
		if i < 0 {
			return n
		}
		n++
		body = body[i+len("-----BEGIN CERTIFICATE-----"):]
	}
}

// legacyInstallRun returns the single RUN command that installs every staged
// certificate into the runtime-detected $WV_CERTDIR, refreshes the store and
// appends the certs to the well-known bundles. Multi-cert bundles are split
// into one <base>-NNNN.crt file per certificate inside the container (same
// naming as the inline awk path); single files are installed under their
// CertTargetName, since store updaters ignore non-.crt names. Update and
// append run in the same shell: all three steps invalidate together on cert
// change, and the append must follow the update because the updaters
// overwrite the bundle.
func legacyInstallRun(names []string, certFiles map[string][]byte) string {
	parts := []string{". " + wvCACertScriptPath, "mkdir -p \"$WV_CERTDIR\""}
	for _, name := range names {
		src := wvStagingDir + "/" + name
		if certBlockCount(certFiles[name]) >= 2 {
			prefix := strings.TrimSuffix(CertTargetName(name), ".crt")
			parts = append(parts, fmt.Sprintf("awk -v D=\"$WV_CERTDIR\" -v P=%s '%s' %s && rm %s",
				shQuote(prefix), awkSplitProg, shQuote(src), shQuote(src)))
		} else {
			parts = append(parts, fmt.Sprintf("mv %s \"$WV_CERTDIR\"/%s",
				shQuote(src), shQuote(CertTargetName(name))))
		}
	}
	parts = append(parts, "rm -rf "+wvStagingDir)
	parts = append(parts, "eval \"$WV_UPDATE\"")
	parts = append(parts, AppendExtraBundlesCmd([]string{"$WV_CERTDIR/*.crt"}, canonicalBundlePath))
	return "RUN " + strings.Join(parts, " && ")
}

// GenerateCACertDockerfileLines emits install + one COPY + one install RUN
// lines for the legacy build path. certFiles maps the build-context entry name
// (the COPY source, which the caller must place in the context tar) to its
// PEM content (nil content means name only and is treated as a single
// certificate).
//
// All files ride in a single COPY (COPY creates the staging dir, so no mkdir
// step is needed); multi-cert bundles are split inside the container, so the
// Dockerfile stays short no matter how many certificates a file holds.
//
// Certificates land in the runtime-detected "$WV_CERTDIR" (see
// caCertDetectScript), so the target dir does not need to be guessed from the
// image name.
func GenerateCACertDockerfileLines(certFiles map[string][]byte) []string {
	names := make([]string, 0, len(certFiles))
	for name := range certFiles {
		names = append(names, name)
	}
	sort.Strings(names)

	var lines []string

	lines = append(lines, detectScriptLines()...)

	lines = append(lines, "# --- injected by whalevet: install ca-certificates package ---")
	lines = append(lines, "RUN . "+wvCACertScriptPath+" && eval \"$WV_INSTALL\"")

	// Copy every certificate into the staging dir (sources are basenames,
	// which must exist in the build context root), then install them into
	// the detected dir, refresh the store and append to the CA bundles.
	lines = append(lines, "# --- injected by whalevet: copy custom CA certificates ---")
	lines = append(lines, "COPY "+strings.Join(names, " ")+" "+wvStagingDir+"/")
	lines = append(lines, "# --- injected by whalevet: install certificates, update store and CA bundles ---")
	lines = append(lines, legacyInstallRun(names, certFiles))

	lines = append(lines, "# --- injected by whalevet: set CA bundle env vars ---")
	lines = append(lines, caCertEnvLines(canonicalBundlePath, canonicalTrustDir)...)

	return lines
}

// ExtraBundlePaths are well-known CA bundle files outside the OS store
// (e.g. curlimages/curl pins curl to /cacert.pem via CURL_CA_BUNDLE).
// Custom certs are appended when the file exists and lacks them.
var ExtraBundlePaths = []string{"/cacert.pem", "/etc/ssl/cert.pem"}

// shQuote quotes a string for POSIX sh single-quoted use.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// AppendExtraBundlesCmd returns a shell snippet appending the given installed
// cert files (absolute paths, or sh globs expanding to them) to the well-known
// ExtraBundlePaths when present, and to bundlePath unconditionally (creating
// it when missing), so runtimes reading SSL_CERT_FILE always find a populated
// bundle even on distros without a native one. Idempotent: skips files whose
// base64 body already appears in the bundle.
//
// Paths are emitted unquoted so globs expand inside the shell rather than at
// Dockerfile parse time; the per-file [ -f ] guard skips unmatched globs.
// This keeps the generated RUN line short no matter how many files match (a
// literal enumeration would blow past BuildKit's 65535-byte line cap).
func AppendExtraBundlesCmd(installedPaths []string, bundlePath string) string {
	var sb strings.Builder
	sb.WriteString("__wv_append() { __b=\"$1\"; for __f in")
	for _, p := range installedPaths {
		sb.WriteString(" " + p)
	}
	// Marker: a 40-char slice of the first base64 body line. Short enough to
	// survive bundles that re-wrap PEM to 60-64 cols, unique enough to never
	// collide across different certs, and free of the "BEGIN CERTIFICATE"
	// header so grep cannot match other entries.
	sb.WriteString("; do [ -f \"$__f\" ] || continue; __h=$(sed -n '2p' \"$__f\" | cut -c1-40); if [ -n \"$__h\" ]; then grep -qF -- \"$__h\" \"$__b\" || cat \"$__f\" >> \"$__b\"; else cat \"$__f\" >> \"$__b\"; fi; done; }; ")
	sb.WriteString("for __b in")
	for _, b := range ExtraBundlePaths {
		sb.WriteString(" " + shQuote(b))
	}
	sb.WriteString("; do [ -f \"$__b\" ] || continue; __wv_append \"$__b\"; done; ")
	sb.WriteString("__cb=" + shQuote(bundlePath) + "; mkdir -p \"${__cb%/*}\" 2>/dev/null; if [ ! -f \"$__cb\" ]; then : > \"$__cb\"; fi; [ -f \"$__cb\" ] && __wv_append \"$__cb\"")
	return sb.String()
}
