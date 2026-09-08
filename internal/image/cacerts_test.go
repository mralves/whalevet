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
