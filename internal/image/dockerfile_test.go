package image

import (
	"strings"
	"testing"

	"github.com/mralves/whalevet/internal/config"
)

func TestModifyEnvAfterBase(t *testing.T) {
	in := "FROM golang:1.22\nRUN echo hi\n"
	want := `FROM golang:1.22
# --- injected by whalevet ---
ENV HTTP_PROXY=http://proxy.internal:8080
# --- injected by whalevet ---
ENV NO_PROXY=localhost,127.0.0.1
RUN echo hi
`
	got := Modify(in, []config.Injection{
		{Type: "env", Env: map[string]string{
			"NO_PROXY":   "localhost,127.0.0.1",
			"HTTP_PROXY": "http://proxy.internal:8080",
		}},
	})
	if got != want {
		t.Fatalf("unexpected output:\n%s\n--- want:\n%s", got, want)
	}
}

func TestModifyEnvBeforeEntrypoint(t *testing.T) {
	in := "FROM alpine:3.19\nENTRYPOINT [\"/app\"]\n"
	want := `FROM alpine:3.19
ENTRYPOINT ["/app"]
# --- injected by whalevet ---
ENV APP_ENV=prod
`
	got := Modify(in, []config.Injection{
		{Type: "env", Position: "before_entrypoint", Env: map[string]string{
			"APP_ENV": "prod",
		}},
	})
	if got != want {
		t.Fatalf("unexpected output:\n%s\n--- want:\n%s", got, want)
	}
}

func TestModifyEnvBeforeEntrypointNoEntry(t *testing.T) {
	in := "FROM alpine:3.19\n"
	want := `FROM alpine:3.19

# --- injected by whalevet ---
ENV X=1`
	got := Modify(in, []config.Injection{
		{Type: "env", Position: "before_entrypoint", Env: map[string]string{
			"X": "1",
		}},
	})
	if got != want {
		t.Fatalf("unexpected output:\n%q\n--- want:\n%q", got, want)
	}
}

func TestModifyCACertExtraEnv(t *testing.T) {
	in := "FROM debian:12\n"
	got := Modify(in, []config.Injection{
		{
			Type:         "ca_certificates",
			Certificates: []string{"root.pem"},
			Env: map[string]string{
				"GIT_SSL_NO_VERIFY": "false",
				"MY_APP_REGION":     "eu",
			},
		},
	})

	for _, w := range []string{
		"ENV GIT_SSL_NO_VERIFY=false",
		"ENV MY_APP_REGION=eu",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in output:\n%s", w, got)
		}
	}

	// Extra env must follow the trust env vars emitted with the cert block.
	if strings.Index(got, "ENV NODE_EXTRA_CA_CERTS") > strings.Index(got, "ENV MY_APP_REGION") {
		t.Errorf("extra env should come after the CA trust env block:\n%s", got)
	}
}

func TestModifyEnvAndRunOrdering(t *testing.T) {
	in := "FROM alpine:3.19\n"
	got := Modify(in, []config.Injection{
		{Type: "run", Command: "apk add curl"},
		{Type: "env", Env: map[string]string{
			"FOO": "bar",
		}},
	})
	runIdx := strings.Index(got, "RUN apk add curl")
	envIdx := strings.Index(got, "ENV FOO=bar")
	if runIdx < 0 || envIdx < 0 || runIdx > envIdx {
		t.Fatalf("expected RUN before ENV:\n%s", got)
	}
}

func TestModifyExtraCAEnvTemplates(t *testing.T) {
	in := "FROM debian:12\n"
	got := Modify(in, []config.Injection{
		{
			Type:         "ca_certificates",
			Certificates: []string{"/tmp/test.pem"},
			Env: map[string]string{
				"REQUEST_CA":  "/etc/ssl/certs/ca-certificates.crt",
				"REQUEST_CA2": "/etc/ssl/certs/ca-certificates.crt",
			},
		},
	})

	want := "ENV REQUEST_CA=/etc/ssl/certs/ca-certificates.crt"
	if !strings.Contains(got, want) {
		t.Fatalf("expected rendered env in output:\n%s\nmissing %q", got, want)
	}
	// Template resolution check: value without {{}} is passed through unchanged
	want2 := "ENV REQUEST_CA2=/etc/ssl/certs/ca-certificates.crt"
	if !strings.Contains(got, want2) {
		t.Fatalf("expected second rendered env:\n%s\nmissing %q", got, want2)
	}
}
