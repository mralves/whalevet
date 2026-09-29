package image

import "testing"

func TestRenderEnvValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		ctx   EnvContext
		want  string
	}{
		{
			name:  "no template",
			value: "http://proxy:8080",
			want:  "http://proxy:8080",
		},
		{
			name:  "bundle path",
			value: "{{.BundlePath}}",
			ctx:   EnvContext{BundlePath: "/etc/ssl/certs/ca-certificates.crt"},
			want:  "/etc/ssl/certs/ca-certificates.crt",
		},
		{
			name:  "mixed",
			value: "file={{.BundlePath}}",
			ctx:   EnvContext{BundlePath: "/etc/pki/tls/certs/ca-bundle.crt"},
			want:  "file=/etc/pki/tls/certs/ca-bundle.crt",
		},
		{
			name:  "unresolved field empty",
			value: "{{.CertDir}}/certs",
			ctx:   EnvContext{CertDir: "/etc/ca-certificates"},
			want:  "/etc/ca-certificates/certs",
		},
		{
			name:  "invalid template",
			value: "{{.Missing",
			want:  "{{.Missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderEnvValue(tt.value, tt.ctx)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnvBlockLines(t *testing.T) {
	// Foldable values share one ENV instruction (one layer).
	got := envBlockLines([]string{"B=2", "A=1"})
	want := []string{"# --- injected by whalevet ---", "ENV B=2 A=1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("folded block = %q, want %q", got, want)
	}

	// Values with whitespace keep one ENV per pair (Dockerfile splits ENV
	// pairs on unquoted whitespace).
	got = envBlockLines([]string{"OK=1", "SPACED=a b"})
	want = []string{
		"# --- injected by whalevet ---", "ENV OK=1",
		"# --- injected by whalevet ---", "ENV SPACED=a b",
	}
	if len(got) != len(want) {
		t.Fatalf("unfolded block = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}

	if got := envBlockLines(nil); got != nil {
		t.Errorf("empty block = %q, want nil", got)
	}
}

func TestMergeEnv(t *testing.T) {
	base := []string{"A=1", "B=2"}
	overrides := []string{"B=overridden", "C=3"}
	got := mergeEnv(base, overrides)
	want := []string{"A=1", "B=overridden", "C=3"}
	if len(got) != len(want) {
		t.Fatalf("len %d != %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: %q != %q", i, got[i], want[i])
		}
	}
}
