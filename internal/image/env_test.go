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
