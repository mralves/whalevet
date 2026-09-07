package main

import (
	"path/filepath"
	"testing"
)

func TestParseGlobalFlags(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/fake/xdg")
	defaultPath := filepath.Join("/fake/xdg", "whalevet", "config.toml")

	if got := defaultConfigPath(); got != defaultPath {
		t.Fatalf("defaultConfigPath() = %q, want %q", got, defaultPath)
	}

	cases := []struct {
		name     string
		args     []string
		wantPath string
		wantRest []string
		wantErr  bool
	}{
		{"no flags", []string{"serve"}, defaultPath, []string{"serve"}, false},
		{"--config before cmd", []string{"--config", "/x/y.toml", "serve"}, "/x/y.toml", []string{"serve"}, false},
		{"--config after cmd", []string{"serve", "--config", "/x/y.toml"}, "/x/y.toml", []string{"serve"}, false},
		{"--config= form", []string{"--config=/x/y.toml", "serve"}, "/x/y.toml", []string{"serve"}, false},
		{"missing value", []string{"--config"}, "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPath, gotRest, err := parseGlobalFlags(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != tc.wantPath {
				t.Fatalf("configPath = %q, want %q", gotPath, tc.wantPath)
			}
			if len(gotRest) != len(tc.wantRest) {
				t.Fatalf("rest = %v, want %v", gotRest, tc.wantRest)
			}
			for i := range gotRest {
				if gotRest[i] != tc.wantRest[i] {
					t.Fatalf("rest = %v, want %v", gotRest, tc.wantRest)
				}
			}
		})
	}
}
