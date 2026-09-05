package proxy

import (
	"bufio"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mralves/whalevet/internal/cache"
	"github.com/mralves/whalevet/internal/config"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern string
		ref     string
		want    bool
	}{
		{"docker.io/library/*", "docker.io/library/ubuntu", true},
		{"docker.io/library/*", "docker.io/library/ubuntu:20.04", true},
		{"docker.io/library/*", "docker.io/mine/ubuntu", false},
		{"ghcr.io/org/**", "ghcr.io/org/team/worker", true},
		{"ghcr.io/org/**", "ghcr.io/other/org/team/worker", false},
		{"**/untrusted/**", "docker.io/untrusted/app", true},
		{"**/untrusted/**", "docker.io/trusted/app", false},
		{"**", "anything/at/all", true},
		{"*", "no/slash", false},
		{"foo?bar", "fooxbar", true},
		{"foo?bar", "foo/bar", false},
		{"registry.internal/**", "registry.internal/svc/db", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.ref); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.ref, got, c.want)
		}
	}
}

func TestPolicyAllowed(t *testing.T) {
	cfg := &config.Config{
		Policy: config.PolicyConfig{
			Allow: []string{"docker.io/library/*", "ghcr.io/org/**"},
			Deny:  []string{"**/untrusted/**"},
		},
	}

	cases := []struct {
		ref  string
		want bool
	}{
		{"docker.io/library/ubuntu:20.04", true},
		{"ghcr.io/org/team/worker", true},
		{"docker.io/mine/custom", false},
		{"docker.io/untrusted/app", false},
		{cache.MakeProxyRef("docker.io/mine/custom"), true},
	}
	for _, c := range cases {
		if got, _ := policyAllowed(cfg, c.ref); got != c.want {
			t.Errorf("policyAllowed(%q) = %v, want %v", c.ref, got, c.want)
		}
	}
}

func TestPolicyAllowedEmptyAllowAllowsAll(t *testing.T) {
	cfg := &config.Config{}
	if ok, _ := policyAllowed(cfg, "any/image"); !ok {
		t.Fatal("empty policy should allow everything")
	}
	cfg = &config.Config{Policy: config.PolicyConfig{Deny: []string{"evil/**"}}}
	if ok, _ := policyAllowed(cfg, "evil/image"); ok {
		t.Fatal("deny should block even with empty allow list")
	}
	if ok, _ := policyAllowed(cfg, "fine/image"); !ok {
		t.Fatal("unmatched image with empty allow should pass")
	}
}

func serveConnRequest(t *testing.T, p *HTTPProxy, req string) string {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan string)
	go func() {
		p.ServeConn(server)
		server.Close()
		done <- ""
	}()
	client.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	client.Close()
	<-done
	body := new(strings.Builder)
	resp.Write(body) //nolint:errcheck
	return body.String()
}

func TestImageCreateDenied(t *testing.T) {
	cfg := &config.Config{
		Policy: config.PolicyConfig{Deny: []string{"evil/**"}},
	}
	proxy := NewHTTPProxy(cfg, nil, nil)
	out := serveConnRequest(t, proxy,
		"POST /images/create?fromImage=evil%2Fimage&tag=latest HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if !strings.Contains(out, "403") || !strings.Contains(out, "blocked by whalevet policy") {
		t.Fatalf("expected 403 denial, got:\n%s", out)
	}
}

func TestImageCreateAllowedHonorsConfig(t *testing.T) {
	daemonSock := filepath.Join(t.TempDir(), "daemon.sock")
	ln, err := net.Listen("unix", daemonSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		bufio.NewReader(conn).ReadString('\n')                                                  //nolint:errcheck
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	cfg := &config.Config{
		Proxy:  config.ProxyConfig{DockerSocket: daemonSock},
		Policy: config.PolicyConfig{Allow: []string{"mounted/**"}},
	}
	proxy := NewHTTPProxy(cfg, nil, nil)
	// Allowed ref must be forwarded to the daemon (200), a miss must be denied.
	out := serveConnRequest(t, proxy,
		"POST /images/create?fromImage=mounted%2Fapp&tag=latest HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if !strings.Contains(out, "200") {
		t.Fatalf("allowed image should be forwarded, got:\n%s", out)
	}
}

func TestContainerCreateDenied(t *testing.T) {
	cfg := &config.Config{
		Policy: config.PolicyConfig{Deny: []string{"**/untrusted/**"}},
	}
	proxy := NewHTTPProxy(cfg, nil, nil)
	body := `{"Image":"docker.io/untrusted/app"}`
	out := serveConnRequest(t, proxy,
		"POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	if !strings.Contains(out, "403") || !strings.Contains(out, "blocked by whalevet policy") {
		t.Fatalf("expected 403 denial, got:\n%s", out)
	}
}

func TestSetConfigReload(t *testing.T) {
	proxy := NewHTTPProxy(&config.Config{Path: "/a.toml"}, nil, nil)
	if got := proxy.Config().Path; got != "/a.toml" {
		t.Fatalf("initial config = %q", got)
	}
	proxy.SetConfig(&config.Config{Path: "/b.toml"})
	if got := proxy.Config().Path; got != "/b.toml" {
		t.Fatalf("reloaded config = %q, want /b.toml", got)
	}
}
