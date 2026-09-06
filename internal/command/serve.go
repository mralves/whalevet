package command

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/mralves/whalevet/internal/cache"
	"github.com/mralves/whalevet/internal/config"
	"github.com/mralves/whalevet/internal/image"
	"github.com/mralves/whalevet/internal/proxy"
)

func RunServe(configPath string, args []string) {
	socket, err := serveSocketArg(args)
	if err != nil {
		log.Fatalf("%v", err)
	}

	cfg, resolved, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if socket != "" {
		cfg.Proxy.Listen = socket
	}

	runProxyServer(cfg, resolved, socket)
}

func loadConfig(configPath string) (*config.Config, string, error) {
	resolved, err := config.ResolvePath(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("config file %q: %w", configPath, err)
	}
	cfg, err := config.Load(resolved)
	if err != nil {
		return nil, resolved, fmt.Errorf("load config %q: %w", resolved, err)
	}
	return cfg, resolved, nil
}

func serveSocketArg(args []string) (string, error) {
	if len(args) > 1 {
		return "", errors.New("usage: whalevet [--config PATH] serve [socket]")
	}
	if len(args) == 1 {
		return args[0], nil
	}
	return "", nil
}

// logInjections summarizes the active injection rules, at startup and after
// each SIGHUP reload.
func logInjections(cfg *config.Config) {
	for i, inj := range cfg.Injections {
		switch inj.Type {
		case "ca_certificates":
			log.Printf("Injection[%d]: ca_certificates certs=%v env=%v", i, inj.Certificates, inj.Env)
		case "run":
			log.Printf("Injection[%d]: run position=%s command=%q", i, inj.Position, inj.Command)
		case "from":
			log.Printf("Injection[%d]: from pattern=%q replacement=%q", i, inj.Pattern, inj.Replacement)
		case "env":
			log.Printf("Injection[%d]: env position=%s vars=%v file=%q", i, inj.Position, inj.Env, inj.EnvFile)
		default:
			log.Printf("Injection[%d]: unknown type %q (ignored)", i, inj.Type)
		}
	}
	log.Printf("Injections: %d rules", len(cfg.Injections))
}

// reloadProxyConfig re-reads the config file, re-applies it to the proxy, and
// rebuilds the frontend image when the config is newer than the image (so rule
// and cert changes baked into the wrapper take effect). On error the running
// proxy keeps its current config and no rebuild is attempted.
func reloadProxyConfig(httpProxy *proxy.HTTPProxy, resolved string) {
	cfg, err := config.Load(resolved)
	if err != nil {
		log.Printf("%s", color.RedString("Config reload failed (keeping current config): %v", err))
		return
	}
	if _, err := rebuildFrontend(resolved, ""); err != nil {
		log.Printf("%s", color.RedString("Frontend rebuild after config reload failed (keeping current config): %v", err))
		return
	}
	httpProxy.SetConfig(cfg)
	log.Printf("%s", color.GreenString("Reloaded config from %s", resolved))
	logInjections(cfg)
}

func runProxyServer(cfg *config.Config, resolved, overrideListen string) {
	log.Printf("Starting whalevet (legacy builder: DOCKER_BUILDKIT=0; BuildKit: use syntax directive)")
	log.Printf("Config file: %s", resolved)
	log.Printf("Listen: %s", cfg.Proxy.Listen)
	log.Printf("Docker socket: %s", cfg.Proxy.DockerSocket)
	logInjections(cfg)

	s, err := newServerState(cfg, resolved, overrideListen)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("%s", color.GreenString("Proxy listening on %s", s.currentListener().Addr()))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go s.acceptLoop()
	go watchConfig(resolved, s)

	for {
		sig := <-sigChan
		if sig != syscall.SIGHUP {
			log.Printf("%s", color.YellowString("Received %s, shutting down gracefully...", sig))
			break
		}
		s.reload()
	}

	close(s.shutdown)
	if l := s.currentListener(); l != nil {
		l.Close()
	}

	s.wgMu.Lock()
	s.closed = true
	s.wgMu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	<-done

	if p := s.currentSockPath(); p != "" {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to remove %s: %v", p, err)
		} else {
			log.Printf("Removed %s", p)
		}
	}

	log.Printf("%s", color.GreenString("Shutdown complete"))
}

// serverState owns the proxy and its live listener so a reload can swap the
// config, the frontend image and the listen address atomically.
type serverState struct {
	httpProxy      *proxy.HTTPProxy
	resolved       string
	overrideListen string

	mu         sync.RWMutex
	listener   net.Listener
	listenAddr string
	sockPath   string

	reloadMu sync.Mutex
	shutdown chan struct{}

	wgMu   sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newServerState(cfg *config.Config, resolved, overrideListen string) (*serverState, error) {
	s := &serverState{
		httpProxy:      proxy.NewHTTPProxy(cfg, image.NewDockerClient(cfg.Proxy.DockerSocket), cache.New()),
		resolved:       resolved,
		overrideListen: overrideListen,
		shutdown:       make(chan struct{}),
	}
	l, sock, err := openListener(cfg.Proxy.Listen)
	if err != nil {
		return nil, err
	}
	s.setListener(l, cfg.Proxy.Listen, sock)
	return s, nil
}

func (s *serverState) setListener(l net.Listener, addr, sock string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listener, s.listenAddr, s.sockPath = l, addr, sock
}

func (s *serverState) currentListener() net.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listener
}

func (s *serverState) currentSockPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sockPath
}

// openListener binds the proxy socket for addr, creating the parent directory
// for unix sockets. It returns the listener and, for unix sockets, the socket
// path.
func openListener(addr string) (net.Listener, string, error) {
	if rest, ok := strings.CutPrefix(addr, "unix:"); ok {
		sockPath := "/" + strings.TrimLeft(rest, "/")
		if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
			return nil, "", fmt.Errorf("create socket directory for %s: %w", sockPath, err)
		}
		os.Remove(sockPath)
		l, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, "", fmt.Errorf("listen on %s: %w", sockPath, err)
		}
		return l, sockPath, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", addr, err)
	}
	return l, "", nil
}

// reload re-reads the config file, rebuilds the frontend image when the config
// is newer than the image, swaps the proxy to the new config and reopens the
// proxy socket when the listen address changed. On any error the running proxy
// keeps its current config, listener and image.
func (s *serverState) reload() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	cfg, err := config.Load(s.resolved)
	if err != nil {
		log.Printf("%s", color.RedString("Config reload failed (keeping current config): %v", err))
		return
	}
	if _, err := rebuildFrontend(s.resolved, ""); err != nil {
		log.Printf("%s", color.RedString("Frontend rebuild after config reload failed (keeping current config): %v", err))
		return
	}

	effListen := cfg.Proxy.Listen
	if s.overrideListen != "" {
		effListen = s.overrideListen
	}
	s.mu.RLock()
	addrChanged := effListen != s.listenAddr
	s.mu.RUnlock()
	if addrChanged {
		l, sock, err := openListener(effListen)
		if err != nil {
			log.Printf("%s", color.RedString("Failed to open new listener %s (keeping current config): %v", effListen, err))
			return
		}
		old := s.currentListener()
		s.setListener(l, effListen, sock)
		old.Close()
		log.Printf("%s", color.GreenString("Proxy now listening on %s", l.Addr()))
	}

	s.httpProxy.SetConfig(cfg)
	log.Printf("%s", color.GreenString("Reloaded config from %s", s.resolved))
	logInjections(cfg)
}

// acceptLoop serves connections on the current listener, transparently
// switching to a new one after a reload swapped it.
func (s *serverState) acceptLoop() {
	for {
		select {
		case <-s.shutdown:
			return
		default:
		}
		l := s.currentListener()
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
			}
			if l != s.currentListener() {
				continue // listener was swapped during a reload
			}
			log.Printf("Accept error: %v", err)
			time.Sleep(20 * time.Millisecond)
			continue
		}
		s.wgMu.Lock()
		if s.closed {
			s.wgMu.Unlock()
			conn.Close()
			continue
		}
		s.wg.Add(1)
		s.wgMu.Unlock()
		go func(c net.Conn) {
			defer s.wg.Done()
			s.httpProxy.ServeConn(c)
		}(conn)
	}
}

// watchConfig watches the config file via fsnotify and triggers a reload as
// soon as it changes, so live edits take effect without a SIGHUP. The parent
// directory is watched (not the file itself) so editors that save atomically
// via rename are still caught; bursts of events per save collapse to one real
// rebuild because needsRebuild is mtime-guarded.
func watchConfig(resolved string, s *serverState) {
	target, err := filepath.Abs(resolved)
	if err != nil {
		log.Printf("%s", color.YellowString("Config watcher disabled: %v", err))
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("%s", color.YellowString("Config watcher disabled: %v", err))
		return
	}
	defer func() {
		_ = watcher.Close()
	}()

	if err := watcher.Add(filepath.Dir(target)); err != nil {
		log.Printf("%s", color.YellowString("Config watcher disabled: %v", err))
		return
	}
	log.Printf("Watching %s for changes", target)

	for {
		select {
		case <-s.shutdown:
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error (file watch continues): %v", err)
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Name != target {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				log.Printf("Config file changed (%s), reloading", event.Op)
				s.reload()
			}
		}
	}
}
