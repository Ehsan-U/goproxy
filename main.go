package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/elazarl/goproxy"
)

var version = "dev"

const pidFile = "/tmp/goproxy.pid"
const maxLogSize = 50 * 1024 * 1024 // 50MB

type rotatingWriter struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

func newRotatingWriter(path string) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	return &rotatingWriter{path: path, file: f, size: info.Size()}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > maxLogSize {
		w.file.Close()
		os.Rename(w.path, w.path+".1")
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return 0, err
		}
		w.file = f
		w.size = 0
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}
type contextKey string
const sessionKey contextKey = "session"
type sessionEntry struct {
	ip       net.IP
	lastUsed time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
	ipNet    *net.IPNet
	ttl      time.Duration
}

func NewSessionStore(cidr string, ttl time.Duration) (*SessionStore, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	s := &SessionStore{
		sessions: make(map[string]*sessionEntry),
		ipNet:    ipNet,
		ttl:      ttl,
	}
	go s.cleanup()
	return s, nil
}

func (s *SessionStore) cleanup() {
	for {
		time.Sleep(60 * time.Second)
		s.mu.Lock()
		now := time.Now()
		for id, entry := range s.sessions {
			if now.Sub(entry.lastUsed) > s.ttl {
				log.Println("[SESSION] expired:", id)
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *SessionStore) IPFor(session string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.sessions[session]; ok {
		entry.lastUsed = time.Now()
		log.Println("[IP Session]", session, "->", entry.ip, "(cached)")
		return entry.ip
	}
	ip := s.randomIP()
	s.sessions[session] = &sessionEntry{ip: ip, lastUsed: time.Now()}
	log.Println("[IP Session]", session, "->", ip, "(new)")
	return ip
}

func (s *SessionStore) RandomIP() net.IP {
	ip := s.randomIP()
	log.Println("[IP Random]", ip)
	return ip
}

func (s *SessionStore) randomIP() net.IP {
	randBytes := make([]byte, len(s.ipNet.IP))
	rand.Read(randBytes)
	ip := make(net.IP, len(s.ipNet.IP))
	for i := range ip {
		ip[i] = (s.ipNet.IP[i] & s.ipNet.Mask[i]) | (randBytes[i] &^ s.ipNet.Mask[i])
	}
	return ip
}

func (s *SessionStore) HostCount() uint64 {
	ones, bits := s.ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return 0
	}
	if hostBits >= 64 {
		return ^uint64(0)
	}
	return 1 << uint(hostBits)
}

// parseAuth decodes Proxy-Authorization and returns (session, ok).
func parseAuth(header, proxyUser, proxyPass string) (string, bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[6:])
	if err != nil {
		return "", false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok || pass != proxyPass {
		return "", false
	}
	// exact match
	if user == proxyUser {
		return "", true
	}
	// user-session-{value}
	prefix := proxyUser + "-session-"
	if strings.HasPrefix(user, prefix) {
		session := strings.TrimPrefix(user, prefix)
		if session != "" {
			return session, true
		}
	}
	return "", false
}

func readPID() (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func isRunning(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "goproxy", "env")
}

func loadConfig() {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	}
}

func promptAndSaveConfig() {
	rl, err := readline.New("")
	if err != nil {
		fmt.Println("failed to init readline:", err)
		os.Exit(1)
	}
	defer rl.Close()
	required := []string{"SUBNETS", "PROXY_USER", "PROXY_PASS"}
	prompted := false
	for _, key := range required {
		if os.Getenv(key) == "" {
			rl.SetPrompt(key + ": ")
			val, _ := rl.Readline()
			val = strings.TrimSpace(val)
			if val == "" {
				fmt.Printf("%s is required\n", key)
				os.Exit(1)
			}
			os.Setenv(key, val)
			prompted = true
		}
	}
	if prompted {
		path := configPath()
		os.MkdirAll(filepath.Dir(path), 0755)
		var lines []string
		for _, key := range []string{"SUBNETS", "PROXY_USER", "PROXY_PASS", "PROXY_PORT", "SESSION_TTL", "LOG_FILE"} {
			if v := os.Getenv(key); v != "" {
				lines = append(lines, key+"="+v)
			}
		}
		os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
		fmt.Printf("config saved to %s\n", path)
	}
}

func cmdStart() {
	if pid, err := readPID(); err == nil && isRunning(pid) {
		fmt.Printf("restarting (stopping pid %d)...\n", pid)
		syscall.Kill(pid, syscall.SIGTERM)
		os.Remove(pidFile)
		time.Sleep(500 * time.Millisecond)
	}

	loadConfig()
	promptAndSaveConfig()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "_DAEMON=1")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		fmt.Println("failed to start:", err)
		os.Exit(1)
	}

	logPath := os.Getenv("LOG_FILE")
	if logPath == "" {
		logPath = "goproxy.log"
	}
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	fmt.Printf("started (pid %d), logging to %s\n", cmd.Process.Pid, logPath)
}

func cmdStop() {
	pid, err := readPID()
	if err != nil || !isRunning(pid) {
		fmt.Println("not running")
		os.Remove(pidFile)
		return
	}
	syscall.Kill(pid, syscall.SIGTERM)
	os.Remove(pidFile)
	fmt.Printf("stopped (pid %d)\n", pid)
}

func cmdStatus() {
	pid, err := readPID()
	if err != nil || !isRunning(pid) {
		fmt.Println("not running")
		return
	}
	fmt.Printf("running (pid %d)\n", pid)
}

func printUsage() {
	fmt.Print(`usage: goproxy <start|stop|status>

commands:
  start   start the proxy in the background
  stop    stop a running proxy
  status  check if the proxy is running

environment variables:
  SUBNETS      subnet CIDR for outbound IP binding (required)
  PROXY_USER   basic auth username (required)
  PROXY_PASS   basic auth password (required)
  PROXY_PORT   listening port (default: 8080)
  SESSION_TTL  sticky session duration in seconds (default: 600)
  LOG_FILE     log file path (default: goproxy.log)

authentication:
  user:pass              random IP each request
  user-sessionID:pass    sticky IP per session ID
`)
}

func main() {
	if os.Getenv("_DAEMON") != "1" {
		if len(os.Args) < 2 {
			printUsage()
			os.Exit(1)
		}
		switch os.Args[1] {
		case "start":
			cmdStart()
		case "stop":
			cmdStop()
		case "status":
			cmdStatus()
		default:
			printUsage()
			os.Exit(1)
		}
		return
	}

	// Daemon mode — set up log rotation
	logPath := os.Getenv("LOG_FILE")
	if logPath == "" {
		logPath = "goproxy.log"
	}
	logWriter, err := newRotatingWriter(logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to open log file:", err)
		os.Exit(1)
	}
	log.SetOutput(logWriter)

	log.Printf("[BOOT] Proxy %s starting...\n", version)

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.IdleConnTimeout = 5 * time.Second

	proxyUser := os.Getenv("PROXY_USER")
	proxyPass := os.Getenv("PROXY_PASS")
	subnet := os.Getenv("SUBNETS")
	if subnet == "" {
		log.Fatal("[FATAL] SUBNETS not set")
	}
	sessionTTL := 600 * time.Second
	if v := os.Getenv("SESSION_TTL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			sessionTTL = time.Duration(secs) * time.Second
		}
	}

	store, err := NewSessionStore(subnet, sessionTTL)
	if err != nil {
		log.Fatal("[FATAL] invalid SUBNETS:", err)
	}

	log.Printf("[BOOT] Subnet: %s (%d IPs), session TTL: %s\n", subnet, store.HostCount(), sessionTTL)

	// HTTP requests
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		auth := req.Header.Get("Proxy-Authorization")
		session, ok := parseAuth(auth, proxyUser, proxyPass)
		if !ok {
			log.Println("[DENIED]", host)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "407 Proxy Authentication Required")
		}
		ctx.UserData = session
		return req, nil
	})

	// CONNECT (HTTPS) requests
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		rHost, _, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
		auth := ctx.Req.Header.Get("Proxy-Authorization")
		session, ok := parseAuth(auth, proxyUser, proxyPass)
		if !ok {
			log.Println("[DENIED-CONNECT]", rHost)
			return &goproxy.ConnectAction{
				Action: goproxy.ConnectProxyAuthHijack,
				Hijack: func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
					client.Write([]byte("Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"))
					client.Close()
				},
			}, host
		}
		if session != "" {
			return goproxy.OkConnect, session + "|" + host
		}
		return goproxy.OkConnect, host
	}))

	// Dialer: pick IP based on session
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		parts := strings.SplitN(addr, "|", 2)
		var ip net.IP
		var hostPort string
		if len(parts) == 2 {
			session := parts[0]
			hostPort = parts[1]
			ip = store.IPFor(session)
		} else {
			hostPort = addr
			ip = store.RandomIP()
		}
		log.Println("[DIAL] binding:", ip, "->", hostPort)
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 30 * time.Second}
		return d.Dial(network, hostPort)
	}

	proxy.Tr.DialContext = dialer

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("[BOOT] Listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}
