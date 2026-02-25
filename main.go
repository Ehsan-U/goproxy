package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"sync/atomic"
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
var ErrNoHealthySubnet = errors.New("no healthy subnets available")

type Subnet struct {
	cidr    string
	ipNet   *net.IPNet
	healthy atomic.Bool
}

func (s *Subnet) RandomIP() net.IP {
	randBytes := make([]byte, len(s.ipNet.IP))
	rand.Read(randBytes)
	ip := make(net.IP, len(s.ipNet.IP))
	for i := range ip {
		ip[i] = (s.ipNet.IP[i] & s.ipNet.Mask[i]) | (randBytes[i] &^ s.ipNet.Mask[i])
	}
	return ip
}

func (s *Subnet) HostCount() uint64 {
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

type SubnetPool struct {
	subnets []*Subnet
	rrIndex atomic.Uint64
}

func NewSubnetPool(cidrs []string) (*SubnetPool, error) {
	if len(cidrs) == 0 {
		return nil, errors.New("no subnets provided")
	}
	p := &SubnetPool{}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		s := &Subnet{cidr: cidr, ipNet: ipNet}
		s.healthy.Store(true)
		p.subnets = append(p.subnets, s)
	}
	return p, nil
}

func (p *SubnetPool) NextHealthy() (*Subnet, error) {
	n := uint64(len(p.subnets))
	for i := uint64(0); i < n; i++ {
		idx := p.rrIndex.Add(1) % n
		if p.subnets[idx].healthy.Load() {
			return p.subnets[idx], nil
		}
	}
	return nil, ErrNoHealthySubnet
}

func (p *SubnetPool) HealthyCount() int {
	count := 0
	for _, s := range p.subnets {
		if s.healthy.Load() {
			count++
		}
	}
	return count
}

func (p *SubnetPool) StartHealthChecks(checkURL string, onUnhealthy func(*Subnet)) {
	for _, s := range p.subnets {
		go p.healthLoop(s, checkURL, onUnhealthy)
	}
}

func (p *SubnetPool) healthLoop(s *Subnet, checkURL string, onUnhealthy func(*Subnet)) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		healthy := p.checkSubnet(s, checkURL)
		wasHealthy := s.healthy.Load()
		s.healthy.Store(healthy)
		if wasHealthy && !healthy {
			log.Printf("[HEALTH] subnet %s marked UNHEALTHY", s.cidr)
			if onUnhealthy != nil {
				onUnhealthy(s)
			}
		} else if !wasHealthy && healthy {
			log.Printf("[HEALTH] subnet %s recovered, marked HEALTHY", s.cidr)
		}
		if healthy {
			sendHeartbeat("goproxy:" + s.cidr)
		}
	}
}

const monitorSocket = "/tmp/itxpmonitor.sock"

func sendHeartbeat(app string) {
	conn, err := net.DialTimeout("unix", monitorSocket, 2*time.Second)
	if err != nil {
		log.Printf("[HEARTBEAT] failed to connect to monitor socket: %v", err)
		return
	}
	defer conn.Close()
	msg, _ := json.Marshal(map[string]string{"type": "heartbeat", "app": app})
	msg = append(msg, '\n')
	if _, err := conn.Write(msg); err != nil {
		log.Printf("[HEARTBEAT] failed to send for %s: %v", app, err)
	}
}

func (p *SubnetPool) checkSubnet(s *Subnet, checkURL string) bool {
	ip := s.RandomIP()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: ip},
				Timeout:   10 * time.Second,
			}).DialContext,
		},
	}
	resp, err := client.Get(checkURL)
	if err != nil {
		log.Printf("[HEALTH] subnet %s check failed: %v", s.cidr, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		page := string(body[:n])
		if isCloudflareHardBlock(page) {
			log.Printf("[HEALTH] subnet %s got 403 (hard blocked)", s.cidr)
			return false
		}
		log.Printf("[HEALTH] subnet %s got 403 (challenge, not hard block)", s.cidr)
		return true
	}
	return true
}

func isCloudflareHardBlock(body string) bool {
	lower := strings.ToLower(body)
	hardBlockSignals := []string{
		"error code: 1005",
		"error code: 1006",
		"error code: 1007",
		"error code: 1008",
		"error code: 1009",
		"error code: 1010",
		"error code: 1012",
		"access denied",
		"sorry, you have been blocked",
		"your ip address is blocked",
	}
	for _, signal := range hardBlockSignals {
		if strings.Contains(lower, signal) {
			return true
		}
	}
	return false
}

type sessionEntry struct {
	ip       net.IP
	lastUsed time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
	pool     *SubnetPool
	ttl      time.Duration
}

func NewSessionStore(cidrs []string, ttl time.Duration, checkURL string) (*SessionStore, error) {
	pool, err := NewSubnetPool(cidrs)
	if err != nil {
		return nil, err
	}
	s := &SessionStore{
		sessions: make(map[string]*sessionEntry),
		pool:     pool,
		ttl:      ttl,
	}
	go s.cleanup()
	pool.StartHealthChecks(checkURL, s.evictSubnet)
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

func (s *SessionStore) evictSubnet(sub *Subnet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, entry := range s.sessions {
		if sub.ipNet.Contains(entry.ip) {
			delete(s.sessions, id)
			count++
		}
	}
	log.Printf("[EVICT] removed %d sessions from subnet %s", count, sub.cidr)
}

func (s *SessionStore) IPFor(session string) (net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.sessions[session]; ok {
		entry.lastUsed = time.Now()
		log.Println("[IP Session]", session, "->", entry.ip, "(cached)")
		return entry.ip, nil
	}
	subnet, err := s.pool.NextHealthy()
	if err != nil {
		return nil, err
	}
	ip := subnet.RandomIP()
	s.sessions[session] = &sessionEntry{ip: ip, lastUsed: time.Now()}
	log.Printf("[IP Session] %s -> %s (new, subnet %s)", session, ip, subnet.cidr)
	return ip, nil
}

func (s *SessionStore) RandomIP() (net.IP, error) {
	subnet, err := s.pool.NextHealthy()
	if err != nil {
		return nil, err
	}
	ip := subnet.RandomIP()
	log.Printf("[IP Random] %s (subnet %s)", ip, subnet.cidr)
	return ip, nil
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

func listSubnets() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var subnets []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			cidr := addr.String()
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if ip.To4() != nil || ones == bits || !ip.IsGlobalUnicast() {
				continue
			}
			subnets = append(subnets, ipNet.String())
		}
	}
	return subnets
}

func promptAndSaveConfig() {
	rl, err := readline.New("")
	if err != nil {
		fmt.Println("failed to init readline:", err)
		os.Exit(1)
	}
	defer rl.Close()
	prompted := false

	// Special handling for SUBNETS: show available subnets to pick from
	if os.Getenv("SUBNETS") == "" {
		subnets := listSubnets()
		if len(subnets) > 0 {
			fmt.Println("available subnets:")
			for i, s := range subnets {
				fmt.Printf("  %d) %s\n", i+1, s)
			}
			rl.SetPrompt("select subnets (comma-separated numbers or CIDRs): ")
			val, _ := rl.Readline()
			val = strings.TrimSpace(val)
			var selected []string
			for _, token := range strings.Split(val, ",") {
				token = strings.TrimSpace(token)
				if token == "" {
					continue
				}
				if num, err := strconv.Atoi(token); err == nil && num >= 1 && num <= len(subnets) {
					selected = append(selected, subnets[num-1])
				} else {
					selected = append(selected, token)
				}
			}
			if len(selected) == 0 {
				fmt.Println("SUBNETS is required")
				os.Exit(1)
			}
			os.Setenv("SUBNETS", strings.Join(selected, ","))
			prompted = true
		} else {
			rl.SetPrompt("SUBNETS (comma-separated CIDRs): ")
			val, _ := rl.Readline()
			val = strings.TrimSpace(val)
			if val == "" {
				fmt.Println("SUBNETS is required")
				os.Exit(1)
			}
			os.Setenv("SUBNETS", val)
			prompted = true
		}
	}

	for _, key := range []string{"PROXY_USER", "PROXY_PASS"} {
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
		for _, key := range []string{"SUBNETS", "PROXY_USER", "PROXY_PASS", "PROXY_PORT", "SESSION_TTL", "LOG_FILE", "HEALTH_CHECK_URL"} {
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
  SUBNETS           comma-separated subnet CIDRs for outbound IPs (required)
  HEALTH_CHECK_URL  URL for subnet health checks (default: http://1.1.1.1)
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
	subnetStr := os.Getenv("SUBNETS")
	if subnetStr == "" {
		log.Fatal("[FATAL] SUBNETS not set")
	}
	var cidrs []string
	for _, c := range strings.Split(subnetStr, ",") {
		if c = strings.TrimSpace(c); c != "" {
			cidrs = append(cidrs, c)
		}
	}
	sessionTTL := 600 * time.Second
	if v := os.Getenv("SESSION_TTL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			sessionTTL = time.Duration(secs) * time.Second
		}
	}
	healthCheckURL := os.Getenv("HEALTH_CHECK_URL")
	if healthCheckURL == "" {
		healthCheckURL = "http://1.1.1.1"
	}

	store, err := NewSessionStore(cidrs, sessionTTL, healthCheckURL)
	if err != nil {
		log.Fatal("[FATAL] invalid SUBNETS: ", err)
	}

	for _, s := range store.pool.subnets {
		log.Printf("[BOOT] Subnet: %s (%d IPs)", s.cidr, s.HostCount())
	}
	log.Printf("[BOOT] %d subnets loaded, session TTL: %s, health check: %s", len(cidrs), sessionTTL, healthCheckURL)

	// HTTP requests
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		auth := req.Header.Get("Proxy-Authorization")
		session, ok := parseAuth(auth, proxyUser, proxyPass)
		if !ok {
			log.Println("[DENIED]", host)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "407 Proxy Authentication Required")
		}
		if store.pool.HealthyCount() == 0 {
			log.Println("[BLOCKED] no healthy subnets, returning 503")
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusServiceUnavailable, "503 Service Unavailable - all subnets blocked")
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
		var ipErr error
		if len(parts) == 2 {
			hostPort = parts[1]
			ip, ipErr = store.IPFor(parts[0])
		} else {
			hostPort = addr
			ip, ipErr = store.RandomIP()
		}
		if ipErr != nil {
			return nil, fmt.Errorf("no healthy subnets: %w", ipErr)
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
