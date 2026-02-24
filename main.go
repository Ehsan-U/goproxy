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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/redis/go-redis/v9"
)

const pidFile = "/tmp/goproxy.pid"

type SubnetGenerator struct {
	ipNet       *net.IPNet
	redisClient *redis.Client
}

func NewSubnetGenerator(cidr string, redisClient *redis.Client) (*SubnetGenerator, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &SubnetGenerator{ipNet: ipNet, redisClient: redisClient}, nil
}

func (s *SubnetGenerator) GetFallbackIP() net.IP {
	val, err := s.redisClient.Get(context.Background(), "use_ip").Result()
	if err == nil {
		val = strings.Trim(val, "\"\n ")
		if parsed := net.ParseIP(val); parsed != nil && s.ipNet.Contains(parsed) {
			log.Println("[IP Select] Using IP from Redis:", parsed)
			return parsed
		}
		log.Println("[IP Reject] Redis IP invalid or out of subnet:", val)
	} else {
		log.Println("[DEBUG] Redis error or key not found:", err)
	}
	return s.GenerateRandom()
}

func (s *SubnetGenerator) GenerateRandom() net.IP {
	randIP := make(net.IP, len(s.ipNet.IP))
	rand.Read(randIP)
	ip := make(net.IP, len(s.ipNet.IP))
	for i := range ip {
		ip[i] = (s.ipNet.IP[i] & s.ipNet.Mask[i]) | (randIP[i] &^ s.ipNet.Mask[i])
	}
	log.Println("[IP Fallback] Using random IP:", ip)
	return ip
}

func loadWhitelist(path string) map[string]struct{} {
	m := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		log.Println("[WARN] could not load whitelist:", err)
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		if ip := strings.TrimSpace(line); ip != "" {
			m[ip] = struct{}{}
		}
	}
	return m
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

func cmdStart() {
	if pid, err := readPID(); err == nil && isRunning(pid) {
		fmt.Printf("already running (pid %d)\n", pid)
		return
	}

	logPath := os.Getenv("LOG_FILE")
	if logPath == "" {
		logPath = "goproxy.log"
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("failed to open log file:", err)
		os.Exit(1)
	}

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "_DAEMON=1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		fmt.Println("failed to start:", err)
		os.Exit(1)
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
  PROXY_USER   basic auth username
  PROXY_PASS   basic auth password
  PROXY_PORT   listening port (default: 8080)
  LOG_FILE     log file path (default: goproxy.log)
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

	// Daemon mode
	log.Println("[BOOT] Proxy starting...")

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.IdleConnTimeout = 5 * time.Second

	proxyUser := os.Getenv("PROXY_USER")
	proxyPass := os.Getenv("PROXY_PASS")
	subnet := os.Getenv("SUBNETS")
	if subnet == "" {
		log.Fatal("[FATAL] SUBNETS not set")
	}
	whitelist := loadWhitelist("whitelisted_ips.txt")

	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ipGen, err := NewSubnetGenerator(subnet, redisClient)
	if err != nil {
		log.Fatal("[FATAL] invalid SUBNETS:", err)
	}

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		log.Println("[AUTH] from", host)
		if _, ok := whitelist[host]; ok {
			return req, nil
		}
		if auth := req.Header.Get("Proxy-Authorization"); auth != "" {
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))
			if auth == expected {
				return req, nil
			}
		}
		log.Println("[DENIED]", host)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "407 Proxy Authentication Required")
	})

	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		rHost, _, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
		log.Println("[AUTH-CONNECT] from", rHost)
		if _, ok := whitelist[rHost]; ok {
			log.Println("[ACCESS-CONNECT] whitelisted")
		} else if auth := ctx.Req.Header.Get("Proxy-Authorization"); auth != "" {
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))
			if auth == expected {
				log.Println("[ACCESS-CONNECT] authorized")
			} else {
				log.Println("[DENIED-CONNECT] invalid credentials")
				return goproxy.RejectConnect, host
			}
		} else {
			log.Println("[DENIED-CONNECT] no auth header and not whitelisted")
			return goproxy.RejectConnect, host
		}
		headIP := strings.TrimSpace(ctx.Req.Header.Get("use_ip"))
		log.Println("[CONNECT header] use_ip=", headIP)
		if headIP != "" {
			return goproxy.OkConnect, headIP + "|" + host
		}
		return goproxy.OkConnect, host
	}))

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		parts := strings.SplitN(addr, "|", 2)
		var ip net.IP
		var hostPort string
		if len(parts) == 2 {
			ipStr := parts[0]
			hostPort = parts[1]
			if ipStr == "random" || ipStr == "" {
				ip = ipGen.GenerateRandom()
			} else if p := net.ParseIP(ipStr); p != nil && ipGen.ipNet.Contains(p) {
				ip = p
			} else {
				log.Println("[CONNECT] invalid header IP, fallback to Redis")
				ip = ipGen.GetFallbackIP()
			}
		} else {
			hostPort = addr
			log.Println("[CONNECT] no header IP, fallback to Redis")
			ip = ipGen.GetFallbackIP()
		}
		log.Println("[DIAL] binding:", ip, ">", hostPort)
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
