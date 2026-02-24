package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/redis/go-redis/v9"
)

type contextKey string
const userDataKey contextKey = "userData"

// SubnetGenerator handles IP selection logic

type SubnetGenerator struct {
	ipNet       *net.IPNet
	redisClient *redis.Client
}

// NewSubnetGenerator parses CIDR and returns a generator
func NewSubnetGenerator(cidr string, redisClient *redis.Client) (*SubnetGenerator, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &SubnetGenerator{ipNet: ipNet, redisClient: redisClient}, nil
}

// GetFallbackIP attempts Redis override, then random
func (s *SubnetGenerator) GetFallbackIP() net.IP {
	val, err := s.redisClient.Get(context.Background(), "use_ip").Result()
	if err == nil {
		val = strings.Trim(val, "\"\n ")
		if parsed := net.ParseIP(val); parsed != nil && s.ipNet.Contains(parsed) {
			fmt.Println("[IP Select] Using IP from Redis:", parsed)
			return parsed
		}
		fmt.Println("[IP Reject] Redis IP invalid or out of subnet:", val)
	} else {
		fmt.Println("[DEBUG] Redis error or key not found:", err)
	}
	return s.GenerateRandom()
}

// GenerateRandom picks a random IP in the subnet
func (s *SubnetGenerator) GenerateRandom() net.IP {
	randIP := make(net.IP, len(s.ipNet.IP))
	rand.Read(randIP)
	ip := make(net.IP, len(s.ipNet.IP))
	for i := range ip {
		ip[i] = (s.ipNet.IP[i] & s.ipNet.Mask[i]) | (randIP[i] &^ s.ipNet.Mask[i])
	}
	fmt.Println("[IP Fallback] Using random IP:", ip)
	return ip
}

// loadWhitelist reads whitelisted client IPs
func loadWhitelist(path string) map[string]struct{} {
	m := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("[WARN] could not load whitelist:", err)
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		if ip := strings.TrimSpace(line); ip != "" {
			m[ip] = struct{}{}
		}
	}
	return m
}

func main() {
	fmt.Println("[BOOT] Proxy starting...")
	// Initialize proxy server
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Tr.IdleConnTimeout = 5 * time.Second

	// Load configuration
	proxyUser := os.Getenv("PROXY_USER")
	proxyPass := os.Getenv("PROXY_PASS")
	subnet := os.Getenv("SUBNETS")
	if subnet == "" {
		fmt.Println("[FATAL] SUBNETS not set")
		return
	}
	whitelist := loadWhitelist("whitelisted_ips.txt")

	// Redis client and subnet generator
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ipGen, err := NewSubnetGenerator(subnet, redisClient)
	if err != nil {
		fmt.Println("[FATAL] invalid SUBNETS:", err)
		return
	}

	// HTTP auth & whitelist check
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		ctx.UserData = req
		fmt.Println("[AUTH] from", host)
		if _, ok := whitelist[host]; ok {
			return req, nil
		}
		if auth := req.Header.Get("Proxy-Authorization"); auth != "" {
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))
			if auth == expected {
				return req, nil
			}
		}
		fmt.Println("[DENIED]", host)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "407 Proxy Authentication Required")
	})

	// CONNECT handler: auth + use_ip override
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		rHost, _, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
		fmt.Println("[AUTH-CONNECT] from", rHost)
		if _, ok := whitelist[rHost]; ok {
			fmt.Println("[ACCESS-CONNECT] whitelisted")
		} else if auth := ctx.Req.Header.Get("Proxy-Authorization"); auth != "" {
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))
			if auth == expected {
				fmt.Println("[ACCESS-CONNECT] authorized")
			} else {
				fmt.Println("[DENIED-CONNECT] invalid credentials")
				return goproxy.RejectConnect, host
			}
		} else {
			fmt.Println("[DENIED-CONNECT] no auth header and not whitelisted")
			return goproxy.RejectConnect, host
		}
		// IP override
		headIP := strings.TrimSpace(ctx.Req.Header.Get("use_ip"))
		fmt.Println("[CONNECT header] use_ip=", headIP)
		if headIP != "" {
			return goproxy.OkConnect, headIP + "|" + host
		}
		return goproxy.OkConnect, host
	}))

	// Dialer: split decorated host, bind local IP
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
				fmt.Println("[CONNECT] invalid header IP, fallback to Redis")
				ip = ipGen.GetFallbackIP()
			}
		} else {
			hostPort = addr
			fmt.Println("[CONNECT] no header IP, fallback to Redis")
			ip = ipGen.GetFallbackIP()
		}
		fmt.Println("[DIAL] binding:", ip, ">", hostPort)
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 30 * time.Second}
		return d.Dial(network, hostPort)
	}

	proxy.Tr.DialContext = dialer

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Println("[BOOT] Listening on :" + port)
	http.ListenAndServe(":"+port, proxy)
}
