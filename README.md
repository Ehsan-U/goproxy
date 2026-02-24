# goproxy

HTTP/HTTPS forward proxy with outbound IP binding from a configured subnet.

## Install

```
curl -sL https://raw.githubusercontent.com/Ehsan-U/goproxy/main/install.sh | bash
```

## Usage

```
goproxy start
goproxy stop
goproxy status
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `SUBNETS` | Subnet CIDR for outbound IP binding | required |
| `PROXY_USER` | Basic auth username | required |
| `PROXY_PASS` | Basic auth password | required |
| `PROXY_PORT` | Listening port | `8080` |
| `SESSION_TTL` | Sticky session duration in seconds | `600` |
| `LOG_FILE` | Log file path | `goproxy.log` |

## Sticky Sessions

Username format: `user-session-{id}:pass`

```bash
# random IP each request
curl -x http://ehsan:pass@server:8080 https://ifconfig.me

# sticky IP — same session ID = same outbound IP
curl -x http://ehsan-session-1:pass@server:8080 https://ifconfig.me
curl -x http://ehsan-session-abc:pass@server:8080 https://ifconfig.me
```

A session stays bound to the same IP as long as it's actively used. After `SESSION_TTL` seconds (default 600) of inactivity, the session expires and the next request gets a new IP.
