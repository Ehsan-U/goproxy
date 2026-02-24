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
| `PROXY_USER` | Basic auth username | |
| `PROXY_PASS` | Basic auth password | |
| `PROXY_PORT` | Listening port | `8080` |
| `LOG_FILE` | Log file path | `goproxy.log` |

## IP Selection

Outbound IP is chosen in this order:
1. `use_ip` request header (if valid and within subnet)
2. `use_ip` Redis key
3. Random IP from subnet
