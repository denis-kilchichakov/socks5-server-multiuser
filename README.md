# go-socks5-proxy

![Latest tag from master branch](https://github.com/serjs/socks5-server/workflows/Latest%20tag%20from%20master%20branch/badge.svg)
![Release tag](https://github.com/serjs/socks5-server/workflows/Release%20tag/badge.svg)

Simple socks5 server using go-socks5 with multi-user authentication, per-user IP restrictions, and destination FQDNs filtering

# Operation Modes

This SOCKS5 proxy server supports two operation modes:

## Legacy Mode (Single User)

Traditional single-user authentication using environment variables:

```bash
# With authentication
docker run -d --name socks5 -p 1080:1080 -e PROXY_USER=<PROXY_USER> -e PROXY_PASSWORD=<PROXY_PASSWORD> ghcr.io/denis-kilchichakov/socks5-server-multiuser:latest

# Without authentication
docker run -d --name socks5 -p 1080:1080 ghcr.io/denis-kilchichakov/socks5-server-multiuser:latest

# Custom port
docker run -d --name socks5 -p 1090:9090 -e PROXY_PORT=9090 ghcr.io/denis-kilchichakov/socks5-server-multiuser:latest
```

## Multi-User Mode (NEW)

Enhanced multi-user support with per-user access controls:

```bash
# Generate test configuration with sample users
go run generate_config.go

# Run in multi-user mode
USE_MULTI_USER=true CONFIG_FILE=users.json go run .

# Or with Docker
docker run -d --name socks5 -p 1080:1080 -e USE_MULTI_USER=true -v $(pwd)/users.json:/users.json -e CONFIG_FILE=/users.json ghcr.io/denis-kilchichakov/socks5-server-multiuser:latest
```

### Multi-User Configuration

Create a `users.json` file with the following structure:

```json
{
  "users": [
    {
      "username": "admin",
      "password_hash": "$2a$10$...",
      "allowed_ips": [],
      "allowed_destinations": "",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00Z"
    },
    {
      "username": "user1",
      "password_hash": "$2a$10$...",
      "allowed_ips": ["192.168.1.0/24", "10.0.0.1"],
      "allowed_destinations": ".*\\.(example\\.com|safe-site\\.org)$",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "global_settings": {
    "port": "1080",
    "config_file": "users.json",
    "require_authentication": true
  }
}
```

### Multi-User Features

- **Per-User IP Restrictions**: Limit users to specific IP addresses or CIDR ranges
- **Per-User Destination Filtering**: Custom regex patterns for allowed destinations
- **Bcrypt Password Hashing**: Secure password storage
- **User Enable/Disable**: Temporarily deactivate users without removal
- **Audit Trail**: Track user creation and last login times

# Environment Variables

## Legacy Mode Parameters

|ENV variable|Type|Default|Description|
|------------|----|-------|-----------|
|PROXY_USER|String|EMPTY|Set proxy user (also required existed PROXY_PASSWORD)|
|PROXY_PASSWORD|String|EMPTY|Set proxy password for auth, used with PROXY_USER|
|PROXY_PORT|String|1080|Set listen port for application inside docker container|
|ALLOWED_DEST_FQDN|String|EMPTY|Allowed destination address regular expression pattern. Default allows all.|
|ALLOWED_IPS|String|EMPTY|Set allowed IP's that can connect to proxy, separator `,`|

## Multi-User Mode Parameters

|ENV variable|Type|Default|Description|
|------------|----|-------|-----------|
|USE_MULTI_USER|Boolean|false|Enable multi-user mode|
|CONFIG_FILE|String|users.json|Path to JSON configuration file|
|PROXY_PORT|String|1080|Set listen port (can be overridden by config file)|


# Build and Run

## Build from source

```bash
go build -o socks5-multiuser .
```

## Generate test configuration (for multi-user mode)

```bash
go run generate_config.go
```

This creates a `users.json` file with three test users:
- **admin**: password `admin123`, full access
- **user1**: password `user123`, limited IPs and destinations  
- **restricted**: password `restricted123`, strict restrictions

## Run locally

```bash
# Legacy mode
PROXY_USER=admin PROXY_PASSWORD=admin123 ./socks5-multiuser

# Multi-user mode
USE_MULTI_USER=true CONFIG_FILE=users.json ./socks5-multiuser
```

## Build Docker image

```bash
docker-compose -f docker-compose.build.yml up -d
```

Don't forget to set parameters in the `.env` file.

# Testing

## Legacy Mode

```bash
# Without authentication
curl --socks5 localhost:1080 https://ifcfg.co

# With authentication
curl --socks5 localhost:1080 -U <PROXY_USER>:<PROXY_PASSWORD> https://ifcfg.co
```

## Multi-User Mode

```bash
# Test with admin user (full access)
curl --socks5 localhost:1080 -U admin:admin123 https://ifcfg.co

# Test with user1 (limited access)
curl --socks5 localhost:1080 -U user1:user123 https://example.com

# Test with restricted user (strict limitations)
curl --socks5 localhost:1080 -U restricted:restricted123 https://example.com

# Test access denied (wrong destination for restricted user)
curl --socks5 localhost:1080 -U restricted:restricted123 https://google.com
```

## Docker Testing

```bash
# Legacy mode
docker run --rm curlimages/curl:7.65.3 -s --socks5 <PROXY_USER>:<PROXY_PASSWORD>@<docker host ip>:1080 https://ifcfg.co

# Multi-user mode
docker run --rm curlimages/curl:7.65.3 -s --socks5 admin:admin123@<docker host ip>:1080 https://ifcfg.co
```

# Authors

* **Sergey Bogayrets**

See also the list of [contributors](https://github.com/serjs/socks5-server/graphs/contributors) who participated in this project.
