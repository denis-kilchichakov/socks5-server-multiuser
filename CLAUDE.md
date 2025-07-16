# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go SOCKS5 proxy server with multi-user authentication support. The server is built using the `github.com/armon/go-socks5` library and provides additional features like per-user IP whitelisting, destination FQDN filtering, and file-based user management with bcrypt password hashing.

## Architecture

The project consists of multiple Go files:

- `server.go`: Main application entry point with dual-mode support (legacy single-user and multi-user)
- `types.go`: User management data structures and configuration types
- `credentials.go`: File-based credential store implementing socks5.CredentialStore interface
- `multiruleset.go`: Per-user access control rules and combined rule sets
- `ruleset.go`: Legacy destination address pattern matching (backward compatibility)
- `usermgmt.go`: User management CLI utilities
- `generate_config.go`: Configuration file generator for testing

### Multi-User Mode

The server supports two modes:

**Legacy Mode (default)**: Uses environment variables for single-user authentication
- `PROXY_USER` and `PROXY_PASSWORD` for authentication
- `ALLOWED_DEST_FQDN` for destination filtering
- `ALLOWED_IPS` for IP whitelisting

**Multi-User Mode**: Uses JSON configuration file for multiple users
- `USE_MULTI_USER=true` to enable
- `CONFIG_FILE=users.json` to specify config file
- Per-user IP restrictions and destination filtering
- Bcrypt password hashing for security

## Build and Development Commands

### Build the application
```bash
go build -o socks5-multiuser .
```

### Generate test configuration
```bash
go run generate_config.go
```

### Run in legacy mode (single user)
```bash
PROXY_USER=admin PROXY_PASSWORD=admin123 ./socks5-multiuser
```

### Run in multi-user mode
```bash
USE_MULTI_USER=true CONFIG_FILE=users.json ./socks5-multiuser
```

### Build with Docker
```bash
docker build -t socks5-server .
```

### Build with Docker Compose
```bash
docker-compose -f docker-compose.build.yml up -d
```

## Configuration

### Environment Variables

The application uses the `github.com/caarlos0/env/v6` library for environment variable parsing:

- `PROXY_USER` / `PROXY_PASSWORD`: Single-user credentials (legacy mode)
- `PROXY_PORT`: Server port (default: 1080)
- `ALLOWED_DEST_FQDN`: Destination filtering regex (legacy mode)
- `ALLOWED_IPS`: IP whitelist, comma-separated (legacy mode)
- `USE_MULTI_USER`: Enable multi-user mode (default: false)
- `CONFIG_FILE`: Path to JSON configuration file (default: users.json)

### Multi-User Configuration File

The JSON configuration file structure:
```json
{
  "users": [
    {
      "username": "admin",
      "password_hash": "$2a$10$...",
      "allowed_ips": ["192.168.1.0/24"],
      "allowed_destinations": ".*\\.example\\.com$",
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

## Testing

### Test the running service

#### Legacy mode (single user)
```bash
# Without authentication
curl --socks5 localhost:1080 https://ifcfg.co

# With authentication
curl --socks5 localhost:1080 -U username:password http://ifcfg.co
```

#### Multi-user mode
```bash
# Test with admin user (full access)
curl --socks5 localhost:1080 -U admin:admin123 https://ifcfg.co

# Test with user1 (restricted access)
curl --socks5 localhost:1080 -U user1:user123 https://example.com

# Test with restricted user
curl --socks5 localhost:1080 -U restricted:restricted123 https://example.com
```

### Generate test configuration
```bash
go run generate_config.go
```

This creates a `users.json` file with three test users:
- **admin**: Full access, password: `admin123`
- **user1**: Limited IPs and destinations, password: `user123`
- **restricted**: Strict limitations, password: `restricted123`

## Dependencies

- Go 1.19+
- `github.com/armon/go-socks5` - SOCKS5 server implementation
- `github.com/caarlos0/env/v6` - Environment variable parsing
- `golang.org/x/crypto` - Bcrypt password hashing
- `golang.org/x/term` - Terminal utilities for password input
- `golang.org/x/net` - Network utilities

## Multi-User Features

### Per-User Access Control
- **IP Restrictions**: Users can be limited to specific IP addresses or CIDR ranges
- **Destination Filtering**: Users can have custom regex patterns for allowed destinations
- **Individual Enable/Disable**: Users can be temporarily disabled without removing them
- **Password Security**: Bcrypt hashing with configurable cost for password storage

### User Management
- **File-based Configuration**: JSON configuration file with hot-reload capability
- **CLI Utilities**: Helper functions for user management (add, remove, change password)
- **Audit Trail**: Creation timestamps and last login tracking
- **Backward Compatibility**: Legacy single-user mode still supported

## Docker Support

The project includes multi-architecture Docker support (amd64, armv7, arm64) with CI/CD pipeline configured in `.github/workflows/main.yml`. The Dockerfile uses a multi-stage build with distroless base image for security.