package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/armon/go-socks5"
)

func TestMultiUserRuleSet_Allow(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [
			{
				"username": "admin",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "restricted",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*\\.example\\.com$",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "disabled",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
				"enabled": false,
				"created_at": "2024-01-01T00:00:00Z"
			}
		],
		"global_settings": {
			"port": "1080",
			"config_file": "test_config.json",
			"require_authentication": true,
			"default_allowed_destinations": ".*\\.default\\.com$"
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(config), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	ruleSet := NewMultiUserRuleSet(credStore, logger)

	tests := []struct {
		name        string
		username    string
		destination string
		expected    bool
	}{
		{
			name:        "Admin user can access any destination",
			username:    "admin",
			destination: "google.com",
			expected:    true,
		},
		{
			name:        "Restricted user can access allowed destination",
			username:    "restricted",
			destination: "test.example.com",
			expected:    true,
		},
		{
			name:        "Restricted user cannot access disallowed destination",
			username:    "restricted",
			destination: "google.com",
			expected:    false,
		},
		{
			name:        "Disabled user cannot access any destination",
			username:    "disabled",
			destination: "example.com",
			expected:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authCtx := &socks5.AuthContext{
				Payload: map[string]string{
					"Username": test.username,
				},
			}

			ctx := context.WithValue(context.Background(), "auth", authCtx)

			req := &socks5.Request{
				DestAddr: &socks5.AddrSpec{
					FQDN: test.destination,
				},
			}

			_, allowed := ruleSet.Allow(ctx, req)
			if allowed != test.expected {
				t.Errorf("Expected %v for user %s accessing %s, got %v", test.expected, test.username, test.destination, allowed)
			}
		})
	}
}

func TestMultiUserRuleSet_Allow_NoAuth(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [],
		"global_settings": {
			"port": "1080",
			"config_file": "test_config.json",
			"require_authentication": true
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(config), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	ruleSet := NewMultiUserRuleSet(credStore, logger)

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "No authentication context",
			ctx:  context.Background(),
		},
		{
			name: "Empty authentication context",
			ctx:  context.WithValue(context.Background(), "auth", nil),
		},
		{
			name: "Auth context without username",
			ctx: context.WithValue(context.Background(), "auth", &socks5.AuthContext{
				Payload: map[string]string{},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &socks5.Request{
				DestAddr: &socks5.AddrSpec{
					FQDN: "example.com",
				},
			}

			_, allowed := ruleSet.Allow(test.ctx, req)
			if allowed {
				t.Error("Expected access to be denied without proper authentication")
			}
		})
	}
}

func TestMultiUserRuleSet_Allow_NonExistentUser(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [],
		"global_settings": {
			"port": "1080",
			"config_file": "test_config.json",
			"require_authentication": true
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(config), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	ruleSet := NewMultiUserRuleSet(credStore, logger)

	authCtx := &socks5.AuthContext{
		Payload: map[string]string{
			"Username": "nonexistent",
		},
	}

	ctx := context.WithValue(context.Background(), "auth", authCtx)

	req := &socks5.Request{
		DestAddr: &socks5.AddrSpec{
			FQDN: "example.com",
		},
	}

	_, allowed := ruleSet.Allow(ctx, req)
	if allowed {
		t.Error("Expected access to be denied for non-existent user")
	}
}

func TestMultiUserRuleSet_isDestinationAllowed(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [
			{
				"username": "specificuser",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*\\.specific\\.com$",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "globaluser",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": "",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "norestrictionsuser",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": "",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			}
		],
		"global_settings": {
			"port": "1080",
			"config_file": "test_config.json",
			"require_authentication": true,
			"default_allowed_destinations": ".*\\.global\\.com$"
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(config), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	ruleSet := NewMultiUserRuleSet(credStore, logger)

	tests := []struct {
		name        string
		username    string
		destination string
		expected    bool
	}{
		{
			name:        "User with specific restriction matches",
			username:    "specificuser",
			destination: "test.specific.com",
			expected:    true,
		},
		{
			name:        "User with specific restriction doesn't match",
			username:    "specificuser",
			destination: "test.other.com",
			expected:    false,
		},
		{
			name:        "User without restriction uses global pattern - matches",
			username:    "globaluser",
			destination: "test.global.com",
			expected:    true,
		},
		{
			name:        "User without restriction uses global pattern - doesn't match",
			username:    "globaluser",
			destination: "test.other.com",
			expected:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, exists := credStore.GetUser(test.username)
			if !exists {
				t.Fatalf("User %s not found", test.username)
			}

			req := &socks5.Request{
				DestAddr: &socks5.AddrSpec{
					FQDN: test.destination,
				},
			}

			result := ruleSet.isDestinationAllowed(req, user)
			if result != test.expected {
				t.Errorf("Expected %v for user %s accessing %s, got %v", test.expected, test.username, test.destination, result)
			}
		})
	}
}

func TestMultiUserRuleSet_isDestinationAllowed_WithIP(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [
			{
				"username": "ipuser",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": "192\\.168\\..*",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			}
		],
		"global_settings": {
			"port": "1080",
			"config_file": "test_config.json",
			"require_authentication": true
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(config), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	ruleSet := NewMultiUserRuleSet(credStore, logger)

	user, exists := credStore.GetUser("ipuser")
	if !exists {
		t.Fatal("User ipuser not found")
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Allowed IP pattern matches",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Disallowed IP pattern doesn't match",
			ip:       "10.0.0.1",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &socks5.Request{
				DestAddr: &socks5.AddrSpec{
					FQDN: "",
					IP:   net.ParseIP(test.ip),
				},
			}

			result := ruleSet.isDestinationAllowed(req, user)
			if result != test.expected {
				t.Errorf("Expected %v for IP %s, got %v", test.expected, test.ip, result)
			}
		})
	}
}

func TestCombinedRuleSet_Allow(t *testing.T) {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	combinedRuleSet := NewCombinedRuleSet(logger)

	allowingRule := &MockRuleSet{allowResult: true}
	denyingRule := &MockRuleSet{allowResult: false}

	combinedRuleSet.AddRule(allowingRule)
	combinedRuleSet.AddRule(allowingRule)

	ctx := context.Background()
	req := &socks5.Request{
		DestAddr: &socks5.AddrSpec{
			FQDN: "test.com",
		},
	}

	_, allowed := combinedRuleSet.Allow(ctx, req)
	if !allowed {
		t.Error("Expected access to be allowed when all rules allow")
	}

	combinedRuleSet.AddRule(denyingRule)

	_, allowed = combinedRuleSet.Allow(ctx, req)
	if allowed {
		t.Error("Expected access to be denied when any rule denies")
	}
}

func TestLegacyDestinationRuleSet_Allow(t *testing.T) {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	tests := []struct {
		name        string
		pattern     string
		destination string
		expected    bool
	}{
		{
			name:        "Empty pattern allows all",
			pattern:     "",
			destination: "example.com",
			expected:    true,
		},
		{
			name:        "Pattern matches destination",
			pattern:     ".*\\.example\\.com$",
			destination: "test.example.com",
			expected:    true,
		},
		{
			name:        "Pattern doesn't match destination",
			pattern:     ".*\\.example\\.com$",
			destination: "test.other.com",
			expected:    false,
		},
		{
			name:        "Pattern matches IP",
			pattern:     "192\\.168\\..*",
			destination: "",
			expected:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ruleSet := NewLegacyDestinationRuleSet(test.pattern, logger)

			req := &socks5.Request{
				DestAddr: &socks5.AddrSpec{
					FQDN: test.destination,
				},
			}

			if test.destination == "" {
				req.DestAddr.IP = net.ParseIP("192.168.1.1")
			}

			ctx := context.Background()
			_, allowed := ruleSet.Allow(ctx, req)
			if allowed != test.expected {
				t.Errorf("Expected %v for pattern %s and destination %s, got %v", test.expected, test.pattern, test.destination, allowed)
			}
		})
	}
}

func TestIPWhitelistRuleSet_Allow(t *testing.T) {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	allowedIPs := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.1.1"),
	}

	ruleSet := NewIPWhitelistRuleSet(allowedIPs, logger)

	ctx := context.Background()
	req := &socks5.Request{
		DestAddr: &socks5.AddrSpec{
			FQDN: "example.com",
		},
	}

	_, allowed := ruleSet.Allow(ctx, req)
	if !allowed {
		t.Error("Expected access to be allowed (current implementation always allows)")
	}

	emptyRuleSet := NewIPWhitelistRuleSet([]net.IP{}, logger)
	_, allowed = emptyRuleSet.Allow(ctx, req)
	if !allowed {
		t.Error("Expected access to be allowed when no IP restrictions")
	}
}

type MockRuleSet struct {
	allowResult bool
}

func (m *MockRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	return ctx, m.allowResult
}