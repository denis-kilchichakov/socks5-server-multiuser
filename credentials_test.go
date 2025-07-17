package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestNewFileBasedCredentialStore(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [
			{
				"username": "testuser",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*\\.example\\.com$",
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	if store == nil {
		t.Fatal("Expected non-nil credential store")
	}

	users := store.ListUsers()
	if len(users) != 1 {
		t.Fatalf("Expected 1 user, got %d", len(users))
	}

	if users[0] != "testuser" {
		t.Fatalf("Expected user 'testuser', got '%s'", users[0])
	}
}

func TestFileBasedCredentialStore_Valid(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	config := `{
		"users": [
			{
				"username": "validuser",
				"password_hash": "` + string(hashedPassword) + `",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "disableduser",
				"password_hash": "` + string(hashedPassword) + `",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
				"enabled": false,
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		expected bool
	}{
		{
			name:     "Valid credentials",
			username: "validuser",
			password: "password123",
			expected: true,
		},
		{
			name:     "Invalid password",
			username: "validuser",
			password: "wrongpassword",
			expected: false,
		},
		{
			name:     "Non-existent user",
			username: "nonexistent",
			password: "password123",
			expected: false,
		},
		{
			name:     "Disabled user",
			username: "disableduser",
			password: "password123",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := store.Valid(test.username, test.password)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestFileBasedCredentialStore_AddUser(t *testing.T) {
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	err = store.AddUser("newuser", "newpassword", []string{"127.0.0.1", "192.168.1.0/24"}, ".*\\.example\\.com$")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	if !store.Valid("newuser", "newpassword") {
		t.Error("Expected newly added user to be valid")
	}

	user, exists := store.GetUser("newuser")
	if !exists {
		t.Fatal("Expected user to exist after adding")
	}

	if user.Username != "newuser" {
		t.Errorf("Expected username 'newuser', got '%s'", user.Username)
	}

	if user.AllowedDestinations != ".*\\.example\\.com$" {
		t.Errorf("Expected allowed destinations '.*\\.example\\.com$', got '%s'", user.AllowedDestinations)
	}

	if len(user.AllowedIPs) != 2 {
		t.Errorf("Expected 2 allowed IPs, got %d", len(user.AllowedIPs))
	}

	if !user.Enabled {
		t.Error("Expected user to be enabled")
	}

	err = store.AddUser("newuser", "password", []string{}, "")
	if err == nil {
		t.Error("Expected error when adding duplicate user")
	}
}

func TestFileBasedCredentialStore_RemoveUser(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	config := `{
		"users": [
			{
				"username": "usertoremove",
				"password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	_, exists := store.GetUser("usertoremove")
	if !exists {
		t.Fatal("Expected user to exist before removal")
	}

	err = store.RemoveUser("usertoremove")
	if err != nil {
		t.Fatalf("Failed to remove user: %v", err)
	}

	_, exists = store.GetUser("usertoremove")
	if exists {
		t.Error("Expected user to not exist after removal")
	}

	err = store.RemoveUser("nonexistent")
	if err == nil {
		t.Error("Expected error when removing non-existent user")
	}
}

func TestFileBasedCredentialStore_UpdateUserPassword(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	config := `{
		"users": [
			{
				"username": "passworduser",
				"password_hash": "` + string(hashedPassword) + `",
				"allowed_ips": ["127.0.0.1"],
				"allowed_destinations": ".*",
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	if !store.Valid("passworduser", "oldpassword") {
		t.Error("Expected old password to be valid")
	}

	err = store.UpdateUserPassword("passworduser", "newpassword")
	if err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	if store.Valid("passworduser", "oldpassword") {
		t.Error("Expected old password to be invalid after update")
	}

	if !store.Valid("passworduser", "newpassword") {
		t.Error("Expected new password to be valid after update")
	}

	err = store.UpdateUserPassword("nonexistent", "password")
	if err == nil {
		t.Error("Expected error when updating password for non-existent user")
	}
}

func TestFileBasedCredentialStore_SaveAndLoadConfig(t *testing.T) {
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
	store, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	err = store.AddUser("saveuser", "savepassword", []string{"127.0.0.1"}, ".*")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	err = store.SaveConfig()
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	newStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create new credential store: %v", err)
	}

	if !newStore.Valid("saveuser", "savepassword") {
		t.Error("Expected user to be valid after save and reload")
	}

	user, exists := newStore.GetUser("saveuser")
	if !exists {
		t.Fatal("Expected user to exist after save and reload")
	}

	if user.Username != "saveuser" {
		t.Errorf("Expected username 'saveuser', got '%s'", user.Username)
	}
}

func TestUser_IsIPAllowed(t *testing.T) {
	user := &User{
		Username:   "testuser",
		AllowedIPs: []string{"127.0.0.1", "192.168.1.0/24", "10.0.0.10"},
	}

	user.allowedNetworks = make([]net.IPNet, 0, len(user.AllowedIPs))
	for _, ipStr := range user.AllowedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			user.allowedNetworks = append(user.allowedNetworks, net.IPNet{IP: ip, Mask: mask})
		} else if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			user.allowedNetworks = append(user.allowedNetworks, *ipNet)
		}
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Allowed single IP",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "Allowed IP in CIDR range",
			ip:       "192.168.1.100",
			expected: true,
		},
		{
			name:     "Allowed single IP 2",
			ip:       "10.0.0.10",
			expected: true,
		},
		{
			name:     "Disallowed IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "Disallowed IP in different range",
			ip:       "192.168.2.1",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := net.ParseIP(test.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", test.ip)
			}

			result := user.IsIPAllowed(ip)
			if result != test.expected {
				t.Errorf("Expected %v for IP %s, got %v", test.expected, test.ip, result)
			}
		})
	}
}

func TestUser_IsIPAllowed_NoRestrictions(t *testing.T) {
	user := &User{
		Username:        "testuser",
		AllowedIPs:      []string{},
		allowedNetworks: []net.IPNet{},
	}

	tests := []string{"127.0.0.1", "192.168.1.100", "8.8.8.8", "::1"}

	for _, ipStr := range tests {
		t.Run("No restrictions for "+ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", ipStr)
			}

			result := user.IsIPAllowed(ip)
			if !result {
				t.Errorf("Expected true for IP %s when no restrictions", ipStr)
			}
		})
	}
}

func TestUser_UpdateLastLogin(t *testing.T) {
	user := &User{
		Username:    "testuser",
		LastLoginAt: nil,
	}

	if user.LastLoginAt != nil {
		t.Error("Expected LastLoginAt to be nil initially")
	}

	before := time.Now()
	user.UpdateLastLogin()
	after := time.Now()

	if user.LastLoginAt == nil {
		t.Fatal("Expected LastLoginAt to be set after update")
	}

	if user.LastLoginAt.Before(before) || user.LastLoginAt.After(after) {
		t.Errorf("Expected LastLoginAt to be between %v and %v, got %v", before, after, *user.LastLoginAt)
	}
}