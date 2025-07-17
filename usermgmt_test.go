package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestNewUserManagementCLI(t *testing.T) {
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
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI: %v", err)
	}

	if cli == nil {
		t.Fatal("Expected non-nil CLI")
	}

	if cli.credStore == nil {
		t.Fatal("Expected non-nil credential store")
	}

	if cli.logger == nil {
		t.Fatal("Expected non-nil logger")
	}
}

func TestNewUserManagementCLI_InvalidConfig(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	invalidConfig := `{
		"users": [
			{
				"username": "test",
				"invalid_field": "value"
		],
		"global_settings": {
			"port": "1080"
		}
	}`

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(invalidConfig), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	_, err = NewUserManagementCLI(tmpFile.Name(), logger)
	if err == nil {
		t.Error("Expected error for invalid config file")
	}
}

func TestUserManagementCLI_RemoveUser(t *testing.T) {
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
				"username": "usertoremove",
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
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI: %v", err)
	}

	_, exists := cli.credStore.GetUser("usertoremove")
	if !exists {
		t.Fatal("Expected user to exist before removal")
	}

	err = cli.RemoveUser("usertoremove")
	if err != nil {
		t.Fatalf("Failed to remove user: %v", err)
	}

	_, exists = cli.credStore.GetUser("usertoremove")
	if exists {
		t.Error("Expected user to not exist after removal")
	}

	err = cli.RemoveUser("nonexistent")
	if err == nil {
		t.Error("Expected error when removing non-existent user")
	}
}

func TestUserManagementCLI_ListUsers(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	now := time.Now()
	loginTime := now.Add(-1 * time.Hour)

	config := `{
		"users": [
			{
				"username": "activeuser",
				"password_hash": "` + string(hashedPassword) + `",
				"allowed_ips": ["127.0.0.1", "192.168.1.0/24"],
				"allowed_destinations": ".*\\.example\\.com$",
				"enabled": true,
				"created_at": "` + now.Format(time.RFC3339) + `",
				"last_login_at": "` + loginTime.Format(time.RFC3339) + `"
			},
			{
				"username": "disableduser",
				"password_hash": "` + string(hashedPassword) + `",
				"allowed_ips": [],
				"allowed_destinations": "",
				"enabled": false,
				"created_at": "` + now.Format(time.RFC3339) + `"
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
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI: %v", err)
	}

	cli.ListUsers()

	users := cli.credStore.ListUsers()
	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}

	activeUser, exists := cli.credStore.GetUser("activeuser")
	if !exists {
		t.Fatal("Expected activeuser to exist")
	}

	if !activeUser.Enabled {
		t.Error("Expected activeuser to be enabled")
	}

	if len(activeUser.AllowedIPs) != 2 {
		t.Errorf("Expected 2 allowed IPs for activeuser, got %d", len(activeUser.AllowedIPs))
	}

	if activeUser.AllowedDestinations != ".*\\.example\\.com$" {
		t.Errorf("Expected specific destination pattern for activeuser, got %s", activeUser.AllowedDestinations)
	}

	if activeUser.LastLoginAt == nil {
		t.Error("Expected LastLoginAt to be set for activeuser")
	}

	disabledUser, exists := cli.credStore.GetUser("disableduser")
	if !exists {
		t.Fatal("Expected disableduser to exist")
	}

	if disabledUser.Enabled {
		t.Error("Expected disableduser to be disabled")
	}

	if len(disabledUser.AllowedIPs) != 0 {
		t.Errorf("Expected 0 allowed IPs for disableduser, got %d", len(disabledUser.AllowedIPs))
	}

	if disabledUser.AllowedDestinations != "" {
		t.Errorf("Expected empty destination pattern for disableduser, got %s", disabledUser.AllowedDestinations)
	}

	if disabledUser.LastLoginAt != nil {
		t.Error("Expected LastLoginAt to be nil for disableduser")
	}
}

func TestUserManagementCLI_ListUsers_Empty(t *testing.T) {
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
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI: %v", err)
	}

	cli.ListUsers()

	users := cli.credStore.ListUsers()
	if len(users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(users))
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	err = CreateDefaultConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create default config: %v", err)
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Fatal("Expected config file to exist after creation")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI with default config: %v", err)
	}

	users := cli.credStore.ListUsers()
	expectedUsers := []string{"admin", "user1", "user2"}

	if len(users) != len(expectedUsers) {
		t.Errorf("Expected %d users, got %d", len(expectedUsers), len(users))
	}

	for _, expectedUser := range expectedUsers {
		found := false
		for _, user := range users {
			if user == expectedUser {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected user %s not found in created config", expectedUser)
		}
	}

	if !cli.credStore.Valid("admin", "admin123") {
		t.Error("Expected admin user to be valid with password admin123")
	}

	if !cli.credStore.Valid("user1", "user123") {
		t.Error("Expected user1 to be valid with password user123")
	}

	if !cli.credStore.Valid("user2", "restricted123") {
		t.Error("Expected user2 to be valid with password restricted123")
	}

	adminUser, exists := cli.credStore.GetUser("admin")
	if !exists {
		t.Fatal("Expected admin user to exist")
	}

	if len(adminUser.AllowedIPs) != 0 {
		t.Errorf("Expected admin user to have no IP restrictions, got %d", len(adminUser.AllowedIPs))
	}

	if adminUser.AllowedDestinations != "" {
		t.Errorf("Expected admin user to have no destination restrictions, got %s", adminUser.AllowedDestinations)
	}

	if !adminUser.Enabled {
		t.Error("Expected admin user to be enabled")
	}

	user1, exists := cli.credStore.GetUser("user1")
	if !exists {
		t.Fatal("Expected user1 to exist")
	}

	if len(user1.AllowedIPs) != 0 {
		t.Errorf("Expected user1 to have no IP restrictions, got %d", len(user1.AllowedIPs))
	}

	if user1.AllowedDestinations != "" {
		t.Error("Expected user1 to have no destination restrictions")
	}

	user2, exists := cli.credStore.GetUser("user2")
	if !exists {
		t.Fatal("Expected user2 to exist")
	}

	if len(user2.AllowedIPs) != 0 {
		t.Errorf("Expected user2 to have no IP restrictions, got %d", len(user2.AllowedIPs))
	}

	if user2.AllowedDestinations != "" {
		t.Error("Expected user2 to have no destination restrictions")
	}
}

func TestCreateDefaultConfig_WriteError(t *testing.T) {
	err := CreateDefaultConfig("/invalid/path/config.json")
	if err == nil {
		t.Error("Expected error when writing to invalid path")
	}
}

func TestUserManagementCLI_Integration(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	err = CreateDefaultConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create default config: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	cli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create user management CLI: %v", err)
	}

	initialUsers := cli.credStore.ListUsers()
	if len(initialUsers) != 3 {
		t.Errorf("Expected 3 initial users, got %d", len(initialUsers))
	}

	err = cli.RemoveUser("user2")
	if err != nil {
		t.Fatalf("Failed to remove user2: %v", err)
	}

	afterRemovalUsers := cli.credStore.ListUsers()
	if len(afterRemovalUsers) != 2 {
		t.Errorf("Expected 2 users after removal, got %d", len(afterRemovalUsers))
	}

	_, exists := cli.credStore.GetUser("user2")
	if exists {
		t.Error("Expected user2 to not exist after removal")
	}

	newCli, err := NewUserManagementCLI(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create new CLI instance: %v", err)
	}

	persistedUsers := newCli.credStore.ListUsers()
	if len(persistedUsers) != 2 {
		t.Errorf("Expected 2 users after config reload, got %d", len(persistedUsers))
	}

	_, exists = newCli.credStore.GetUser("user2")
	if exists {
		t.Error("Expected user2 to not exist after config reload")
	}
}