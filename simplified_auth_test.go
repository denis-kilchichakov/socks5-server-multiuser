package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/bcrypt"
)

func TestSimplifiedMultiUserAuth(t *testing.T) {
	// Create temporary config file
	tmpFile, err := ioutil.TempFile("", "test_simplified_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Create test users with bcrypt hashes
	hashedPassword1, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.DefaultCost)
	hashedPassword2, _ := bcrypt.GenerateFromPassword([]byte("password2"), bcrypt.DefaultCost)
	hashedPassword3, _ := bcrypt.GenerateFromPassword([]byte("password3"), bcrypt.DefaultCost)

	config := `{
		"users": [
			{
				"username": "user1",
				"password_hash": "` + string(hashedPassword1) + `",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "user2",
				"password_hash": "` + string(hashedPassword2) + `",
				"enabled": true,
				"created_at": "2024-01-01T00:00:00Z"
			},
			{
				"username": "disabled_user",
				"password_hash": "` + string(hashedPassword3) + `",
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

	// Create logger
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// Create credential store
	credStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	// Test authentication directly
	t.Run("Valid Authentication", func(t *testing.T) {
		if !credStore.Valid("user1", "password1") {
			t.Error("Expected user1 to authenticate successfully")
		}
		if !credStore.Valid("user2", "password2") {
			t.Error("Expected user2 to authenticate successfully")
		}
	})

	t.Run("Invalid Authentication", func(t *testing.T) {
		if credStore.Valid("user1", "wrongpassword") {
			t.Error("Expected user1 with wrong password to fail authentication")
		}
		if credStore.Valid("nonexistent", "password") {
			t.Error("Expected nonexistent user to fail authentication")
		}
		if credStore.Valid("disabled_user", "password3") {
			t.Error("Expected disabled user to fail authentication")
		}
	})

	// Test SOCKS5 configuration setup
	t.Run("SOCKS5 Configuration", func(t *testing.T) {
		socks5conf := &socks5.Config{
			Logger: logger,
		}

		// Set up authentication only - no custom rule sets
		authenticator := socks5.UserPassAuthenticator{Credentials: credStore}
		socks5conf.AuthMethods = []socks5.Authenticator{authenticator}

		// Create server (don't start it, just test configuration)
		server, err := socks5.New(socks5conf)
		if err != nil {
			t.Fatalf("Failed to create SOCKS5 server: %v", err)
		}

		if server == nil {
			t.Fatal("Expected non-nil SOCKS5 server")
		}

		// Verify we have the right number of users
		users := credStore.ListUsers()
		if len(users) != 3 {
			t.Errorf("Expected 3 users, got %d", len(users))
		}

		// Verify specific users exist
		expectedUsers := map[string]bool{"user1": true, "user2": true, "disabled_user": true}
		for _, username := range users {
			if !expectedUsers[username] {
				t.Errorf("Unexpected user: %s", username)
			}
		}
	})

	// Test user management operations
	t.Run("User Management", func(t *testing.T) {
		// Add a new user
		err := credStore.AddUser("newuser", "newpass", []string{}, "")
		if err != nil {
			t.Fatalf("Failed to add new user: %v", err)
		}

		// Verify new user can authenticate
		if !credStore.Valid("newuser", "newpass") {
			t.Error("Expected new user to authenticate successfully")
		}

		// Update password
		err = credStore.UpdateUserPassword("newuser", "updatedpass")
		if err != nil {
			t.Fatalf("Failed to update user password: %v", err)
		}

		// Verify old password doesn't work
		if credStore.Valid("newuser", "newpass") {
			t.Error("Expected old password to fail after update")
		}

		// Verify new password works
		if !credStore.Valid("newuser", "updatedpass") {
			t.Error("Expected new password to work after update")
		}

		// Remove user
		err = credStore.RemoveUser("newuser")
		if err != nil {
			t.Fatalf("Failed to remove user: %v", err)
		}

		// Verify user can't authenticate after removal
		if credStore.Valid("newuser", "updatedpass") {
			t.Error("Expected removed user to fail authentication")
		}
	})

	// Test configuration persistence
	t.Run("Configuration Persistence", func(t *testing.T) {
		// Add a user
		err := credStore.AddUser("persistuser", "persistpass", []string{}, "")
		if err != nil {
			t.Fatalf("Failed to add user: %v", err)
		}

		// Save configuration
		err = credStore.SaveConfig()
		if err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}

		// Create new credential store from same file
		newCredStore, err := NewFileBasedCredentialStore(tmpFile.Name(), logger)
		if err != nil {
			t.Fatalf("Failed to create new credential store: %v", err)
		}

		// Verify user exists in new store
		if !newCredStore.Valid("persistuser", "persistpass") {
			t.Error("Expected persisted user to authenticate in new store")
		}
	})
}