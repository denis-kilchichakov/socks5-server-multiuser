package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/armon/go-socks5"
)

func TestMultiUserIntegration_FullWorkflow(t *testing.T) {
	th := NewTestHelper(t)

	store, cleanup := th.CreateCredentialStore(DefaultTestUsers(), DefaultGlobalSettings())
	defer cleanup()

	t.Run("Authentication", func(t *testing.T) {
		th.AssertValidCredentials(store, "admin", "admin123")
		th.AssertValidCredentials(store, "user1", "user123")
		th.AssertValidCredentials(store, "restricted", "restricted123")
		th.AssertInvalidCredentials(store, "disabled", "disabled123")
		th.AssertInvalidCredentials(store, "admin", "wrongpassword")
		th.AssertInvalidCredentials(store, "nonexistent", "password")
	})

	t.Run("User Management", func(t *testing.T) {
		th.AssertUserCount(store, 4)
		th.AssertUserExists(store, "admin")
		th.AssertUserExists(store, "user1")
		th.AssertUserExists(store, "restricted")
		th.AssertUserExists(store, "disabled")

		th.AssertUserEnabled(store, "admin")
		th.AssertUserEnabled(store, "user1")
		th.AssertUserEnabled(store, "restricted")
		th.AssertUserDisabled(store, "disabled")
	})

	t.Run("IP Restrictions", func(t *testing.T) {
		adminUser, _ := store.GetUser("admin")
		user1User, _ := store.GetUser("user1")
		restrictedUser, _ := store.GetUser("restricted")

		if !adminUser.IsIPAllowed(net.ParseIP("127.0.0.1")) {
			t.Error("Admin should be allowed from any IP")
		}
		if !adminUser.IsIPAllowed(net.ParseIP("8.8.8.8")) {
			t.Error("Admin should be allowed from any IP")
		}

		if !user1User.IsIPAllowed(net.ParseIP("127.0.0.1")) {
			t.Error("User1 should be allowed from 127.0.0.1")
		}
		if !user1User.IsIPAllowed(net.ParseIP("192.168.1.100")) {
			t.Error("User1 should be allowed from 192.168.1.100")
		}
		if user1User.IsIPAllowed(net.ParseIP("8.8.8.8")) {
			t.Error("User1 should not be allowed from 8.8.8.8")
		}

		if !restrictedUser.IsIPAllowed(net.ParseIP("127.0.0.1")) {
			t.Error("Restricted user should be allowed from 127.0.0.1")
		}
		if restrictedUser.IsIPAllowed(net.ParseIP("192.168.1.100")) {
			t.Error("Restricted user should not be allowed from 192.168.1.100")
		}
	})

	t.Run("Access Control Rules", func(t *testing.T) {
		logger := th.logger
		ruleSet := NewMultiUserRuleSet(store, logger)

		tests := []struct {
			name        string
			username    string
			destination string
			expected    bool
		}{
			{"Admin access to any site", "admin", "google.com", true},
			{"User1 access to allowed site", "user1", "test.example.com", true},
			{"User1 access to disallowed site", "user1", "google.com", false},
			{"Restricted access to allowed site", "restricted", "restricted.example.com", true},
			{"Restricted access to disallowed site", "restricted", "test.example.com", false},
			{"Disabled user access denied", "disabled", "example.com", false},
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
					t.Errorf("Expected %v for %s accessing %s, got %v", 
						test.expected, test.username, test.destination, allowed)
				}
			})
		}
	})

	t.Run("Configuration Persistence", func(t *testing.T) {
		err := store.AddUser("newuser", "newpass", []string{"10.0.0.1"}, ".*\\.new\\.com$")
		if err != nil {
			t.Fatalf("Failed to add user: %v", err)
		}

		err = store.SaveConfig()
		if err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}

		th.AssertUserCount(store, 5)
		th.AssertValidCredentials(store, "newuser", "newpass")
		th.AssertUserHasAllowedIPs(store, "newuser", []string{"10.0.0.1"})
		th.AssertUserHasAllowedDestinations(store, "newuser", ".*\\.new\\.com$")
	})

	t.Run("User Removal", func(t *testing.T) {
		err := store.RemoveUser("newuser")
		if err != nil {
			t.Fatalf("Failed to remove user: %v", err)
		}

		th.AssertUserCount(store, 4)
		th.AssertUserNotExists(store, "newuser")
		th.AssertInvalidCredentials(store, "newuser", "newpass")
	})

	t.Run("Password Update", func(t *testing.T) {
		th.AssertValidCredentials(store, "user1", "user123")

		err := store.UpdateUserPassword("user1", "newpassword")
		if err != nil {
			t.Fatalf("Failed to update password: %v", err)
		}

		th.AssertInvalidCredentials(store, "user1", "user123")
		th.AssertValidCredentials(store, "user1", "newpassword")
	})

	t.Run("Last Login Tracking", func(t *testing.T) {
		user, _ := store.GetUser("user1")
		originalLastLogin := user.LastLoginAt

		store.Valid("user1", "newpassword")

		user, _ = store.GetUser("user1")
		newLastLogin := user.LastLoginAt

		if newLastLogin == nil {
			t.Error("Expected last login to be set after authentication")
		}

		if originalLastLogin != nil && !newLastLogin.After(*originalLastLogin) {
			t.Error("Expected last login to be updated after authentication")
		}
	})
}

func TestMultiUserIntegration_CLI(t *testing.T) {
	th := NewTestHelper(t)

	cli, cleanup := th.CreateUserManagementCLI([]TestUser{}, DefaultGlobalSettings())
	defer cleanup()

	t.Run("Initial State", func(t *testing.T) {
		th.AssertUserCount(cli.credStore, 0)
		users := cli.credStore.ListUsers()
		if len(users) != 0 {
			t.Errorf("Expected 0 users initially, got %d", len(users))
		}
	})

	t.Run("Add User", func(t *testing.T) {
		err := cli.credStore.AddUser("testuser", "testpass", []string{"127.0.0.1"}, ".*\\.test\\.com$")
		if err != nil {
			t.Fatalf("Failed to add user: %v", err)
		}

		th.AssertUserCount(cli.credStore, 1)
		th.AssertUserExists(cli.credStore, "testuser")
		th.AssertValidCredentials(cli.credStore, "testuser", "testpass")
		th.AssertUserEnabled(cli.credStore, "testuser")
	})

	t.Run("List Users", func(t *testing.T) {
		users := cli.credStore.ListUsers()
		if len(users) != 1 {
			t.Errorf("Expected 1 user, got %d", len(users))
		}
		if users[0] != "testuser" {
			t.Errorf("Expected user 'testuser', got %s", users[0])
		}
	})

	t.Run("Remove User", func(t *testing.T) {
		err := cli.RemoveUser("testuser")
		if err != nil {
			t.Fatalf("Failed to remove user: %v", err)
		}

		th.AssertUserCount(cli.credStore, 0)
		th.AssertUserNotExists(cli.credStore, "testuser")
	})

	t.Run("Persistence", func(t *testing.T) {
		err := cli.credStore.AddUser("persistuser", "persistpass", []string{}, ".*")
		if err != nil {
			t.Fatalf("Failed to add user: %v", err)
		}

		err = cli.credStore.SaveConfig()
		if err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}

		th.AssertUserCount(cli.credStore, 1)
		th.AssertValidCredentials(cli.credStore, "persistuser", "persistpass")
	})
}

func TestMultiUserIntegration_EdgeCases(t *testing.T) {
	th := NewTestHelper(t)

	t.Run("Empty Configuration", func(t *testing.T) {
		store, cleanup := th.CreateCredentialStore([]TestUser{}, DefaultGlobalSettings())
		defer cleanup()

		th.AssertUserCount(store, 0)
		th.AssertInvalidCredentials(store, "anyuser", "anypass")
	})

	t.Run("User with No Restrictions", func(t *testing.T) {
		users := []TestUser{
			{
				Username:            "unrestricted",
				Password:            "pass",
				AllowedIPs:          []string{},
				AllowedDestinations: "",
				Enabled:             true,
				CreatedAt:           time.Now(),
				LastLoginAt:         nil,
			},
		}

		store, cleanup := th.CreateCredentialStore(users, DefaultGlobalSettings())
		defer cleanup()

		user, _ := store.GetUser("unrestricted")
		
		if !user.IsIPAllowed(net.ParseIP("127.0.0.1")) {
			t.Error("Unrestricted user should be allowed from any IP")
		}
		if !user.IsIPAllowed(net.ParseIP("8.8.8.8")) {
			t.Error("Unrestricted user should be allowed from any IP")
		}
	})

	t.Run("User with Complex IP Restrictions", func(t *testing.T) {
		users := []TestUser{
			{
				Username:            "complex",
				Password:            "pass",
				AllowedIPs:          []string{"10.0.0.1", "192.168.0.0/16", "172.16.0.0/12"},
				AllowedDestinations: "",
				Enabled:             true,
				CreatedAt:           time.Now(),
				LastLoginAt:         nil,
			},
		}

		store, cleanup := th.CreateCredentialStore(users, DefaultGlobalSettings())
		defer cleanup()

		user, _ := store.GetUser("complex")

		tests := []struct {
			ip       string
			expected bool
		}{
			{"10.0.0.1", true},
			{"10.0.0.2", false},
			{"192.168.1.100", true},
			{"192.168.255.255", true},
			{"192.169.1.1", false},
			{"172.16.0.1", true},
			{"172.31.255.255", true},
			{"172.32.0.1", false},
			{"8.8.8.8", false},
		}

		for _, test := range tests {
			t.Run("IP "+test.ip, func(t *testing.T) {
				result := user.IsIPAllowed(net.ParseIP(test.ip))
				if result != test.expected {
					t.Errorf("Expected %v for IP %s, got %v", test.expected, test.ip, result)
				}
			})
		}
	})

	t.Run("Duplicate User Addition", func(t *testing.T) {
		users := []TestUser{
			{
				Username:            "existing",
				Password:            "pass",
				AllowedIPs:          []string{},
				AllowedDestinations: "",
				Enabled:             true,
				CreatedAt:           time.Now(),
				LastLoginAt:         nil,
			},
		}

		store, cleanup := th.CreateCredentialStore(users, DefaultGlobalSettings())
		defer cleanup()

		err := store.AddUser("existing", "newpass", []string{}, "")
		if err == nil {
			t.Error("Expected error when adding duplicate user")
		}

		th.AssertUserCount(store, 1)
		th.AssertInvalidCredentials(store, "existing", "newpass")
		th.AssertValidCredentials(store, "existing", "pass")
	})

	t.Run("Update Non-existent User", func(t *testing.T) {
		store, cleanup := th.CreateCredentialStore([]TestUser{}, DefaultGlobalSettings())
		defer cleanup()

		err := store.UpdateUserPassword("nonexistent", "newpass")
		if err == nil {
			t.Error("Expected error when updating non-existent user")
		}

		err = store.RemoveUser("nonexistent")
		if err == nil {
			t.Error("Expected error when removing non-existent user")
		}
	})

	t.Run("Invalid Regex Patterns", func(t *testing.T) {
		users := []TestUser{
			{
				Username:            "invalidregex",
				Password:            "pass",
				AllowedIPs:          []string{},
				AllowedDestinations: "[invalid-regex",
				Enabled:             true,
				CreatedAt:           time.Now(),
				LastLoginAt:         nil,
			},
		}

		store, cleanup := th.CreateCredentialStore(users, DefaultGlobalSettings())
		defer cleanup()

		logger := th.logger
		ruleSet := NewMultiUserRuleSet(store, logger)

		authCtx := &socks5.AuthContext{
			Payload: map[string]string{
				"Username": "invalidregex",
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
			t.Error("Expected access to be denied for invalid regex pattern")
		}
	})
}

func TestMultiUserIntegration_Performance(t *testing.T) {
	th := NewTestHelper(t)

	const numUsers = 100
	users := make([]TestUser, numUsers)
	for i := 0; i < numUsers; i++ {
		users[i] = TestUser{
			Username:            fmt.Sprintf("user%d", i),
			Password:            fmt.Sprintf("pass%d", i),
			AllowedIPs:          []string{"127.0.0.1"},
			AllowedDestinations: fmt.Sprintf(".*\\.user%d\\.com$", i),
			Enabled:             true,
			CreatedAt:           time.Now(),
			LastLoginAt:         nil,
		}
	}

	store, cleanup := th.CreateCredentialStore(users, DefaultGlobalSettings())
	defer cleanup()

	t.Run("Bulk Authentication", func(t *testing.T) {
		start := time.Now()
		
		for i := 0; i < numUsers; i++ {
			username := fmt.Sprintf("user%d", i)
			password := fmt.Sprintf("pass%d", i)
			
			if !store.Valid(username, password) {
				t.Errorf("Authentication failed for user %s", username)
			}
		}
		
		elapsed := time.Since(start)
		t.Logf("Authenticated %d users in %v (%.2f auth/sec)", 
			numUsers, elapsed, float64(numUsers)/elapsed.Seconds())
		
		if elapsed > 10*time.Second {
			t.Errorf("Authentication took too long: %v", elapsed)
		}
	})

	t.Run("Bulk User Lookup", func(t *testing.T) {
		start := time.Now()
		
		for i := 0; i < numUsers; i++ {
			username := fmt.Sprintf("user%d", i)
			
			_, exists := store.GetUser(username)
			if !exists {
				t.Errorf("User lookup failed for %s", username)
			}
		}
		
		elapsed := time.Since(start)
		t.Logf("Looked up %d users in %v (%.2f lookups/sec)", 
			numUsers, elapsed, float64(numUsers)/elapsed.Seconds())
		
		if elapsed > 1*time.Second {
			t.Errorf("User lookup took too long: %v", elapsed)
		}
	})

	t.Run("Concurrent Authentication", func(t *testing.T) {
		const numGoroutines = 10
		const authsPerGoroutine = 20
		
		results := make(chan bool, numGoroutines*authsPerGoroutine)
		
		start := time.Now()
		
		for g := 0; g < numGoroutines; g++ {
			go func(goroutineID int) {
				for i := 0; i < authsPerGoroutine; i++ {
					userIndex := (goroutineID*authsPerGoroutine + i) % numUsers
					username := fmt.Sprintf("user%d", userIndex)
					password := fmt.Sprintf("pass%d", userIndex)
					
					results <- store.Valid(username, password)
				}
			}(g)
		}
		
		successCount := 0
		for i := 0; i < numGoroutines*authsPerGoroutine; i++ {
			if <-results {
				successCount++
			}
		}
		
		elapsed := time.Since(start)
		totalAuths := numGoroutines * authsPerGoroutine
		
		t.Logf("Concurrent authentication: %d/%d successful in %v (%.2f auth/sec)", 
			successCount, totalAuths, elapsed, float64(totalAuths)/elapsed.Seconds())
		
		if successCount != totalAuths {
			t.Errorf("Expected %d successful authentications, got %d", totalAuths, successCount)
		}
		
		if elapsed > 10*time.Second {
			t.Errorf("Concurrent authentication took too long: %v", elapsed)
		}
	})
}