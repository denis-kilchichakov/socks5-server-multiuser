package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestHelper provides utilities for testing multi-user functionality
type TestHelper struct {
	t      *testing.T
	logger *log.Logger
}

// NewTestHelper creates a new test helper
func NewTestHelper(t *testing.T) *TestHelper {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	return &TestHelper{
		t:      t,
		logger: logger,
	}
}

// CreateTempConfigFile creates a temporary configuration file with test data
func (th *TestHelper) CreateTempConfigFile(users []TestUser, globalSettings GlobalSettings) (string, func()) {
	th.t.Helper()

	tmpFile, err := ioutil.TempFile("", "test_config_*.json")
	if err != nil {
		th.t.Fatalf("Failed to create temp file: %v", err)
	}

	configUsers := make([]User, len(users))
	for i, user := range users {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			th.t.Fatalf("Failed to hash password for user %s: %v", user.Username, err)
		}

		configUsers[i] = User{
			Username:            user.Username,
			PasswordHash:        string(hashedPassword),
			AllowedIPs:          user.AllowedIPs,
			AllowedDestinations: user.AllowedDestinations,
			Enabled:             user.Enabled,
			CreatedAt:           user.CreatedAt,
			LastLoginAt:         user.LastLoginAt,
		}
	}

	config := Config{
		Users:          configUsers,
		GlobalSettings: globalSettings,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		th.t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := ioutil.WriteFile(tmpFile.Name(), data, 0600); err != nil {
		th.t.Fatalf("Failed to write temp file: %v", err)
	}

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	return tmpFile.Name(), cleanup
}

// CreateCredentialStore creates a credential store from a temp config file
func (th *TestHelper) CreateCredentialStore(users []TestUser, globalSettings GlobalSettings) (*FileBasedCredentialStore, func()) {
	th.t.Helper()

	configFile, cleanup := th.CreateTempConfigFile(users, globalSettings)

	store, err := NewFileBasedCredentialStore(configFile, th.logger)
	if err != nil {
		cleanup()
		th.t.Fatalf("Failed to create credential store: %v", err)
	}

	return store, cleanup
}

// CreateUserManagementCLI creates a user management CLI from a temp config file
func (th *TestHelper) CreateUserManagementCLI(users []TestUser, globalSettings GlobalSettings) (*UserManagementCLI, func()) {
	th.t.Helper()

	configFile, cleanup := th.CreateTempConfigFile(users, globalSettings)

	cli, err := NewUserManagementCLI(configFile, th.logger)
	if err != nil {
		cleanup()
		th.t.Fatalf("Failed to create user management CLI: %v", err)
	}

	return cli, cleanup
}

// TestUser represents a test user configuration
type TestUser struct {
	Username            string
	Password            string
	AllowedIPs          []string
	AllowedDestinations string
	Enabled             bool
	CreatedAt           time.Time
	LastLoginAt         *time.Time
}

// DefaultTestUsers returns a set of default test users
func DefaultTestUsers() []TestUser {
	now := time.Now()
	loginTime := now.Add(-1 * time.Hour)

	return []TestUser{
		{
			Username:            "admin",
			Password:            "admin123",
			AllowedIPs:          []string{},
			AllowedDestinations: ".*",
			Enabled:             true,
			CreatedAt:           now,
			LastLoginAt:         &loginTime,
		},
		{
			Username:            "user1",
			Password:            "user123",
			AllowedIPs:          []string{"127.0.0.1", "192.168.1.0/24"},
			AllowedDestinations: ".*\\.example\\.com$",
			Enabled:             true,
			CreatedAt:           now,
			LastLoginAt:         nil,
		},
		{
			Username:            "restricted",
			Password:            "restricted123",
			AllowedIPs:          []string{"127.0.0.1"},
			AllowedDestinations: "restricted\\.example\\.com$",
			Enabled:             true,
			CreatedAt:           now,
			LastLoginAt:         nil,
		},
		{
			Username:            "disabled",
			Password:            "disabled123",
			AllowedIPs:          []string{"127.0.0.1"},
			AllowedDestinations: ".*",
			Enabled:             false,
			CreatedAt:           now,
			LastLoginAt:         nil,
		},
	}
}

// DefaultGlobalSettings returns default global settings for testing
func DefaultGlobalSettings() GlobalSettings {
	return GlobalSettings{
		Port:                       "1080",
		ConfigFile:                 "test_config.json",
		RequireAuthentication:      true,
		DefaultAllowedDestinations: ".*\\.test\\.com$",
	}
}

// AssertUserExists checks if a user exists in the credential store
func (th *TestHelper) AssertUserExists(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	_, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("Expected user %s to exist", username)
	}
}

// AssertUserNotExists checks if a user does not exist in the credential store
func (th *TestHelper) AssertUserNotExists(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	_, exists := store.GetUser(username)
	if exists {
		th.t.Errorf("Expected user %s to not exist", username)
	}
}

// AssertUserEnabled checks if a user is enabled
func (th *TestHelper) AssertUserEnabled(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if !user.Enabled {
		th.t.Errorf("Expected user %s to be enabled", username)
	}
}

// AssertUserDisabled checks if a user is disabled
func (th *TestHelper) AssertUserDisabled(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if user.Enabled {
		th.t.Errorf("Expected user %s to be disabled", username)
	}
}

// AssertValidCredentials checks if credentials are valid
func (th *TestHelper) AssertValidCredentials(store *FileBasedCredentialStore, username, password string) {
	th.t.Helper()

	if !store.Valid(username, password) {
		th.t.Errorf("Expected credentials %s:%s to be valid", username, password)
	}
}

// AssertInvalidCredentials checks if credentials are invalid
func (th *TestHelper) AssertInvalidCredentials(store *FileBasedCredentialStore, username, password string) {
	th.t.Helper()

	if store.Valid(username, password) {
		th.t.Errorf("Expected credentials %s:%s to be invalid", username, password)
	}
}

// AssertUserCount checks if the number of users matches expected count
func (th *TestHelper) AssertUserCount(store *FileBasedCredentialStore, expectedCount int) {
	th.t.Helper()

	users := store.ListUsers()
	if len(users) != expectedCount {
		th.t.Errorf("Expected %d users, got %d", expectedCount, len(users))
	}
}

// AssertUserHasAllowedIPs checks if a user has the expected allowed IPs
func (th *TestHelper) AssertUserHasAllowedIPs(store *FileBasedCredentialStore, username string, expectedIPs []string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if len(user.AllowedIPs) != len(expectedIPs) {
		th.t.Errorf("Expected %d allowed IPs for user %s, got %d", len(expectedIPs), username, len(user.AllowedIPs))
		return
	}

	for i, expectedIP := range expectedIPs {
		if i >= len(user.AllowedIPs) || user.AllowedIPs[i] != expectedIP {
			th.t.Errorf("Expected IP %s at position %d for user %s, got %s", expectedIP, i, username, user.AllowedIPs[i])
		}
	}
}

// AssertUserHasAllowedDestinations checks if a user has the expected allowed destinations
func (th *TestHelper) AssertUserHasAllowedDestinations(store *FileBasedCredentialStore, username string, expectedDestinations string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if user.AllowedDestinations != expectedDestinations {
		th.t.Errorf("Expected destinations %s for user %s, got %s", expectedDestinations, username, user.AllowedDestinations)
	}
}

// AssertUserHasLastLogin checks if a user has a last login time set
func (th *TestHelper) AssertUserHasLastLogin(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if user.LastLoginAt == nil {
		th.t.Errorf("Expected user %s to have last login time", username)
	}
}

// AssertUserHasNoLastLogin checks if a user has no last login time set
func (th *TestHelper) AssertUserHasNoLastLogin(store *FileBasedCredentialStore, username string) {
	th.t.Helper()

	user, exists := store.GetUser(username)
	if !exists {
		th.t.Errorf("User %s not found", username)
		return
	}

	if user.LastLoginAt != nil {
		th.t.Errorf("Expected user %s to have no last login time", username)
	}
}

// CreateMinimalConfig creates a minimal configuration for testing
func (th *TestHelper) CreateMinimalConfig() (string, func()) {
	th.t.Helper()

	return th.CreateTempConfigFile([]TestUser{}, DefaultGlobalSettings())
}

// CreateConfigWithSingleUser creates a configuration with a single test user
func (th *TestHelper) CreateConfigWithSingleUser(username, password string) (string, func()) {
	th.t.Helper()

	users := []TestUser{
		{
			Username:            username,
			Password:            password,
			AllowedIPs:          []string{"127.0.0.1"},
			AllowedDestinations: ".*",
			Enabled:             true,
			CreatedAt:           time.Now(),
			LastLoginAt:         nil,
		},
	}

	return th.CreateTempConfigFile(users, DefaultGlobalSettings())
}

// WaitForConfigSave waits for configuration save operations to complete
func (th *TestHelper) WaitForConfigSave() {
	th.t.Helper()
	time.Sleep(10 * time.Millisecond)
}

// CompareUsers compares two users for equality (excluding password hash)
func (th *TestHelper) CompareUsers(expected, actual *User) {
	th.t.Helper()

	if expected.Username != actual.Username {
		th.t.Errorf("Expected username %s, got %s", expected.Username, actual.Username)
	}

	if len(expected.AllowedIPs) != len(actual.AllowedIPs) {
		th.t.Errorf("Expected %d allowed IPs, got %d", len(expected.AllowedIPs), len(actual.AllowedIPs))
		return
	}

	for i, expectedIP := range expected.AllowedIPs {
		if actual.AllowedIPs[i] != expectedIP {
			th.t.Errorf("Expected IP %s at position %d, got %s", expectedIP, i, actual.AllowedIPs[i])
		}
	}

	if expected.AllowedDestinations != actual.AllowedDestinations {
		th.t.Errorf("Expected destinations %s, got %s", expected.AllowedDestinations, actual.AllowedDestinations)
	}

	if expected.Enabled != actual.Enabled {
		th.t.Errorf("Expected enabled %v, got %v", expected.Enabled, actual.Enabled)
	}
}

// LogTestStart logs the start of a test
func (th *TestHelper) LogTestStart(testName string) {
	th.t.Helper()
	th.logger.Printf("Starting test: %s", testName)
}

// LogTestEnd logs the end of a test
func (th *TestHelper) LogTestEnd(testName string) {
	th.t.Helper()
	th.logger.Printf("Completed test: %s", testName)
}