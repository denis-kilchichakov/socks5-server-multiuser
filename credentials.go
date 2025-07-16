package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
	
	"golang.org/x/crypto/bcrypt"
)

// FileBasedCredentialStore implements socks5.CredentialStore for multi-user authentication
type FileBasedCredentialStore struct {
	userManager *UserManager
	configFile  string
	mu          sync.RWMutex
	logger      *log.Logger
}

// NewFileBasedCredentialStore creates a new file-based credential store
func NewFileBasedCredentialStore(configFile string, logger *log.Logger) (*FileBasedCredentialStore, error) {
	store := &FileBasedCredentialStore{
		userManager: NewUserManager(),
		configFile:  configFile,
		logger:      logger,
	}
	
	if err := store.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}
	
	return store, nil
}

// LoadConfig loads the configuration from file
func (s *FileBasedCredentialStore) LoadConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, err := os.Stat(s.configFile); os.IsNotExist(err) {
		s.logger.Printf("Config file %s does not exist, using empty configuration", s.configFile)
		return nil
	}
	
	data, err := ioutil.ReadFile(s.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	
	if err := s.userManager.LoadFromJSON(data); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	
	s.logger.Printf("Loaded %d users from config file", len(s.userManager.GetUsers()))
	return nil
}

// SaveConfig saves the current configuration to file
func (s *FileBasedCredentialStore) SaveConfig() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	data, err := s.userManager.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize config: %v", err)
	}
	
	if err := ioutil.WriteFile(s.configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	
	return nil
}

// Valid implements socks5.CredentialStore interface
func (s *FileBasedCredentialStore) Valid(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	user, exists := s.userManager.GetUser(username)
	if !exists {
		s.logger.Printf("Authentication failed: user %s not found", username)
		return false
	}
	
	if !user.Enabled {
		s.logger.Printf("Authentication failed: user %s is disabled", username)
		return false
	}
	
	// Verify password using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.logger.Printf("Authentication failed: invalid password for user %s", username)
		return false
	}
	
	// Update last login time
	user.UpdateLastLogin()
	
	s.logger.Printf("Authentication successful for user %s", username)
	return true
}

// GetUser retrieves a user by username (thread-safe)
func (s *FileBasedCredentialStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	return s.userManager.GetUser(username)
}

// GetGlobalSettings returns global settings (thread-safe)
func (s *FileBasedCredentialStore) GetGlobalSettings() GlobalSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	return s.userManager.GetGlobalSettings()
}

// AddUser adds a new user with bcrypt password hashing
func (s *FileBasedCredentialStore) AddUser(username, password string, allowedIPs []string, allowedDestinations string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Check if user already exists
	if _, exists := s.userManager.GetUser(username); exists {
		return fmt.Errorf("user %s already exists", username)
	}
	
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	
	// Create new user
	user := User{
		Username:            username,
		PasswordHash:        string(hashedPassword),
		AllowedIPs:          allowedIPs,
		AllowedDestinations: allowedDestinations,
		Enabled:             true,
		CreatedAt:           time.Now(),
	}
	
	// Add to configuration
	s.userManager.config.Users = append(s.userManager.config.Users, user)
	s.userManager.userMap[username] = &s.userManager.config.Users[len(s.userManager.config.Users)-1]
	
	// Parse IP networks for the new user
	newUser := s.userManager.userMap[username]
	newUser.allowedNetworks = make([]net.IPNet, 0, len(newUser.AllowedIPs))
	for _, ipStr := range newUser.AllowedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			// Single IP address
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			newUser.allowedNetworks = append(newUser.allowedNetworks, net.IPNet{IP: ip, Mask: mask})
		} else if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			// CIDR notation
			newUser.allowedNetworks = append(newUser.allowedNetworks, *ipNet)
		}
	}
	
	s.logger.Printf("Added user %s", username)
	return nil
}

// RemoveUser removes a user
func (s *FileBasedCredentialStore) RemoveUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Find user index
	userIndex := -1
	for i, user := range s.userManager.config.Users {
		if user.Username == username {
			userIndex = i
			break
		}
	}
	
	if userIndex == -1 {
		return fmt.Errorf("user %s not found", username)
	}
	
	// Remove from slice
	s.userManager.config.Users = append(
		s.userManager.config.Users[:userIndex],
		s.userManager.config.Users[userIndex+1:]...,
	)
	
	// Remove from map
	delete(s.userManager.userMap, username)
	
	s.logger.Printf("Removed user %s", username)
	return nil
}

// UpdateUserPassword updates a user's password
func (s *FileBasedCredentialStore) UpdateUserPassword(username, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	user, exists := s.userManager.GetUser(username)
	if !exists {
		return fmt.Errorf("user %s not found", username)
	}
	
	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	
	user.PasswordHash = string(hashedPassword)
	s.logger.Printf("Updated password for user %s", username)
	return nil
}

// ListUsers returns all usernames
func (s *FileBasedCredentialStore) ListUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	users := s.userManager.GetUsers()
	usernames := make([]string, len(users))
	for i, user := range users {
		usernames[i] = user.Username
	}
	return usernames
}