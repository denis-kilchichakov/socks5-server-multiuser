package main

import (
	"encoding/json"
	"net"
	"time"
)

// User represents a single user configuration
type User struct {
	Username             string    `json:"username"`
	PasswordHash         string    `json:"password_hash"`
	AllowedIPs           []string  `json:"allowed_ips,omitempty"`
	AllowedDestinations  string    `json:"allowed_destinations,omitempty"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	
	// Parsed IP networks for efficient matching
	allowedNetworks      []net.IPNet `json:"-"`
}

// GlobalSettings contains server-wide configuration
type GlobalSettings struct {
	Port                    string `json:"port"`
	ConfigFile              string `json:"config_file"`
	RequireAuthentication   bool   `json:"require_authentication"`
	DefaultAllowedDestinations string `json:"default_allowed_destinations,omitempty"`
}

// Config represents the complete multi-user configuration
type Config struct {
	Users          []User         `json:"users"`
	GlobalSettings GlobalSettings `json:"global_settings"`
}

// UserManager provides methods for user management
type UserManager struct {
	config *Config
	userMap map[string]*User
}

// NewUserManager creates a new user manager
func NewUserManager() *UserManager {
	return &UserManager{
		config: &Config{
			Users: make([]User, 0),
			GlobalSettings: GlobalSettings{
				Port:                  "1080",
				ConfigFile:            "users.json",
				RequireAuthentication: true,
			},
		},
		userMap: make(map[string]*User),
	}
}

// LoadFromJSON loads configuration from JSON data
func (um *UserManager) LoadFromJSON(data []byte) error {
	if err := json.Unmarshal(data, um.config); err != nil {
		return err
	}
	
	// Rebuild user map and parse IP networks
	um.userMap = make(map[string]*User)
	for i := range um.config.Users {
		user := &um.config.Users[i]
		um.userMap[user.Username] = user
		
		// Parse IP networks for efficient matching
		user.allowedNetworks = make([]net.IPNet, 0, len(user.AllowedIPs))
		for _, ipStr := range user.AllowedIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				// Single IP address
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				user.allowedNetworks = append(user.allowedNetworks, net.IPNet{IP: ip, Mask: mask})
			} else if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
				// CIDR notation
				user.allowedNetworks = append(user.allowedNetworks, *ipNet)
			}
		}
	}
	
	return nil
}

// ToJSON serializes configuration to JSON
func (um *UserManager) ToJSON() ([]byte, error) {
	return json.MarshalIndent(um.config, "", "  ")
}

// GetUser retrieves a user by username
func (um *UserManager) GetUser(username string) (*User, bool) {
	user, exists := um.userMap[username]
	return user, exists
}

// GetUsers returns all users
func (um *UserManager) GetUsers() []User {
	return um.config.Users
}

// GetGlobalSettings returns global settings
func (um *UserManager) GetGlobalSettings() GlobalSettings {
	return um.config.GlobalSettings
}

// IsIPAllowed checks if an IP is allowed for a specific user
func (u *User) IsIPAllowed(ip net.IP) bool {
	if len(u.allowedNetworks) == 0 {
		return true // No restrictions
	}
	
	for _, network := range u.allowedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// UpdateLastLogin updates the last login time for a user
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}