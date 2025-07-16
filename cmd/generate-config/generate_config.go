package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a single user configuration
type ConfigUser struct {
	Username             string    `json:"username"`
	PasswordHash         string    `json:"password_hash"`
	AllowedIPs           []string  `json:"allowed_ips,omitempty"`
	AllowedDestinations  string    `json:"allowed_destinations,omitempty"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
}

// GlobalSettings contains server-wide configuration
type ConfigGlobalSettings struct {
	Port                    string `json:"port"`
	ConfigFile              string `json:"config_file"`
	RequireAuthentication   bool   `json:"require_authentication"`
	DefaultAllowedDestinations string `json:"default_allowed_destinations,omitempty"`
}

// Config represents the complete multi-user configuration
type ConfigStruct struct {
	Users          []ConfigUser         `json:"users"`
	GlobalSettings ConfigGlobalSettings `json:"global_settings"`
}

func main() {
	fmt.Println("Generating SOCKS5 multi-user configuration...")

	// Generate bcrypt hashes for test passwords
	adminHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash admin password:", err)
	}

	user1Hash, err := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash user1 password:", err)
	}

	restrictedHash, err := bcrypt.GenerateFromPassword([]byte("restricted123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash restricted password:", err)
	}

	// Create configuration
	config := ConfigStruct{
		Users: []ConfigUser{
			{
				Username:            "admin",
				PasswordHash:        string(adminHash),
				AllowedIPs:          []string{},
				AllowedDestinations: "",
				Enabled:             true,
				CreatedAt:           time.Now(),
			},
			{
				Username:            "user1",
				PasswordHash:        string(user1Hash),
				AllowedIPs:          []string{"192.168.1.0/24", "10.0.0.1"},
				AllowedDestinations: ".*\\.(example\\.com|safe-site\\.org)$",
				Enabled:             true,
				CreatedAt:           time.Now(),
			},
			{
				Username:            "restricted",
				PasswordHash:        string(restrictedHash),
				AllowedIPs:          []string{"192.168.1.100"},
				AllowedDestinations: ".*\\.example\\.com$",
				Enabled:             true,
				CreatedAt:           time.Now(),
			},
		},
		GlobalSettings: ConfigGlobalSettings{
			Port:                    "1080",
			ConfigFile:              "users.json",
			RequireAuthentication:   true,
			DefaultAllowedDestinations: "",
		},
	}

	// Serialize to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Fatal("Failed to serialize config:", err)
	}

	// Write to file
	err = ioutil.WriteFile("users.json", data, 0600)
	if err != nil {
		log.Fatal("Failed to write config file:", err)
	}

	fmt.Println("Configuration file 'users.json' created successfully!")
	fmt.Println()
	fmt.Println("Test users created:")
	fmt.Println("  admin (password: admin123) - full access")
	fmt.Println("  user1 (password: user123) - IP and destination restrictions")
	fmt.Println("  restricted (password: restricted123) - strict restrictions")
	fmt.Println()
	fmt.Println("To test the server:")
	fmt.Println("  USE_MULTI_USER=true CONFIG_FILE=users.json ./socks5-multiuser")
	fmt.Println()

	// Test password verification
	fmt.Println("Testing password verification...")
	testPasswords := map[string]string{
		"admin":      "admin123",
		"user1":      "user123",
		"restricted": "restricted123",
	}

	for username, password := range testPasswords {
		for _, user := range config.Users {
			if user.Username == username {
				err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
				if err == nil {
					fmt.Printf("✓ Password verification successful for %s\n", username)
				} else {
					fmt.Printf("✗ Password verification failed for %s: %v\n", username, err)
				}
				break
			}
		}
	}
}