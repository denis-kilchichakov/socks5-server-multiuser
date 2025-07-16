package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"syscall"
	"time"
	
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// UserManagementCLI provides command-line user management functionality
type UserManagementCLI struct {
	credStore *FileBasedCredentialStore
	logger    *log.Logger
}

// NewUserManagementCLI creates a new user management CLI
func NewUserManagementCLI(configFile string, logger *log.Logger) (*UserManagementCLI, error) {
	credStore, err := NewFileBasedCredentialStore(configFile, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize credential store: %v", err)
	}
	
	return &UserManagementCLI{
		credStore: credStore,
		logger:    logger,
	}, nil
}

// AddUserInteractive adds a user with interactive password input
func (cli *UserManagementCLI) AddUserInteractive(username string, allowedIPs []string, allowedDestinations string) error {
	fmt.Printf("Adding user: %s\n", username)
	
	// Get password securely
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println()
	
	fmt.Print("Confirm password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %v", err)
	}
	fmt.Println()
	
	if string(password) != string(confirmPassword) {
		return fmt.Errorf("passwords do not match")
	}
	
	// Add user
	err = cli.credStore.AddUser(username, string(password), allowedIPs, allowedDestinations)
	if err != nil {
		return fmt.Errorf("failed to add user: %v", err)
	}
	
	// Save configuration
	err = cli.credStore.SaveConfig()
	if err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}
	
	fmt.Printf("User %s added successfully\n", username)
	return nil
}

// RemoveUser removes a user
func (cli *UserManagementCLI) RemoveUser(username string) error {
	err := cli.credStore.RemoveUser(username)
	if err != nil {
		return fmt.Errorf("failed to remove user: %v", err)
	}
	
	// Save configuration
	err = cli.credStore.SaveConfig()
	if err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}
	
	fmt.Printf("User %s removed successfully\n", username)
	return nil
}

// ListUsers lists all users
func (cli *UserManagementCLI) ListUsers() {
	users := cli.credStore.ListUsers()
	
	if len(users) == 0 {
		fmt.Println("No users found")
		return
	}
	
	fmt.Println("Users:")
	for _, username := range users {
		if user, exists := cli.credStore.GetUser(username); exists {
			status := "enabled"
			if !user.Enabled {
				status = "disabled"
			}
			
			fmt.Printf("  %s (%s)\n", username, status)
			if len(user.AllowedIPs) > 0 {
				fmt.Printf("    Allowed IPs: %s\n", strings.Join(user.AllowedIPs, ", "))
			}
			if user.AllowedDestinations != "" {
				fmt.Printf("    Allowed Destinations: %s\n", user.AllowedDestinations)
			}
			if user.LastLoginAt != nil {
				fmt.Printf("    Last Login: %s\n", user.LastLoginAt.Format("2006-01-02 15:04:05"))
			}
		}
	}
}

// ChangePasswordInteractive changes a user's password with interactive input
func (cli *UserManagementCLI) ChangePasswordInteractive(username string) error {
	// Check if user exists
	if _, exists := cli.credStore.GetUser(username); !exists {
		return fmt.Errorf("user %s not found", username)
	}
	
	fmt.Printf("Changing password for user: %s\n", username)
	
	// Get new password securely
	fmt.Print("Enter new password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println()
	
	fmt.Print("Confirm new password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %v", err)
	}
	fmt.Println()
	
	if string(password) != string(confirmPassword) {
		return fmt.Errorf("passwords do not match")
	}
	
	// Update password
	err = cli.credStore.UpdateUserPassword(username, string(password))
	if err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}
	
	// Save configuration
	err = cli.credStore.SaveConfig()
	if err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}
	
	fmt.Printf("Password updated successfully for user %s\n", username)
	return nil
}

// CreateDefaultConfig creates a default configuration file with sample users
func CreateDefaultConfig(configFile string) error {
	// Create sample users with hashed passwords
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	user1Hash, _ := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	restrictedHash, _ := bcrypt.GenerateFromPassword([]byte("restricted123"), bcrypt.DefaultCost)
	
	config := &Config{
		Users: []User{
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
		GlobalSettings: GlobalSettings{
			Port:                    "1080",
			ConfigFile:              configFile,
			RequireAuthentication:   true,
			DefaultAllowedDestinations: "",
		},
	}
	
	um := NewUserManager()
	um.config = config
	
	data, err := um.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize config: %v", err)
	}
	
	err = ioutil.WriteFile(configFile, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	
	fmt.Printf("Default configuration created at %s\n", configFile)
	fmt.Println("Sample users created:")
	fmt.Println("  admin (password: admin123) - full access")
	fmt.Println("  user1 (password: user123) - IP and destination restrictions")
	fmt.Println("  restricted (password: restricted123) - strict restrictions")
	fmt.Println()
	fmt.Println("Please change these default passwords before production use!")
	
	return nil
}