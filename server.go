package main

import (
	"log"
	"os"

	"github.com/armon/go-socks5"
	"github.com/caarlos0/env/v6"
)

type params struct {
	User            string    `env:"PROXY_USER" envDefault:""`
	Password        string    `env:"PROXY_PASSWORD" envDefault:""`
	Port            string    `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn string    `env:"ALLOWED_DEST_FQDN" envDefault:""`
	AllowedIPs      []string  `env:"ALLOWED_IPS" envSeparator:"," envDefault:""`
	ConfigFile      string    `env:"CONFIG_FILE" envDefault:"users.json"`
	UseMultiUser    bool      `env:"USE_MULTI_USER" envDefault:"false"`
}

func main() {
	// Working with app params
	cfg := params{}
	err := env.Parse(&cfg)
	if err != nil {
		log.Printf("%+v\n", err)
	}

	// Initialize logger
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// Initialize socks5 config
	socks5conf := &socks5.Config{
		Logger: logger,
	}

	// Choose authentication method based on configuration
	if cfg.UseMultiUser {
		// Multi-user mode using configuration file
		logger.Printf("Starting in multi-user mode with config file: %s", cfg.ConfigFile)
		
		credStore, err := NewFileBasedCredentialStore(cfg.ConfigFile, logger)
		if err != nil {
			log.Fatal("Failed to initialize credential store:", err)
		}
		
		// Set up authentication only - no custom rule sets
		authenticator := socks5.UserPassAuthenticator{Credentials: credStore}
		socks5conf.AuthMethods = []socks5.Authenticator{authenticator}
		
		// Use port from config file if available
		globalSettings := credStore.GetGlobalSettings()
		if globalSettings.Port != "" {
			cfg.Port = globalSettings.Port
		}
		
		logger.Printf("Multi-user authentication enabled for %d users", len(credStore.ListUsers()))
		
	} else {
		// Legacy single-user mode
		logger.Printf("Starting in legacy single-user mode")
		
		if cfg.User+cfg.Password != "" {
			creds := socks5.StaticCredentials{
				cfg.User: cfg.Password,
			}
			cator := socks5.UserPassAuthenticator{Credentials: creds}
			socks5conf.AuthMethods = []socks5.Authenticator{cator}
		}

		if cfg.AllowedDestFqdn != "" {
			socks5conf.Rules = PermitDestAddrPattern(cfg.AllowedDestFqdn)
		}
	}

	server, err := socks5.New(socks5conf)
	if err != nil {
		log.Fatal(err)
	}

	// Set IP whitelist (legacy mode only)
	// Note: The original IP whitelist functionality appears to be a custom extension
	// that's not available in the standard go-socks5 library
	if !cfg.UseMultiUser && len(cfg.AllowedIPs) > 0 {
		logger.Printf("Warning: IP whitelist functionality requires custom go-socks5 modifications")
		logger.Printf("Allowed IPs specified: %v", cfg.AllowedIPs)
		// TODO: Implement IP whitelist as a custom RuleSet
	}

	log.Printf("Start listening proxy service on port %s\n", cfg.Port)
	if err := server.ListenAndServe("tcp", ":"+cfg.Port); err != nil {
		log.Fatal(err)
	}
}
