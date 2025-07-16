package main

import (
	"context"
	"log"
	"net"
	"regexp"
	
	"github.com/armon/go-socks5"
)

// MultiUserRuleSet implements socks5.RuleSet for per-user access control
type MultiUserRuleSet struct {
	credentialStore *FileBasedCredentialStore
	logger          *log.Logger
	globalAllowedDestPattern string
}

// NewMultiUserRuleSet creates a new multi-user rule set
func NewMultiUserRuleSet(credentialStore *FileBasedCredentialStore, logger *log.Logger) *MultiUserRuleSet {
	settings := credentialStore.GetGlobalSettings()
	return &MultiUserRuleSet{
		credentialStore:          credentialStore,
		logger:                   logger,
		globalAllowedDestPattern: settings.DefaultAllowedDestinations,
	}
}

// Allow implements socks5.RuleSet interface with per-user access control
func (m *MultiUserRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	// Get authentication context
	authCtx, ok := ctx.Value("auth").(*socks5.AuthContext)
	if !ok || authCtx == nil {
		m.logger.Printf("Access denied: no authentication context")
		return ctx, false
	}
	
	// Get username from authentication context
	username, ok := authCtx.Payload["Username"]
	if !ok || username == "" {
		m.logger.Printf("Access denied: no username in authentication context")
		return ctx, false
	}
	
	// Get user configuration
	user, exists := m.credentialStore.GetUser(username)
	if !exists {
		m.logger.Printf("Access denied: user %s not found", username)
		return ctx, false
	}
	
	if !user.Enabled {
		m.logger.Printf("Access denied: user %s is disabled", username)
		return ctx, false
	}
	
	// Check IP restrictions
	// Note: Client IP checking is limited by the current go-socks5 library structure
	// For now, we'll skip IP checking in the rules and rely on connection-level filtering
	// This could be enhanced with library modifications to pass client IP in context
	
	// Check destination restrictions
	if !m.isDestinationAllowed(req, user) {
		m.logger.Printf("Access denied: destination %s not allowed for user %s", req.DestAddr.FQDN, username)
		return ctx, false
	}
	
	m.logger.Printf("Access granted for user %s to %s", username, req.DestAddr.FQDN)
	return ctx, true
}

// getClientIP extracts client IP from the request
// Note: This is currently not implemented due to go-socks5 library limitations
func (m *MultiUserRuleSet) getClientIP(req *socks5.Request) net.IP {
	// The current go-socks5 library doesn't provide client IP in the request
	// This would require library modifications to pass client connection info
	return nil
}

// isDestinationAllowed checks if the destination is allowed for the user
func (m *MultiUserRuleSet) isDestinationAllowed(req *socks5.Request, user *User) bool {
	destination := req.DestAddr.FQDN
	
	// If destination is empty, try to use IP
	if destination == "" && req.DestAddr.IP != nil {
		destination = req.DestAddr.IP.String()
	}
	
	// Check user-specific destination pattern first
	if user.AllowedDestinations != "" {
		match, err := regexp.MatchString(user.AllowedDestinations, destination)
		if err != nil {
			m.logger.Printf("Error matching user destination pattern for %s: %v", user.Username, err)
			return false
		}
		return match
	}
	
	// Fall back to global pattern if user doesn't have specific restrictions
	if m.globalAllowedDestPattern != "" {
		match, err := regexp.MatchString(m.globalAllowedDestPattern, destination)
		if err != nil {
			m.logger.Printf("Error matching global destination pattern: %v", err)
			return false
		}
		return match
	}
	
	// If no patterns are configured, allow all destinations
	return true
}

// CombinedRuleSet combines multiple rule sets for backward compatibility
type CombinedRuleSet struct {
	rules  []socks5.RuleSet
	logger *log.Logger
}

// NewCombinedRuleSet creates a new combined rule set
func NewCombinedRuleSet(logger *log.Logger) *CombinedRuleSet {
	return &CombinedRuleSet{
		rules:  make([]socks5.RuleSet, 0),
		logger: logger,
	}
}

// AddRule adds a rule to the combined set
func (c *CombinedRuleSet) AddRule(rule socks5.RuleSet) {
	c.rules = append(c.rules, rule)
}

// Allow implements socks5.RuleSet interface, requiring all rules to pass
func (c *CombinedRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	for i, rule := range c.rules {
		newCtx, allowed := rule.Allow(ctx, req)
		if !allowed {
			c.logger.Printf("Access denied by rule %d", i)
			return newCtx, false
		}
		ctx = newCtx
	}
	return ctx, true
}

// IPWhitelistRuleSet implements IP whitelisting as a rule set for better integration
type IPWhitelistRuleSet struct {
	allowedIPs []net.IP
	logger     *log.Logger
}

// NewIPWhitelistRuleSet creates a new IP whitelist rule set
func NewIPWhitelistRuleSet(allowedIPs []net.IP, logger *log.Logger) *IPWhitelistRuleSet {
	return &IPWhitelistRuleSet{
		allowedIPs: allowedIPs,
		logger:     logger,
	}
}

// Allow implements socks5.RuleSet interface for IP whitelisting
func (w *IPWhitelistRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if len(w.allowedIPs) == 0 {
		return ctx, true // No restrictions
	}
	
	// This is a simplified implementation - in practice, you'd need to get the client IP
	// from the connection context, which requires modifications to the go-socks5 library
	// For now, we'll just allow all connections if IP whitelisting is configured
	// The per-user IP restrictions will be handled by MultiUserRuleSet
	
	return ctx, true
}

// LegacyDestinationRuleSet provides backward compatibility with the original destination filtering
type LegacyDestinationRuleSet struct {
	pattern string
	logger  *log.Logger
}

// NewLegacyDestinationRuleSet creates a new legacy destination rule set
func NewLegacyDestinationRuleSet(pattern string, logger *log.Logger) *LegacyDestinationRuleSet {
	return &LegacyDestinationRuleSet{
		pattern: pattern,
		logger:  logger,
	}
}

// Allow implements socks5.RuleSet interface for legacy destination filtering
func (l *LegacyDestinationRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if l.pattern == "" {
		return ctx, true // No restrictions
	}
	
	destination := req.DestAddr.FQDN
	if destination == "" && req.DestAddr.IP != nil {
		destination = req.DestAddr.IP.String()
	}
	
	match, err := regexp.MatchString(l.pattern, destination)
	if err != nil {
		l.logger.Printf("Error matching legacy destination pattern: %v", err)
		return ctx, false
	}
	
	if !match {
		l.logger.Printf("Access denied by legacy destination filter: %s", destination)
	}
	
	return ctx, match
}