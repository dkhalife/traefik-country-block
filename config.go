package traefik_country_block

import (
	"fmt"
	"net"
	"strings"
)

type Config struct {
	Mode               string   `json:"mode"`
	DefaultAction      string   `json:"defaultAction"`
	AllowPrivateRanges bool     `json:"allowPrivateRanges"`
	InternalIPs        []string `json:"internalIPs,omitempty"`
	AllowedCountries   []string `json:"allowedCountries,omitempty"`
	AllowedIPs         []string `json:"allowedIPs,omitempty"`
	BlockedCountries   []string `json:"blockedCountries,omitempty"`
	BlockedIPs         []string `json:"blockedIPs,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		DefaultAction:      "403",
		AllowPrivateRanges: true,
	}
}

func validateConfig(cfg *Config) error {
	if cfg.Mode != "allowlist" && cfg.Mode != "blocklist" {
		return fmt.Errorf("mode must be 'allowlist' or 'blocklist', got %q", cfg.Mode)
	}

	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "403"
	}
	switch cfg.DefaultAction {
	case "403", "404", "close":
	default:
		return fmt.Errorf("defaultAction must be '403', '404', or 'close', got %q", cfg.DefaultAction)
	}

	if cfg.Mode == "allowlist" {
		if len(cfg.BlockedCountries) > 0 || len(cfg.BlockedIPs) > 0 {
			return fmt.Errorf("blockedCountries and blockedIPs must be empty when mode is 'allowlist'")
		}
	}
	if cfg.Mode == "blocklist" {
		if len(cfg.AllowedCountries) > 0 || len(cfg.AllowedIPs) > 0 {
			return fmt.Errorf("allowedCountries and allowedIPs must be empty when mode is 'blocklist'")
		}
	}

	return nil
}

// IPs without a prefix length are treated as /32 (IPv4) or /128 (IPv6).
func parseCIDRs(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %q", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %q: %w", entry, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}
