package traefik_country_block

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

type CountryBlock struct {
	next             http.Handler
	name             string
	config           *Config
	cache            *cache
	modeNets         []*net.IPNet
	internalNets     []*net.IPNet
	countries        map[string]struct{}
	allowPrivateNets []*net.IPNet
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	var modeEntries []string
	countries := make(map[string]struct{})
	if config.Mode == "allowlist" {
		modeEntries = config.AllowedIPs
		for _, c := range config.AllowedCountries {
			countries[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
		}
	} else {
		modeEntries = config.BlockedIPs
		for _, c := range config.BlockedCountries {
			countries[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
		}
	}

	modeNets, err := parseCIDRs(modeEntries)
	if err != nil {
		return nil, fmt.Errorf("invalid IP in config: %w", err)
	}

	internalNets, err := parseCIDRs(config.InternalIPs)
	if err != nil {
		return nil, fmt.Errorf("invalid internal IP in config: %w", err)
	}

	var allowPrivateNets []*net.IPNet
	if config.AllowPrivateRanges {
		allowPrivateNets = privateRanges
	}

	return &CountryBlock{
		next:             next,
		name:             name,
		config:           config,
		cache:            newCache(),
		modeNets:         modeNets,
		internalNets:     internalNets,
		countries:        countries,
		allowPrivateNets: allowPrivateNets,
	}, nil
}

func (cb *CountryBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := extractIP(req)
	if ip == "" {
		cb.deny(rw, req)
		return
	}

	parsedIP := net.ParseIP(ip)

	if parsedIP != nil {
		if cb.isInternal(parsedIP) {
			cb.next.ServeHTTP(rw, req)
			return
		}
	}

	if allowed, found := cb.cache.get(ip); found {
		if allowed {
			cb.next.ServeHTTP(rw, req)
		} else {
			cb.deny(rw, req)
		}
		return
	}

	allowed := cb.evaluate(ip, parsedIP)
	cb.cache.set(ip, allowed)

	if allowed {
		cb.next.ServeHTTP(rw, req)
	} else {
		cb.deny(rw, req)
	}
}

func (cb *CountryBlock) isInternal(ip net.IP) bool {
	for _, n := range cb.allowPrivateNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, n := range cb.internalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (cb *CountryBlock) evaluate(ipStr string, ip net.IP) bool {
	cidrMatch := false
	if ip != nil {
		for _, n := range cb.modeNets {
			if n.Contains(ip) {
				cidrMatch = true
				break
			}
		}
	}

	countryMatch := false
	if len(cb.countries) > 0 {
		country, err := lookupCountry(ipStr)
		if err == nil && country != "" && country != "-" {
			_, countryMatch = cb.countries[strings.ToUpper(country)]
		}
	}

	matched := cidrMatch || countryMatch

	if cb.config.Mode == "allowlist" {
		return matched
	}
	return !matched
}

func (cb *CountryBlock) deny(rw http.ResponseWriter, req *http.Request) {
	switch cb.config.DefaultAction {
	case "close":
		hj, ok := rw.(http.Hijacker)
		if ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		// Fallback to 403 if hijack not supported
		rw.WriteHeader(http.StatusForbidden)
	case "404":
		rw.WriteHeader(http.StatusNotFound)
	default:
		rw.WriteHeader(http.StatusForbidden)
	}
}

func extractIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	if xri := req.Header.Get("X-Real-Ip"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}
