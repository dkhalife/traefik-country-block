package traefik_country_block

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testDBPath = "./IP2LOCATION-LITE-DB1.BIN"

// helper to create a working config for tests
func baseBlocklistConfig() *Config {
	return &Config{
		Mode:              "blocklist",
		DatabasePath:      testDBPath,
		DefaultAction:     "403",
		AllowPrivateRanges: true,
		BlockedCountries:  []string{"CN"},
	}
}

func baseAllowlistConfig() *Config {
	return &Config{
		Mode:              "allowlist",
		DatabasePath:      testDBPath,
		DefaultAction:     "403",
		AllowPrivateRanges: true,
		AllowedCountries:  []string{"US"},
	}
}

// --- Config validation tests ---

func TestValidateConfig_ModeRequired(t *testing.T) {
	cfg := &Config{}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for missing mode")
	}
}

func TestValidateConfig_InvalidMode(t *testing.T) {
	cfg := &Config{Mode: "invalid"}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidateConfig_InvalidDefaultAction(t *testing.T) {
	cfg := &Config{Mode: "blocklist", DefaultAction: "500"}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for invalid defaultAction")
	}
}

func TestValidateConfig_AllowlistWithBlockedFields(t *testing.T) {
	cfg := &Config{Mode: "allowlist", BlockedCountries: []string{"CN"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error when allowlist has blocked fields")
	}
}

func TestValidateConfig_BlocklistWithAllowedFields(t *testing.T) {
	cfg := &Config{Mode: "blocklist", AllowedIPs: []string{"1.2.3.4"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error when blocklist has allowed fields")
	}
}

func TestValidateConfig_ValidBlocklist(t *testing.T) {
	cfg := &Config{Mode: "blocklist", BlockedCountries: []string{"CN"}}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_ValidAllowlist(t *testing.T) {
	cfg := &Config{Mode: "allowlist", AllowedCountries: []string{"US"}}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_DefaultActionFillsIn(t *testing.T) {
	cfg := &Config{Mode: "blocklist"}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultAction != "403" {
		t.Fatalf("expected defaultAction '403', got %q", cfg.DefaultAction)
	}
}

// --- CIDR parsing tests ---

func TestParseCIDRs_IPWithoutPrefix(t *testing.T) {
	nets, err := parseCIDRs([]string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	if ones, _ := nets[0].Mask.Size(); ones != 32 {
		t.Fatalf("expected /32, got /%d", ones)
	}
}

func TestParseCIDRs_IPv6WithoutPrefix(t *testing.T) {
	nets, err := parseCIDRs([]string{"2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ones, _ := nets[0].Mask.Size(); ones != 128 {
		t.Fatalf("expected /128, got /%d", ones)
	}
}

func TestParseCIDRs_ValidCIDR(t *testing.T) {
	nets, err := parseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
}

func TestParseCIDRs_InvalidIP(t *testing.T) {
	_, err := parseCIDRs([]string{"not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseCIDRs_EmptyEntry(t *testing.T) {
	nets, err := parseCIDRs([]string{""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 0 {
		t.Fatalf("expected 0 nets, got %d", len(nets))
	}
}

// --- Cache tests ---

func TestCache_GetMiss(t *testing.T) {
	c := newCache()
	_, found := c.get("1.2.3.4")
	if found {
		t.Fatal("expected cache miss")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	c := newCache()
	c.set("1.2.3.4", true)
	allowed, found := c.get("1.2.3.4")
	if !found {
		t.Fatal("expected cache hit")
	}
	if !allowed {
		t.Fatal("expected allowed=true")
	}
}

// --- CreateConfig test ---

func TestCreateConfig_Defaults(t *testing.T) {
	cfg := CreateConfig()
	if cfg.DefaultAction != "403" {
		t.Fatalf("expected default action '403', got %q", cfg.DefaultAction)
	}
	if !cfg.AllowPrivateRanges {
		t.Fatal("expected AllowPrivateRanges to default to true")
	}
}

// --- Middleware integration tests ---

func nextHandler(t *testing.T, called *bool) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		*called = true
		rw.WriteHeader(http.StatusOK)
	})
}

func TestBlocklist_PrivateIPAllowed(t *testing.T) {
	cfg := baseBlocklistConfig()
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected private IP to be allowed")
	}
}

func TestBlocklist_PrivateIPBlocked_WhenDisabled(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedIPs = []string{"10.0.0.1"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected blocked IP to be denied")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestBlocklist_BlockedCIDR(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.0/24"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "5.6.7.10:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected CIDR-matched IP to be blocked")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestBlocklist_UnblockedIPAllowed(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.0/24"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected unblocked IP to be allowed")
	}
}

func TestAllowlist_AllowedIPPasses(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = false
	cfg.AllowedCountries = nil
	cfg.AllowedIPs = []string{"8.8.8.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected allowed IP to pass")
	}
}

func TestAllowlist_NonAllowedIPBlocked(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = false
	cfg.AllowedCountries = nil
	cfg.AllowedIPs = []string{"8.8.8.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected non-allowed IP to be blocked")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestDefaultAction_404(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.DefaultAction = "404"
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestDefaultAction_Close(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.DefaultAction = "close"
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// httptest.ResponseRecorder doesn't support Hijack, so it falls back to 403
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 fallback, got %d", rr.Code)
	}
}

func TestInternalIPs_AlwaysAllowed(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.InternalIPs = []string{"100.64.0.0/10"}
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"100.64.0.1"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected internal IP to be allowed")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestXForwardedFor_Used(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected XFF IP to be used and blocked")
	}
}

func TestXRealIP_Used(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected X-Real-Ip to be used and blocked")
	}
}

func TestCacheHit_SecondRequest(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First request
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	// Second request (should hit cache)
	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "5.6.7.8:5678"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from cache, got %d", rr2.Code)
	}
}

func TestBlocklist_CountryBlocked(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	// 1.0.1.0 is in CN range per IP2Location
	cfg.BlockedCountries = []string{"AU"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1.0.0.1 is in AU per IP2Location LITE
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "1.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected AU IP to be blocked")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAllowlist_CountryAllowed(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = false
	// 1.0.0.1 is AU per IP2Location LITE
	cfg.AllowedCountries = []string{"AU"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "1.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected AU IP to be allowed")
	}
}

func TestNew_InvalidConfig(t *testing.T) {
	cfg := &Config{Mode: "invalid"}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNew_InvalidDBPath(t *testing.T) {
	cfg := &Config{
		Mode:         "blocklist",
		DatabasePath: "/nonexistent/path.bin",
	}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

func TestNew_InvalidCIDR(t *testing.T) {
	cfg := &Config{
		Mode:         "blocklist",
		DatabasePath: testDBPath,
		BlockedIPs:   []string{"not-valid"},
	}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNew_InvalidInternalIP(t *testing.T) {
	cfg := &Config{
		Mode:         "blocklist",
		DatabasePath: testDBPath,
		InternalIPs:  []string{"not-valid"},
	}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid internal IP")
	}
}
