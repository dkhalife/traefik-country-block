package traefik_country_block

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// helper to create a working config for tests
func baseBlocklistConfig() *Config {
	return &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: true,
		BlockedCountries:   []string{"CN"},
	}
}

func baseAllowlistConfig() *Config {
	return &Config{
		Mode:               "allowlist",
		DefaultAction:      "403",
		AllowPrivateRanges: true,
		AllowedCountries:   []string{"US"},
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

func TestValidateConfig_MissingDatabasePath(t *testing.T) {
	cfg := &Config{Mode: "blocklist"}
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

func TestNew_InvalidCIDR(t *testing.T) {
	cfg := &Config{
		Mode:       "blocklist",
		BlockedIPs: []string{"not-valid"},
	}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNew_InvalidInternalIP(t *testing.T) {
	cfg := &Config{
		Mode:        "blocklist",
		InternalIPs: []string{"not-valid"},
	}
	_, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid internal IP")
	}
}

// --- parseCIDRs edge cases ---

func TestParseCIDRs_InvalidCIDRWithSlash(t *testing.T) {
	_, err := parseCIDRs([]string{"1.2.3.4/abc"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR with slash")
	}
}

func TestParseCIDRs_MultipleMixed(t *testing.T) {
	nets, err := parseCIDRs([]string{"1.2.3.4", "10.0.0.0/8", "", "2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 nets, got %d", len(nets))
	}
}

// --- extractIP edge cases ---

func TestExtractIP_InvalidXFF(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "not-an-ip, 1.2.3.4")

	ip := extractIP(req)
	// Invalid XFF is skipped, should fall through to RemoteAddr
	if ip != "8.8.8.8" {
		t.Fatalf("expected '8.8.8.8', got %q", ip)
	}
}

func TestExtractIP_InvalidXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Real-Ip", "not-an-ip")

	ip := extractIP(req)
	if ip != "8.8.8.8" {
		t.Fatalf("expected '8.8.8.8', got %q", ip)
	}
}

func TestExtractIP_RemoteAddrWithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8" // no port

	ip := extractIP(req)
	// SplitHostPort fails, should return RemoteAddr
	if ip != "8.8.8.8" {
		t.Fatalf("expected '8.8.8.8', got %q", ip)
	}
}

func TestExtractIP_EmptyRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = ""

	ip := extractIP(req)
	if ip != "" {
		t.Fatalf("expected empty string, got %q", ip)
	}
}

// --- ServeHTTP edge cases ---

func TestServeHTTP_EmptyIP(t *testing.T) {
	cfg := baseBlocklistConfig()
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "" // yields empty IP
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected deny for empty IP")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestServeHTTP_CacheHitAllowed(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	cfg.BlockedIPs = []string{"9.9.9.9"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First request: 8.8.8.8 is not blocked → allowed, cached as allowed
	req1 := httptest.NewRequest("GET", "http://example.com", nil)
	req1.RemoteAddr = "8.8.8.8:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if !called {
		t.Fatal("expected first request to be allowed")
	}

	// Second request: hits cache with allowed=true
	called = false
	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "8.8.8.8:5678"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if !called {
		t.Fatal("expected second request to be allowed from cache")
	}
}

func TestServeHTTP_ParsedIPNil(t *testing.T) {
	// When RemoteAddr has no port and is a hostname, ParseIP returns nil
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = nil
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "not-an-ip" // SplitHostPort fails → returns "not-an-ip", ParseIP → nil

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Not in blocklist, parsedIP is nil → no CIDR match, no country match → allowed in blocklist mode
	if !called {
		t.Fatal("expected request to be allowed in blocklist mode with no matches")
	}
}

// --- deny edge cases ---

// mockHijackConn is a minimal net.Conn for testing
type mockHijackConn struct {
	closed bool
}

func (c *mockHijackConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *mockHijackConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (c *mockHijackConn) Close() error                       { c.closed = true; return nil }
func (c *mockHijackConn) LocalAddr() net.Addr                { return nil }
func (c *mockHijackConn) RemoteAddr() net.Addr               { return nil }
func (c *mockHijackConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockHijackConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockHijackConn) SetWriteDeadline(t time.Time) error { return nil }

type hijackResponseWriter struct {
	http.ResponseWriter
	conn     *mockHijackConn
	hijacked bool
}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

func TestDeny_CloseWithHijack(t *testing.T) {
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

	conn := &mockHijackConn{}
	rw := &hijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           conn,
	}
	handler.ServeHTTP(rw, req)

	if !rw.hijacked {
		t.Fatal("expected hijack to be called")
	}
	if !conn.closed {
		t.Fatal("expected connection to be closed")
	}
}

type failHijackResponseWriter struct {
	http.ResponseWriter
	headerWritten int
}

func (f *failHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack failed")
}

func (f *failHijackResponseWriter) WriteHeader(code int) {
	f.headerWritten = code
}

func TestDeny_CloseWithFailedHijack(t *testing.T) {
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

	rw := &failHijackResponseWriter{ResponseWriter: httptest.NewRecorder()}
	handler.ServeHTTP(rw, req)

	if rw.headerWritten != http.StatusForbidden {
		t.Fatalf("expected 403 fallback after hijack failure, got %d", rw.headerWritten)
	}
}

// --- lookupCountry tests ---

func TestLookupCountry_InvalidIP(t *testing.T) {
	_, err := lookupCountry("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestLookupCountry_IPv4(t *testing.T) {
	// 1.0.0.1 is AU per IP2Location LITE
	country, err := lookupCountry("1.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if country != "AU" {
		t.Fatalf("expected 'AU', got %q", country)
	}
}

func TestLookupCountry_IPv6Regular(t *testing.T) {
	// Regular IPv6 address − exercises the IPv6 lookup path
	country, err := lookupCountry("2607:f8b0:4004:800::200e")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With empty ipv6 data, result will be "-"
	if country != "-" {
		t.Logf("got country %q for regular IPv6", country)
	}
}

func TestLookupCountry_6to4(t *testing.T) {
	// 6to4 address: 2002:0100:0001::1 embeds IPv4 1.0.0.1 (AU)
	country, err := lookupCountry("2002:0100:0001::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if country != "AU" {
		t.Fatalf("expected 'AU' for 6to4 address embedding 1.0.0.1, got %q", country)
	}
}

func TestLookupCountry_Teredo(t *testing.T) {
	// Teredo address: 2001:0000:xxxx:xxxx:xxxx:xxxx:YYYY:ZZZZ
	// Client IPv4 = bitwise NOT of last 4 bytes
	// For 1.0.0.1: NOT = 0xFEFFFFFE → last 4 bytes = FE:FF:FF:FE
	country, err := lookupCountry("2001:0000:0000:0000:0000:0000:feff:fffe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if country != "AU" {
		t.Fatalf("expected 'AU' for Teredo embedding 1.0.0.1, got %q", country)
	}
}

// --- lookupIPv4 edge cases ---

func TestLookupIPv4_EmptyEntries(t *testing.T) {
	ensureInit()
	old := ipv4Entries
	ipv4Entries = nil
	defer func() { ipv4Entries = old }()

	result := lookupIPv4(100)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv4_BeforeFirstEntry(t *testing.T) {
	ensureInit()
	old := ipv4Entries
	ipv4Entries = []ipv4Entry{{from: 1000, country: 1}}
	defer func() { ipv4Entries = old }()

	result := lookupIPv4(50)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv4_CountryIndexOutOfBounds(t *testing.T) {
	ensureInit()
	old := ipv4Entries
	ipv4Entries = []ipv4Entry{{from: 0, country: 255}}
	defer func() { ipv4Entries = old }()

	result := lookupIPv4(50)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv4_NormalLookup(t *testing.T) {
	ensureInit()
	old := ipv4Entries
	ipv4Entries = []ipv4Entry{
		{from: 0, country: 1},   // AU
		{from: 100, country: 2}, // CN
		{from: 200, country: 3}, // JP
	}
	defer func() { ipv4Entries = old }()

	result := lookupIPv4(150) // should find entry at index 1 (CN)
	if result != "CN" {
		t.Fatalf("expected 'CN', got %q", result)
	}
}

// --- lookupIPv6 edge cases ---

func TestLookupIPv6_EmptyEntries(t *testing.T) {
	ensureInit()
	old := ipv6Entries
	ipv6Entries = nil
	defer func() { ipv6Entries = old }()

	result := lookupIPv6(0, 50)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv6_BeforeFirstEntry(t *testing.T) {
	ensureInit()
	old := ipv6Entries
	ipv6Entries = []ipv6Entry{{fromHi: 100, fromLo: 0, country: 1}}
	defer func() { ipv6Entries = old }()

	result := lookupIPv6(0, 0)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv6_CountryIndexOutOfBounds(t *testing.T) {
	ensureInit()
	old := ipv6Entries
	ipv6Entries = []ipv6Entry{{fromHi: 0, fromLo: 0, country: 255}}
	defer func() { ipv6Entries = old }()

	result := lookupIPv6(0, 50)
	if result != "-" {
		t.Fatalf("expected '-', got %q", result)
	}
}

func TestLookupIPv6_NormalLookup(t *testing.T) {
	ensureInit()
	old := ipv6Entries
	ipv6Entries = []ipv6Entry{
		{fromHi: 0, fromLo: 0, country: 1},   // AU
		{fromHi: 0, fromLo: 100, country: 2}, // CN
		{fromHi: 1, fromLo: 0, country: 3},   // JP
	}
	defer func() { ipv6Entries = old }()

	result := lookupIPv6(0, 50) // should find entry at index 0 (AU)
	if result != "AU" {
		t.Fatalf("expected 'AU', got %q", result)
	}
}

func TestLookupIPv6_HighHi(t *testing.T) {
	ensureInit()
	old := ipv6Entries
	ipv6Entries = []ipv6Entry{
		{fromHi: 0, fromLo: 0, country: 1},
		{fromHi: 5, fromLo: 0, country: 2},
		{fromHi: 10, fromLo: 0, country: 3},
	}
	defer func() { ipv6Entries = old }()

	result := lookupIPv6(7, 999) // should find entry at index 1 (CN)
	if result != "CN" {
		t.Fatalf("expected 'CN', got %q", result)
	}
}

// --- Config validation edge cases ---

func TestValidateConfig_AllowlistWithBlockedIPs(t *testing.T) {
	cfg := &Config{Mode: "allowlist", BlockedIPs: []string{"1.2.3.4"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error when allowlist has blocked IPs")
	}
}

func TestValidateConfig_BlocklistWithAllowedCountries(t *testing.T) {
	cfg := &Config{Mode: "blocklist", AllowedCountries: []string{"US"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error when blocklist has allowed countries")
	}
}

func TestValidateConfig_DefaultAction_404(t *testing.T) {
	cfg := &Config{Mode: "blocklist", DefaultAction: "404"}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_DefaultAction_Close(t *testing.T) {
	cfg := &Config{Mode: "blocklist", DefaultAction: "close"}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Allowlist mode with countries blocked by IP ---

func TestAllowlist_CountryNotAllowed(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = false
	cfg.AllowedCountries = []string{"JP"} // Only JP allowed
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1.0.0.1 is AU, which is NOT in allowed list
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "1.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected non-allowed country to be blocked")
	}
}

// --- Blocklist with countries and IPs ---

func TestBlocklist_CountryAndIPBothChecked(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = false
	cfg.BlockedCountries = []string{"AU"}
	cfg.BlockedIPs = []string{"5.6.7.8"}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 5.6.7.8 is blocked by IP
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected IP-blocked request to be denied")
	}
}

// --- Private IP ranges ---

func TestPrivateRanges_IPv6Loopback(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = true
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[::1]:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected IPv6 loopback to be allowed")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPrivateRanges_IPv6ULA(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = true
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[fc00::1]:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected IPv6 ULA to be allowed")
	}
}

func TestPrivateRanges_LinkLocal(t *testing.T) {
	cfg := baseBlocklistConfig()
	cfg.AllowPrivateRanges = true
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "169.254.1.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected link-local IP to be allowed")
	}
}

// --- evaluate with no countries configured ---

func TestEvaluate_NoCountriesConfigured(t *testing.T) {
	cfg := &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: false,
		BlockedIPs:         []string{"5.6.7.0/24"},
	}
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IP not in blocked list, no countries to check
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected unblocked IP to pass with no country check")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// --- New() with allowlist mode populates correct fields ---

func TestNew_AllowlistMode(t *testing.T) {
	cfg := &Config{
		Mode:             "allowlist",
		DefaultAction:    "403",
		AllowedCountries: []string{"us", " gb "},
		AllowedIPs:       []string{"1.2.3.4"},
	}
	handler, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cb := handler.(*CountryBlock)
	if _, ok := cb.countries["US"]; !ok {
		t.Fatal("expected US in countries")
	}
	if _, ok := cb.countries["GB"]; !ok {
		t.Fatal("expected GB in countries")
	}
	if len(cb.modeNets) != 1 {
		t.Fatalf("expected 1 mode net, got %d", len(cb.modeNets))
	}
}

func TestNew_BlocklistMode(t *testing.T) {
	cfg := &Config{
		Mode:             "blocklist",
		DefaultAction:    "403",
		BlockedCountries: []string{"cn", " ru "},
		BlockedIPs:       []string{"5.6.7.0/24"},
	}
	handler, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cb := handler.(*CountryBlock)
	if _, ok := cb.countries["CN"]; !ok {
		t.Fatal("expected CN in countries")
	}
	if _, ok := cb.countries["RU"]; !ok {
		t.Fatal("expected RU in countries")
	}
}

func TestNew_AllowPrivateRangesDisabled(t *testing.T) {
	cfg := &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: false,
	}
	handler, err := New(nil, http.DefaultServeMux, cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cb := handler.(*CountryBlock)
	if len(cb.allowPrivateNets) != 0 {
		t.Fatalf("expected no private nets, got %d", len(cb.allowPrivateNets))
	}
}

// --- Cache: set false value ---

func TestCache_SetFalseAndGet(t *testing.T) {
	c := newCache()
	c.set("1.2.3.4", false)
	allowed, found := c.get("1.2.3.4")
	if !found {
		t.Fatal("expected cache hit")
	}
	if allowed {
		t.Fatal("expected allowed=false")
	}
}

// --- decodeIPv4Data / decodeIPv6Data called directly ---

func TestDecodeIPv4Data(t *testing.T) {
	entries := decodeIPv4Data()
	if len(entries) == 0 {
		t.Fatal("expected ipv4 entries from embedded data")
	}
}

func TestDecodeIPv6Data_Empty(t *testing.T) {
	entries := decodeIPv6Data()
	// geoIPv6Data is empty const, so should return nil
	if entries != nil {
		t.Fatal("expected nil entries for empty ipv6 data")
	}
}

// --- XFF with multiple IPs (first one valid) ---

func TestExtractIP_XFFMultipleIPs(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Fatalf("expected '1.2.3.4', got %q", ip)
	}
}

// --- XFF takes precedence over X-Real-IP ---

func TestExtractIP_XFFTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "5.6.7.8")

	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Fatalf("expected '1.2.3.4' from XFF, got %q", ip)
	}
}

// --- AllowPrivateRanges with allowlist mode ---

func TestAllowlist_PrivateIPAllowed(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = true
	called := false
	handler, err := New(nil, nextHandler(t, &called), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected private IP to be allowed in allowlist mode")
	}
}

// --- InternalIPs with allowlist mode ---

func TestAllowlist_InternalIPAllowed(t *testing.T) {
	cfg := baseAllowlistConfig()
	cfg.AllowPrivateRanges = false
	cfg.AllowedCountries = nil
	cfg.InternalIPs = []string{"100.64.0.0/10"}
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
		t.Fatal("expected internal IP to be allowed in allowlist mode")
	}
}

// --- decodeIPv4 / decodeIPv6 parameterized tests ---

func TestDecodeIPv4_Empty(t *testing.T) {
	entries := decodeIPv4("")
	if entries != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestDecodeIPv4_InvalidBase64(t *testing.T) {
	entries := decodeIPv4("not-valid-base64!!!")
	if entries != nil {
		t.Fatal("expected nil for invalid base64")
	}
}

func TestDecodeIPv4_ValidData(t *testing.T) {
	// Build 2 entries: each 5 bytes [4B BE ip_from][1B country]
	raw := make([]byte, 10)
	binary.BigEndian.PutUint32(raw[0:4], 100)
	raw[4] = 1 // country index 1
	binary.BigEndian.PutUint32(raw[5:9], 200)
	raw[9] = 2 // country index 2

	b64 := base64.StdEncoding.EncodeToString(raw)
	entries := decodeIPv4(b64)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].from != 100 || entries[0].country != 1 {
		t.Fatalf("entry 0 mismatch: %+v", entries[0])
	}
	if entries[1].from != 200 || entries[1].country != 2 {
		t.Fatalf("entry 1 mismatch: %+v", entries[1])
	}
}

func TestDecodeIPv4_ShortData(t *testing.T) {
	// 3 bytes → not enough for one full 5-byte entry → n=0
	raw := []byte{1, 2, 3}
	b64 := base64.StdEncoding.EncodeToString(raw)
	entries := decodeIPv4(b64)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for short data, got %d", len(entries))
	}
}

func TestDecodeIPv6_Empty(t *testing.T) {
	entries := decodeIPv6("")
	if entries != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestDecodeIPv6_InvalidBase64(t *testing.T) {
	entries := decodeIPv6("not-valid-base64!!!")
	if entries != nil {
		t.Fatal("expected nil for invalid base64")
	}
}

func TestDecodeIPv6_ValidData(t *testing.T) {
	// Build 1 entry: 17 bytes [8B BE hi][8B BE lo][1B country]
	raw := make([]byte, 17)
	binary.BigEndian.PutUint64(raw[0:8], 1000)
	binary.BigEndian.PutUint64(raw[8:16], 2000)
	raw[16] = 3

	b64 := base64.StdEncoding.EncodeToString(raw)
	entries := decodeIPv6(b64)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].fromHi != 1000 || entries[0].fromLo != 2000 || entries[0].country != 3 {
		t.Fatalf("entry 0 mismatch: %+v", entries[0])
	}
}

func TestDecodeIPv6_ShortData(t *testing.T) {
	// 10 bytes → not enough for one 17-byte entry → n=0
	raw := make([]byte, 10)
	b64 := base64.StdEncoding.EncodeToString(raw)
	entries := decodeIPv6(b64)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for short data, got %d", len(entries))
	}
}

func TestDecodeIPv6_MultipleEntries(t *testing.T) {
	// Build 2 entries: each 17 bytes
	raw := make([]byte, 34)
	binary.BigEndian.PutUint64(raw[0:8], 100)
	binary.BigEndian.PutUint64(raw[8:16], 200)
	raw[16] = 1
	binary.BigEndian.PutUint64(raw[17:25], 300)
	binary.BigEndian.PutUint64(raw[25:33], 400)
	raw[33] = 2

	b64 := base64.StdEncoding.EncodeToString(raw)
	entries := decodeIPv6(b64)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].fromHi != 100 || entries[0].fromLo != 200 {
		t.Fatalf("entry 0 mismatch: %+v", entries[0])
	}
	if entries[1].fromHi != 300 || entries[1].fromLo != 400 {
		t.Fatalf("entry 1 mismatch: %+v", entries[1])
	}
}
