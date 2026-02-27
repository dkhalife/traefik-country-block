package traefik_country_block

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type discardResponseWriter struct {
	header http.Header
	code   int
}

func (w *discardResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *discardResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *discardResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

func (w *discardResponseWriter) reset() {
	w.code = 0
}

func benchmarkHandler(b *testing.B, cfg *Config) http.Handler {
	b.Helper()
	h, err := New(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "bench")
	if err != nil {
		b.Fatalf("failed to build handler: %v", err)
	}
	return h
}

func BenchmarkExtractIP_XFF(b *testing.B) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := extractIP(req); got == "" {
			b.Fatal("empty ip")
		}
	}
}

func BenchmarkServeHTTP_CacheHit(b *testing.B) {
	cfg := &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: false,
		BlockedIPs:         []string{"9.9.9.9"},
	}
	h := benchmarkHandler(b, cfg)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"

	warm := httptest.NewRecorder()
	h.ServeHTTP(warm, req)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", rr.Code)
		}
	}
}

func BenchmarkServeHTTP_CacheMissCIDR(b *testing.B) {
	cfg := &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: false,
		BlockedCountries:   nil,
		BlockedIPs:         []string{"203.0.113.0/24"},
	}
	h := benchmarkHandler(b, cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i%250+1)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", rr.Code)
		}
	}
}

func BenchmarkLookupCountry_IPv4(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		country, err := lookupCountry("1.0.0.1")
		if err != nil {
			b.Fatalf("lookup failed: %v", err)
		}
		if country == "" {
			b.Fatal("empty country")
		}
	}
}

func BenchmarkServeHTTP_Matrix(b *testing.B) {
	cfg := &Config{
		Mode:               "blocklist",
		DefaultAction:      "403",
		AllowPrivateRanges: false,
		BlockedIPs:         []string{"203.0.113.0/24"},
	}

	hotSet := buildIPPool(64, "198.51.100")
	churnSet := buildIPPool(4096, "203.0.114")

	b.Run("serial/hotset-hit", func(b *testing.B) {
		h := benchmarkHandler(b, cfg)
		preWarmHandler(h, hotSet)
		rw := &discardResponseWriter{}
		req := httptest.NewRequest("GET", "http://example.com", nil)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.RemoteAddr = hotSet[i%len(hotSet)] + ":1234"
			rw.reset()
			h.ServeHTTP(rw, req)
			if rw.code != 0 && rw.code != http.StatusOK {
				b.Fatalf("unexpected status: %d", rw.code)
			}
		}
	})

	b.Run("serial/churn-miss", func(b *testing.B) {
		h := benchmarkHandler(b, cfg)
		rw := &discardResponseWriter{}
		req := httptest.NewRequest("GET", "http://example.com", nil)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.RemoteAddr = churnSet[i%len(churnSet)] + ":1234"
			rw.reset()
			h.ServeHTTP(rw, req)
			if rw.code != 0 && rw.code != http.StatusOK && rw.code != http.StatusForbidden {
				b.Fatalf("unexpected status: %d", rw.code)
			}
		}
	})

	b.Run("serial/mixed-90-10", func(b *testing.B) {
		h := benchmarkHandler(b, cfg)
		preWarmHandler(h, hotSet)
		rw := &discardResponseWriter{}
		req := httptest.NewRequest("GET", "http://example.com", nil)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if i%10 == 0 {
				req.RemoteAddr = churnSet[i%len(churnSet)] + ":1234"
			} else {
				req.RemoteAddr = hotSet[i%len(hotSet)] + ":1234"
			}
			rw.reset()
			h.ServeHTTP(rw, req)
			if rw.code != 0 && rw.code != http.StatusOK && rw.code != http.StatusForbidden {
				b.Fatalf("unexpected status: %d", rw.code)
			}
		}
	})

	for _, workers := range []int{1, 8, 32} {
		workers := workers
		b.Run(fmt.Sprintf("parallel-%d/hotset-hit", workers), func(b *testing.B) {
			h := benchmarkHandler(b, cfg)
			preWarmHandler(h, hotSet)
			b.SetParallelism(workers)

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				rw := &discardResponseWriter{}
				idx := 0
				for pb.Next() {
					req.RemoteAddr = hotSet[idx%len(hotSet)] + ":1234"
					rw.reset()
					h.ServeHTTP(rw, req)
					if rw.code != 0 && rw.code != http.StatusOK {
						b.Fatalf("unexpected status: %d", rw.code)
					}
					idx++
				}
			})
		})

		b.Run(fmt.Sprintf("parallel-%d/churn-miss", workers), func(b *testing.B) {
			h := benchmarkHandler(b, cfg)
			b.SetParallelism(workers)
			var counter atomic.Uint64

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				rw := &discardResponseWriter{}
				for pb.Next() {
					i := int(counter.Add(1)-1) % len(churnSet)
					req.RemoteAddr = churnSet[i] + ":1234"
					rw.reset()
					h.ServeHTTP(rw, req)
					if rw.code != 0 && rw.code != http.StatusOK && rw.code != http.StatusForbidden {
						b.Fatalf("unexpected status: %d", rw.code)
					}
				}
			})
		})
	}
}

func buildIPPool(size int, prefix string) []string {
	ips := make([]string, size)
	for i := 0; i < size; i++ {
		third := (i / 254) % 254
		fourth := (i % 254) + 1
		ips[i] = fmt.Sprintf("%s.%d.%d", prefix, third, fourth)
	}
	return ips
}

func preWarmHandler(h http.Handler, ips []string) {
	rw := &discardResponseWriter{}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	for _, ip := range ips {
		req.RemoteAddr = ip + ":1234"
		rw.reset()
		h.ServeHTTP(rw, req)
	}
}
