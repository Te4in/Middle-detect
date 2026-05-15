// Package security: Load Protector
// ============================================
// ทำหน้าที่: ป้องกัน load สูง / DoS
//   - จำกัด concurrent connection ทั้ง server
//   - จำกัด concurrent connection per-IP
//   - จำกัดขนาด request body (กัน upload bomb)
//   - Timeout (กัน slowloris)
//   - Header size limit
//
// หมายเหตุ: บางอย่างต้อง set ที่ http.Server config ไม่ใช่ middleware
//   เช่น ReadHeaderTimeout, ReadTimeout, WriteTimeout

package security

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================
// Config
// ============================================
type LoadProtectConfig struct {
	MaxConcurrentRequests   int64         // จำนวน request ที่ process พร้อมกันทั้ง server
	MaxConcurrentPerIP      int           // จำนวน request พร้อมกันต่อ IP (กัน abuse จาก 1 IP)
	MaxRequestBodyBytes     int64         // ขนาด body สูงสุด (เช่น 1<<20 = 1MB)
	RequestTimeout          time.Duration // timeout ทั้ง request (กัน handler ทำงานนานเกิน)
	SlowClientThreshold     time.Duration // ถ้า client ส่ง body ช้ากว่านี้ → drop
}

func DefaultLoadProtectConfig() LoadProtectConfig {
	return LoadProtectConfig{
		MaxConcurrentRequests: 1000,
		MaxConcurrentPerIP:    20,
		MaxRequestBodyBytes:   1 << 20, // 1 MB
		RequestTimeout:        30 * time.Second,
		SlowClientThreshold:   5 * time.Second,
	}
}

// ============================================
// Load Protector
// ============================================
type LoadProtector struct {
	config       LoadProtectConfig
	currentTotal atomic.Int64
	perIPCount   map[string]*int64
	perIPMu      sync.Mutex
}

func NewLoadProtector(cfg LoadProtectConfig) *LoadProtector {
	return &LoadProtector{
		config:     cfg,
		perIPCount: make(map[string]*int64),
	}
}

// ============================================
// Middleware: Concurrent limit (total)
// ============================================
func (lp *LoadProtector) ConcurrentLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// เพิ่ม counter
		current := lp.currentTotal.Add(1)
		defer lp.currentTotal.Add(-1)

		if current > lp.config.MaxConcurrentRequests {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================
// Middleware: Per-IP concurrent limit
// ============================================
// ใช้คู่กับ IP extractor จาก ratelimit.go
func (lp *LoadProtector) PerIPLimitMiddleware(getIP IPExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)
			counter := lp.getIPCounter(ip)

			current := atomic.AddInt64(counter, 1)
			defer atomic.AddInt64(counter, -1)

			if current > int64(lp.config.MaxConcurrentPerIP) {
				http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (lp *LoadProtector) getIPCounter(ip string) *int64 {
	lp.perIPMu.Lock()
	defer lp.perIPMu.Unlock()
	c, ok := lp.perIPCount[ip]
	if !ok {
		var v int64
		c = &v
		lp.perIPCount[ip] = c
	}
	return c
}

// ============================================
// Middleware: Body size limit
// ============================================
func (lp *LoadProtector) BodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, lp.config.MaxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================
// Middleware: Request timeout
// ============================================
// ⚠️ ใช้ http.TimeoutHandler — built-in ของ net/http
func (lp *LoadProtector) TimeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, lp.config.RequestTimeout, "request timeout")
}

// ============================================
// ฟังก์ชันช่วย: config http.Server สำหรับกัน Slowloris + DoS
// ============================================
// ใช้ตอนสร้าง server: srv := lp.ConfigureServer(&http.Server{...})
func (lp *LoadProtector) ConfigureServer(srv *http.Server) *http.Server {
	if srv.ReadHeaderTimeout == 0 {
		srv.ReadHeaderTimeout = 5 * time.Second
	}
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = 15 * time.Second
	}
	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = 30 * time.Second
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = 120 * time.Second
	}
	if srv.MaxHeaderBytes == 0 {
		srv.MaxHeaderBytes = 1 << 14 // 16 KB
	}
	return srv
}

// ============================================
// Cleanup IP counter map ที่ไม่ใช้แล้ว
// (เรียกใน goroutine ทุก N นาที)
// ============================================
func (lp *LoadProtector) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			lp.perIPMu.Lock()
			for ip, c := range lp.perIPCount {
				if atomic.LoadInt64(c) == 0 {
					delete(lp.perIPCount, ip)
				}
			}
			lp.perIPMu.Unlock()
		}
	}()
}
