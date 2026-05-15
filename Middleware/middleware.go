// Package security: Middleware Chain Builder
// ============================================
// ทำหน้าที่: รวม middleware ทั้งหมดเป็น chain เดียว
//   เรียงลำดับให้ถูก — order matter!
//
// ลำดับที่แนะนำ (จากนอกสุด → ในสุด):
//   1. Logger (รับ request, log)
//   2. Load protector — concurrent + body limit + timeout
//   3. IP Blocklist — block IP ที่เคย ban ก่อนเลย
//   4. Rate limiter — จำกัด request per IP
//   5. Attack detector — สแกน pattern, strike → ban
//   6. Security headers — เพิ่ม response header
//   7. Handler ของ app

package security

import (
	"net/http"
	"time"
)

// ============================================
// Security Stack — รวมทุก component
// ============================================
type SecurityStack struct {
	RateLimiter    *RateLimiter
	Detector       *AttackDetector
	Blocklist      *Blocklist
	LoadProtector  *LoadProtector
	Logger         *SecurityLogger
}

// ============================================
// Builder — สร้าง stack ทั้งหมดจาก config เดียว
// ============================================
type StackConfig struct {
	RateLimit  RateLimitConfig
	Blocklist  BlocklistConfig
	LoadProtect LoadProtectConfig
	LogFile    string
}

func DefaultStackConfig() StackConfig {
	return StackConfig{
		RateLimit:   DefaultRateLimitConfig(),
		Blocklist:   DefaultBlocklistConfig(),
		LoadProtect: DefaultLoadProtectConfig(),
		LogFile:     "./logs/security.log",
	}
}

func NewSecurityStack(cfg StackConfig) (*SecurityStack, error) {
	logger, err := NewSecurityLogger(cfg.LogFile)
	if err != nil {
		return nil, err
	}

	stack := &SecurityStack{
		RateLimiter:   NewRateLimiter(cfg.RateLimit),
		Detector:      NewAttackDetector(),
		Logger:        logger,
		LoadProtector: NewLoadProtector(cfg.LoadProtect),
	}
	stack.Blocklist = NewBlocklist(cfg.Blocklist, logger)

	// start cleanup สำหรับ IP counter
	stack.LoadProtector.StartCleanup(5 * time.Minute)

	return stack, nil
}

// ============================================
// Attack Detection Middleware
// ============================================
// แยก middleware นี้ไว้ใน chain.go เพราะมัน depend ทั้ง Detector + Blocklist + Logger
func (s *SecurityStack) AttackDetectionMiddleware(next http.Handler) http.Handler {
	getIP := s.RateLimiter.GetClientIP

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)

		result := s.Detector.Detect(r)
		if result.Detected {
			// log event
			s.Logger.Warn("attack pattern detected",
				"ip", ip,
				"path", r.URL.Path,
				"category", result.Category,
				"pattern", result.Pattern,
				"severity", result.Severity,
				"user_agent", r.UserAgent(),
				"method", r.Method,
			)

			// บันทึก strike — ถ้าครบ threshold หรือ severity = critical → ban
			banned := s.Blocklist.RecordStrike(
				ip,
				result.Category+":"+result.Pattern,
				result.Severity,
			)

			// ไม่ว่าจะ ban หรือไม่ — request นี้โดน reject ก่อน
			if banned {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================
// Security Headers Middleware
// ============================================
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' https://cdn.jsdelivr.net; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

// ============================================
// Request Logger Middleware
// ============================================
func (s *SecurityStack) RequestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}

		next.ServeHTTP(wrapped, r)

		s.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"ip", s.RateLimiter.GetClientIP(r),
			"duration_ms", time.Since(start).Milliseconds(),
			"user_agent", r.UserAgent(),
		)
	})
}

// statusWriter — wrap ResponseWriter เพื่อจับ status code
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// ============================================
// Chain — ประกอบ middleware ทั้งหมดเป็นชั้นเดียว
// ============================================
// ใช้: http.Handle("/", stack.Chain(myHandler))
func (s *SecurityStack) Chain(handler http.Handler) http.Handler {
	getIP := s.RateLimiter.GetClientIP

	// ลำดับสำคัญมาก! ดู comment ที่ต้นไฟล์
	h := handler
	h = SecurityHeadersMiddleware(h)               // 7. headers
	h = s.AttackDetectionMiddleware(h)              // 6. attack detect
	h = s.RateLimiter.Middleware(h)                 // 5. rate limit
	h = s.Blocklist.Middleware(getIP)(h)            // 4. block list
	h = s.LoadProtector.BodyLimitMiddleware(h)      // 3c. body size
	h = s.LoadProtector.PerIPLimitMiddleware(getIP)(h) // 3b. per-IP concurrent
	h = s.LoadProtector.ConcurrentLimitMiddleware(h) // 3a. total concurrent
	h = s.LoadProtector.TimeoutMiddleware(h)        // 3d. timeout (ต้องอยู่นอกสุดของ load)
	h = s.RequestLoggerMiddleware(h)                // 1. log first
	return h
}

// Close — เรียกตอน shutdown
func (s *SecurityStack) Close() error {
	return s.Logger.Close()
}
