// Package security: Rate Limiter Middleware
// ============================================
// ทำหน้าที่: จำกัดจำนวน request ต่อ IP ในช่วงเวลาหนึ่ง
// อัลกอริทึม: Token Bucket (เริ่มต้นเต็ม burst, เติม token ตาม rate)
//
// ตัวอย่างการใช้:
//   limiter := NewRateLimiter(RateLimitConfig{
//       RequestsPerSecond: 10,   // 10 req/s
//       Burst:             20,   // เก็บ burst สูงสุด 20
//       CleanupInterval:   5 * time.Minute,
//   })
//   http.Handle("/api/", limiter.Middleware(yourHandler))

package security

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================
// Config
// ============================================
type RateLimitConfig struct {
	RequestsPerSecond float64       // จำนวน request ต่อวินาที (rate)
	Burst             int           // burst size (ขีดสูงสุดที่อนุญาตให้ทะลักพร้อมกัน)
	CleanupInterval   time.Duration // ลบ IP ที่ไม่ active ออกจาก memory
	IPIdleTimeout     time.Duration // IP ไม่ใช้นานเท่านี้ → ลบทิ้ง
	TrustedProxies    []string      // CIDR ของ reverse proxy ที่เชื่อ X-Forwarded-For
}

// ค่า default
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             20,
		CleanupInterval:   5 * time.Minute,
		IPIdleTimeout:     10 * time.Minute,
		TrustedProxies:    []string{"127.0.0.1/32", "::1/128"},
	}
}

// ============================================
// Token Bucket — เก็บสถานะของแต่ละ IP
// ============================================
type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func (b *tokenBucket) allow(rate float64, burst int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()

	// เติม token ตาม rate * เวลาที่ผ่านไป
	b.tokens += elapsed * rate
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastRefill = now

	// มี token ≥ 1 → ผ่าน
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ============================================
// Rate Limiter
// ============================================
type RateLimiter struct {
	config    RateLimitConfig
	buckets   map[string]*bucketEntry
	mu        sync.RWMutex
	trustedCIDRs []*net.IPNet
}

type bucketEntry struct {
	bucket   *tokenBucket
	lastSeen time.Time
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:  cfg,
		buckets: make(map[string]*bucketEntry),
	}

	// Parse trusted proxy CIDR ล่วงหน้า
	for _, cidr := range cfg.TrustedProxies {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			rl.trustedCIDRs = append(rl.trustedCIDRs, ipnet)
		}
	}

	// Goroutine ทำความสะอาด IP เก่า
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) getBucket(ip string) *tokenBucket {
	rl.mu.RLock()
	entry, exists := rl.buckets[ip]
	rl.mu.RUnlock()

	if exists {
		entry.lastSeen = time.Now()
		return entry.bucket
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	// double-check after lock
	if entry, exists := rl.buckets[ip]; exists {
		entry.lastSeen = time.Now()
		return entry.bucket
	}

	b := &tokenBucket{
		tokens:     float64(rl.config.Burst),
		lastRefill: time.Now(),
	}
	rl.buckets[ip] = &bucketEntry{bucket: b, lastSeen: time.Now()}
	return b
}

// ลบ IP เก่าออก (กัน memory leak ถ้ามีคน scan ด้วย IP random)
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-rl.config.IPIdleTimeout)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, entry := range rl.buckets {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

// ============================================
// Middleware
// ============================================
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.getClientIP(r)
		bucket := rl.getBucket(ip)

		if !bucket.allow(rl.config.RequestsPerSecond, rl.config.Burst) {
			retryAfter := strconv.FormatFloat(1.0/rl.config.RequestsPerSecond, 'f', 2, 64)
			w.Header().Set("Retry-After", retryAfter)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.Burst))
			w.Header().Set("X-RateLimit-Remaining", "0")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================
// ดึง real IP — ระวัง X-Forwarded-For spoof
// ============================================
// เชื่อ X-Forwarded-For เฉพาะเมื่อ RemoteAddr เป็น trusted proxy
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	// ถ้า remote เป็น trusted proxy → ใช้ XFF
	if rl.isTrustedProxy(remoteIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// XFF อาจมีหลาย IP — เอาตัวซ้ายสุด (client จริง)
			parts := strings.Split(xff, ",")
			clientIP := strings.TrimSpace(parts[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	return remoteIP
}

func (rl *RateLimiter) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range rl.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Helper: เปิดเป็น public method ให้ middleware อื่นใช้
func (rl *RateLimiter) GetClientIP(r *http.Request) string {
	return rl.getClientIP(r)
}
