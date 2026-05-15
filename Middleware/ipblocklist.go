// Package security: IP Blocklist
// ============================================
// ทำหน้าที่: เก็บ list ของ IP ที่ถูก block
//   - In-memory map (fast lookup)
//   - Persist ลง file (JSON) เมื่อ ban — กัน restart แล้วลืม
//   - มี TTL (ban ชั่วคราว) หรือ permanent
//   - Strike system: เจอ pattern ครั้งแรก → warn, ครั้งที่ N → ban
//
// ใช้คู่กับ attackdetector.go:
//   ถ้า Detector เจอ pattern → blocklist.Ban(ip, reason, duration)

package security

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// ============================================
// Banned entry
// ============================================
type BannedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
	HitCount  int       `json:"hit_count"`  // จำนวนครั้งที่ตรวจเจอ pattern
}

// IP ที่ "เพ่งเล็ง" (ยังไม่ ban — รอ strike ครบ)
type strikeEntry struct {
	count    int
	firstHit time.Time
	lastHit  time.Time
}

// ============================================
// Config
// ============================================
type BlocklistConfig struct {
	PersistFile      string        // path file สำหรับ persist (เช่น "/var/app/banned.json")
	DefaultBanTime   time.Duration // ban นานเท่าไหร่โดย default (เช่น 24h)
	StrikeThreshold  int           // เจอ pattern กี่ครั้งถึง ban (1 = ban ทันที)
	StrikeWindow     time.Duration // นับ strike ภายในช่วงเวลานี้
	CleanupInterval  time.Duration // ทำความสะอาด expired ban
	Whitelist        []string      // IP ที่จะไม่โดน ban เด็ดขาด (เช่น admin)
}

func DefaultBlocklistConfig() BlocklistConfig {
	return BlocklistConfig{
		PersistFile:     "./banned_ips.json",
		DefaultBanTime:  24 * time.Hour,
		StrikeThreshold: 1, // ban ทันทีถ้าเจอ critical pattern
		StrikeWindow:    10 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		Whitelist:       []string{"127.0.0.1", "::1"},
	}
}

// ============================================
// Blocklist
// ============================================
type Blocklist struct {
	config    BlocklistConfig
	banned    map[string]*BannedIP
	strikes   map[string]*strikeEntry
	whitelist map[string]bool
	mu        sync.RWMutex
	logger    *SecurityLogger // optional — ดู logger.go
}

func NewBlocklist(cfg BlocklistConfig, logger *SecurityLogger) *Blocklist {
	bl := &Blocklist{
		config:    cfg,
		banned:    make(map[string]*BannedIP),
		strikes:   make(map[string]*strikeEntry),
		whitelist: make(map[string]bool),
		logger:    logger,
	}
	for _, ip := range cfg.Whitelist {
		bl.whitelist[ip] = true
	}

	// โหลด ban list เก่าจาก disk
	bl.loadFromFile()

	go bl.cleanupLoop()
	return bl
}

// ============================================
// ตรวจสอบว่า IP ถูก ban ไหม
// ============================================
func (b *Blocklist) IsBanned(ip string) (bool, *BannedIP) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	entry, exists := b.banned[ip]
	if !exists {
		return false, nil
	}

	// ตรวจ expiry
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return false, nil // expired — จะถูก cleanup ภายหลัง
	}

	return true, entry
}

// ============================================
// Ban IP
// ============================================
func (b *Blocklist) Ban(ip, reason string, duration time.Duration) {
	if b.whitelist[ip] {
		if b.logger != nil {
			b.logger.Warn("attempted to ban whitelisted IP",
				"ip", ip, "reason", reason)
		}
		return
	}

	b.mu.Lock()
	now := time.Now()
	expiresAt := time.Time{}
	if duration > 0 {
		expiresAt = now.Add(duration)
	}

	entry, exists := b.banned[ip]
	if exists {
		// ถ้า ban อยู่แล้ว → เพิ่ม hit count + extend
		entry.HitCount++
		if !entry.ExpiresAt.IsZero() && !expiresAt.IsZero() && expiresAt.After(entry.ExpiresAt) {
			entry.ExpiresAt = expiresAt
		}
	} else {
		b.banned[ip] = &BannedIP{
			IP:        ip,
			Reason:    reason,
			BannedAt:  now,
			ExpiresAt: expiresAt,
			HitCount:  1,
		}
	}
	b.mu.Unlock()

	if b.logger != nil {
		b.logger.Critical("IP banned",
			"ip", ip,
			"reason", reason,
			"duration", duration.String(),
		)
	}

	// Persist ทันที (sync บน disk)
	b.saveToFile()
}

// ============================================
// บันทึก strike — ถ้าครบ threshold ค่อย ban
// ============================================
func (b *Blocklist) RecordStrike(ip, reason string, severity string) bool {
	if b.whitelist[ip] {
		return false
	}

	// "critical" severity → ban ทันที (ไม่ต้องนับ strike)
	if severity == "critical" {
		b.Ban(ip, reason, b.config.DefaultBanTime)
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	entry, exists := b.strikes[ip]

	if !exists || now.Sub(entry.firstHit) > b.config.StrikeWindow {
		// strike แรก หรือเลย window แล้ว
		b.strikes[ip] = &strikeEntry{
			count:    1,
			firstHit: now,
			lastHit:  now,
		}
		return false
	}

	entry.count++
	entry.lastHit = now

	if entry.count >= b.config.StrikeThreshold {
		// ครบ threshold — unlock ก่อน เพราะ Ban จะ lock อีกที
		b.mu.Unlock()
		b.Ban(ip, reason, b.config.DefaultBanTime)
		b.mu.Lock()
		delete(b.strikes, ip)
		return true
	}

	return false
}

// ============================================
// Unban
// ============================================
func (b *Blocklist) Unban(ip string) {
	b.mu.Lock()
	delete(b.banned, ip)
	b.mu.Unlock()
	b.saveToFile()

	if b.logger != nil {
		b.logger.Info("IP unbanned", "ip", ip)
	}
}

// ============================================
// List all
// ============================================
func (b *Blocklist) List() []BannedIP {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]BannedIP, 0, len(b.banned))
	for _, v := range b.banned {
		result = append(result, *v)
	}
	return result
}

// ============================================
// Middleware — block request ของ IP ที่ ban
// ============================================
// ต้องใช้ getClientIP จาก RateLimiter (ส่งเข้ามาตอน chain)
type IPExtractor func(r *http.Request) string

func (b *Blocklist) Middleware(getIP IPExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)
			if banned, entry := b.IsBanned(ip); banned {
				if b.logger != nil {
					b.logger.Info("blocked request from banned IP",
						"ip", ip,
						"reason", entry.Reason,
						"path", r.URL.Path,
					)
				}
				// ⚠️ ส่ง 403 generic — อย่าบอกเหตุผล
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================
// Persistence
// ============================================
func (b *Blocklist) saveToFile() {
	if b.config.PersistFile == "" {
		return
	}

	b.mu.RLock()
	data, err := json.MarshalIndent(b.banned, "", "  ")
	b.mu.RUnlock()
	if err != nil {
		return
	}

	// เขียนแบบ atomic — เขียน .tmp แล้ว rename
	tmpFile := b.config.PersistFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return
	}
	os.Rename(tmpFile, b.config.PersistFile)
}

func (b *Blocklist) loadFromFile() {
	if b.config.PersistFile == "" {
		return
	}
	data, err := os.ReadFile(b.config.PersistFile)
	if err != nil {
		return
	}
	var loaded map[string]*BannedIP
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for ip, entry := range loaded {
		// skip expired
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		b.banned[ip] = entry
	}
}

// ============================================
// Cleanup
// ============================================
func (b *Blocklist) cleanupLoop() {
	ticker := time.NewTicker(b.config.CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		b.cleanup()
	}
}

func (b *Blocklist) cleanup() {
	now := time.Now()
	changed := false

	b.mu.Lock()
	// ลบ expired ban
	for ip, entry := range b.banned {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(b.banned, ip)
			changed = true
		}
	}
	// ลบ strike เก่า
	for ip, entry := range b.strikes {
		if now.Sub(entry.lastHit) > b.config.StrikeWindow {
			delete(b.strikes, ip)
		}
	}
	b.mu.Unlock()

	if changed {
		b.saveToFile()
	}
}
