// Package security: Structured Security Logger
// ============================================
// ทำหน้าที่: log security event แบบ structured (JSON) ลง file + stdout
//   - ใช้ log/slog ของ Go stdlib (1.21+)
//   - แยก log level: Info, Warn, Critical
//   - Rotate file ตามขนาด (basic)
//   - ⚠️ ห้าม log: password, token, full cookie, credit card

package security

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// ============================================
// Logger
// ============================================
type SecurityLogger struct {
	logger  *slog.Logger
	file    *os.File
	mu      sync.Mutex
	logPath string
}

// NewSecurityLogger สร้าง logger ที่เขียนทั้ง stdout + file (JSON)
// ถ้า logPath == "" → เขียน stdout อย่างเดียว
func NewSecurityLogger(logPath string) (*SecurityLogger, error) {
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	sl := &SecurityLogger{logPath: logPath}

	if logPath != "" {
		// สร้าง directory ถ้ายังไม่มี
		dir := filepath.Dir(logPath)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		sl.file = f
		writers = append(writers, f)
	}

	multi := io.MultiWriter(writers...)
	handler := slog.NewJSONHandler(multi, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	sl.logger = slog.New(handler)
	return sl, nil
}

func (sl *SecurityLogger) Close() error {
	if sl.file != nil {
		return sl.file.Close()
	}
	return nil
}

// ============================================
// Log methods
// ============================================
func (sl *SecurityLogger) Info(msg string, args ...any) {
	sl.logger.Info(msg, args...)
}

func (sl *SecurityLogger) Warn(msg string, args ...any) {
	sl.logger.Warn(msg, args...)
}

func (sl *SecurityLogger) Error(msg string, args ...any) {
	sl.logger.Error(msg, args...)
}

// Critical = severity สูงสุด — security event ที่ต้อง alert
func (sl *SecurityLogger) Critical(msg string, args ...any) {
	args = append(args, "severity", "critical")
	sl.logger.Error(msg, args...)
}

// ============================================
// Sanitize value ก่อน log
// ============================================
// ⚠️ ถ้าจะ log header / form value — ใช้ฟังก์ชันนี้กรอง sensitive ออก
var sensitiveKeys = map[string]bool{
	"password":      true,
	"passwd":        true,
	"pwd":           true,
	"secret":        true,
	"token":         true,
	"authorization": true,
	"cookie":        true,
	"set-cookie":    true,
	"x-api-key":     true,
	"api_key":       true,
	"apikey":        true,
	"credit_card":   true,
	"card_number":   true,
	"ssn":           true,
	"cvv":           true,
}

// SanitizeHeaders คืน map ที่ลบ header ที่ sensitive แล้ว
func SanitizeHeaders(headers map[string][]string) map[string]string {
	clean := make(map[string]string)
	for k, v := range headers {
		lower := toLower(k)
		if sensitiveKeys[lower] {
			clean[k] = "[REDACTED]"
		} else if len(v) > 0 {
			clean[k] = v[0]
		}
	}
	return clean
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
