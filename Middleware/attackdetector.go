// Package security: Attack Pattern Detector
// ============================================
// ทำหน้าที่: ตรวจจับ pattern ของ scanner / attack tools
//   - SQL Injection patterns
//   - sqlmap signatures
//   - Nikto signatures
//   - RustScan / nmap fingerprints
//   - Common scanner User-Agent
//   - Directory bruteforce patterns
//
// เจอ pattern → return ScanResult + reason
// จากนั้นให้ middleware เอา IP ไป block (ดู ipblocklist.go)

package security

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ============================================
// ผลการตรวจ
// ============================================
type ScanResult struct {
	Detected bool
	Category string // "sqli", "scanner", "path_traversal", "command_injection", "xss"
	Pattern  string // pattern ที่ match
	Severity string // "low", "medium", "high", "critical"
}

// ============================================
// SQL Injection Patterns
// ============================================
// pattern ที่พบใน payload sqlmap / manual injection
var sqlInjectionPatterns = []*regexp.Regexp{
	// Union-based
	regexp.MustCompile(`(?i)\bunion\b.{1,100}\bselect\b`),
	// Boolean-based
	regexp.MustCompile(`(?i)\b(or|and)\b\s+\d+\s*[=<>]\s*\d+`),
	regexp.MustCompile(`(?i)\b(or|and)\b\s+['"]\w*['"]\s*[=<>]\s*['"]\w*['"]`),
	// Time-based (sleep/benchmark/waitfor)
	regexp.MustCompile(`(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`),
	// Stacked queries
	regexp.MustCompile(`(?i);\s*(drop|delete|update|insert|create|alter|truncate)\s+`),
	// Comments commonly used to bypass
	regexp.MustCompile(`(?i)(--[\s\-]|#|/\*.*?\*/|--$)`),
	// Information schema probing
	regexp.MustCompile(`(?i)\b(information_schema|pg_catalog|sysobjects|sys\.tables)\b`),
	// Common SQLi functions
	regexp.MustCompile(`(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b`),
	// Hex/char encoding tricks
	regexp.MustCompile(`(?i)\b(char|chr|concat|chr_)\s*\(\s*\d+`),
	// PostgreSQL specific
	regexp.MustCompile(`(?i)\b(pg_user|pg_shadow|current_database|current_user)\s*\(`),
}

// ============================================
// XSS Patterns
// ============================================
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*script[^>]*>`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)on(error|load|click|mouseover|focus|blur)\s*=`),
	regexp.MustCompile(`(?i)<\s*iframe`),
	regexp.MustCompile(`(?i)<\s*object`),
	regexp.MustCompile(`(?i)<\s*embed`),
	regexp.MustCompile(`(?i)<\s*svg[^>]*on\w+\s*=`),
	regexp.MustCompile(`(?i)document\.(cookie|domain|location)`),
	regexp.MustCompile(`(?i)\beval\s*\(`),
}

// ============================================
// Path Traversal Patterns
// ============================================
var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`(?i)%2e%2e[/\\]`),
	regexp.MustCompile(`(?i)\.\.%2f`),
	regexp.MustCompile(`(?i)\.\.%5c`),
	regexp.MustCompile(`(?i)/etc/(passwd|shadow|hosts)`),
	regexp.MustCompile(`(?i)c:\\windows\\`),
	regexp.MustCompile(`(?i)/proc/self/`),
}

// ============================================
// Command Injection Patterns
// ============================================
var commandInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|` + "`" + `]\s*(cat|ls|wget|curl|nc|bash|sh|whoami|id|uname)\b`),
	regexp.MustCompile(`\$\(.+\)`),
	regexp.MustCompile("`.+`"),
	regexp.MustCompile(`(?i)\b(cmd\.exe|powershell)\b`),
}

// ============================================
// Scanner User-Agents (case-insensitive substring)
// ============================================
var scannerUserAgents = []string{
	"sqlmap",
	"nikto",
	"nessus",
	"nmap",
	"masscan",
	"rustscan",
	"acunetix",
	"burp",
	"burpsuite",
	"zaproxy",
	"zap/",
	"wpscan",
	"dirbuster",
	"dirb/",
	"gobuster",
	"ffuf",
	"feroxbuster",
	"hydra",
	"medusa",
	"nuclei",
	"wfuzz",
	"havij",
	"jaeles",
	"x8",
	"arjun",
	"paramspider",
	"katana",
	"httpx",  // ⚠️ ระวัง false positive ถ้ามีคนใช้ legit
	"sslscan",
	"testssl",
	"openvas",
	"metasploit",
	"netsparker",
	"appscan",
	"qualys",
	"webinspect",
	"skipfish",
	"wapiti",
	"w3af",
	"vega/",
	"arachni",
	"detectify",
	"whatweb",
}

// ============================================
// Nikto-specific paths (paths ที่ Nikto ชอบยิง)
// ============================================
var niktoSuspiciousPaths = []string{
	"/cgi-bin/",
	"/admin.php",
	"/phpmyadmin/",
	"/wp-admin/",
	"/wp-login.php",
	"/.env",
	"/.git/",
	"/.svn/",
	"/.htaccess",
	"/.htpasswd",
	"/server-status",
	"/server-info",
	"/web.config",
	"/manager/html",        // Tomcat
	"/console/",            // Weblogic
	"/struts2-rest-showcase/", // Struts
	"/owa/",
	"/exchange/",
	"/jmx-console/",
	"/invoker/",
	"/test.php",
	"/info.php",
	"/phpinfo.php",
	"/install.php",
	"/setup.php",
	"/config.php.bak",
	"/backup.sql",
	"/dump.sql",
	"/database.sql",
	"/.DS_Store",
	"/.idea/",
	"/.vscode/",
	"/composer.json",
	"/package.json.bak",
}

// ============================================
// Suspicious headers / RustScan fingerprints
// ============================================
// RustScan/nmap ส่ง raw TCP probe — request HTTP มักจะ malformed
// ตรวจจาก: missing User-Agent, missing Accept, ส่ง raw method
var validHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// ============================================
// Detector
// ============================================
type AttackDetector struct {
	// option: เพิ่มเติม custom pattern
	customPatterns []*regexp.Regexp
}

func NewAttackDetector() *AttackDetector {
	return &AttackDetector{}
}

// ตรวจ request ทั้งก้อน
func (d *AttackDetector) Detect(r *http.Request) ScanResult {
	// 1. User-Agent — scanner ส่วนใหญ่ไม่ปลอม UA
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if ua == "" {
		// บาง scanner ไม่ส่ง UA เลย → suspicious (แต่ไม่ block ทันที)
		return ScanResult{
			Detected: true, Category: "scanner",
			Pattern: "empty user-agent", Severity: "medium",
		}
	}
	for _, sig := range scannerUserAgents {
		if strings.Contains(ua, sig) {
			return ScanResult{
				Detected: true, Category: "scanner",
				Pattern: "UA:" + sig, Severity: "critical",
			}
		}
	}

	// 2. Method ต้องเป็น HTTP method มาตรฐาน
	if !validHTTPMethods[r.Method] {
		return ScanResult{
			Detected: true, Category: "scanner",
			Pattern: "invalid method: " + r.Method, Severity: "high",
		}
	}

	// 3. Path — เช็ค Nikto-style probing
	path := strings.ToLower(r.URL.Path)
	for _, sus := range niktoSuspiciousPaths {
		if strings.HasPrefix(path, sus) {
			return ScanResult{
				Detected: true, Category: "scanner",
				Pattern: "nikto-path:" + sus, Severity: "high",
			}
		}
	}

	// 4. Path traversal ใน path
	for _, p := range pathTraversalPatterns {
		if p.MatchString(r.URL.Path) {
			return ScanResult{
				Detected: true, Category: "path_traversal",
				Pattern: p.String(), Severity: "critical",
			}
		}
	}

	// 5. Query string — SQLi, XSS, command injection
	// URL-decode ก่อน scan (กัน attacker ใช้ encoding bypass)
	queryStr := r.URL.RawQuery
	if decoded, err := url.QueryUnescape(queryStr); err == nil {
		queryStr = decoded
	}
	if result := d.scanString(queryStr); result.Detected {
		return result
	}
	// scan query values แยกแต่ละ field ด้วย
	for _, values := range r.URL.Query() {
		for _, v := range values {
			if result := d.scanString(v); result.Detected {
				return result
			}
		}
	}

	// 6. POST body (form values) — ระวังเรื่อง body size, อ่านแค่ที่ parse แล้ว
	// ⚠️ ไม่ดึงดู raw body ที่นี่ — handler ตัวจริงจะอ่านอีกที
	// ถ้าอยากตรวจ body ต้องอ่าน → save buffer → ใส่กลับ
	if err := r.ParseForm(); err == nil {
		for _, values := range r.PostForm {
			for _, v := range values {
				if result := d.scanString(v); result.Detected {
					return result
				}
			}
		}
	}

	// 7. Headers ที่น่าสงสัย
	for name, values := range r.Header {
		for _, v := range values {
			// บางครั้ง attacker ฝัง payload ใน custom header
			if result := d.scanString(v); result.Detected {
				result.Pattern = "header[" + name + "]:" + result.Pattern
				return result
			}
		}
	}

	return ScanResult{Detected: false}
}

// scanString — ตรวจ string เดี่ยวๆ ว่ามี attack pattern ไหม
func (d *AttackDetector) scanString(s string) ScanResult {
	if s == "" {
		return ScanResult{Detected: false}
	}

	// SQL Injection
	for _, p := range sqlInjectionPatterns {
		if p.MatchString(s) {
			return ScanResult{
				Detected: true, Category: "sqli",
				Pattern: p.String(), Severity: "critical",
			}
		}
	}

	// XSS
	for _, p := range xssPatterns {
		if p.MatchString(s) {
			return ScanResult{
				Detected: true, Category: "xss",
				Pattern: p.String(), Severity: "high",
			}
		}
	}

	// Path traversal in params
	for _, p := range pathTraversalPatterns {
		if p.MatchString(s) {
			return ScanResult{
				Detected: true, Category: "path_traversal",
				Pattern: p.String(), Severity: "critical",
			}
		}
	}

	// Command injection
	for _, p := range commandInjectionPatterns {
		if p.MatchString(s) {
			return ScanResult{
				Detected: true, Category: "command_injection",
				Pattern: p.String(), Severity: "critical",
			}
		}
	}

	// Custom patterns
	for _, p := range d.customPatterns {
		if p.MatchString(s) {
			return ScanResult{
				Detected: true, Category: "custom",
				Pattern: p.String(), Severity: "high",
			}
		}
	}

	return ScanResult{Detected: false}
}

// เพิ่ม custom pattern (เช่น app-specific)
func (d *AttackDetector) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	d.customPatterns = append(d.customPatterns, re)
	return nil
}
