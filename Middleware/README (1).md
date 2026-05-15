# 🛡️ Go Security Middleware

Security middleware stack สำหรับ Go net/http — รวม:
- ✅ **Rate Limiting** (Token Bucket per-IP)
- ✅ **Attack Pattern Detection** (SQLi, XSS, sqlmap, nikto, nmap, rustscan)
- ✅ **IP Blocklist** (auto-ban + persist to file + TTL)
- ✅ **Load Protection** (concurrent limit, body size, timeout, slowloris)
- ✅ **Structured Logging** (JSON + sensitive data redaction)
- ✅ **Security Headers** (CSP, HSTS, X-Frame-Options, ฯลฯ)

---

## 📁 โครงสร้างไฟล์

```
security/
├── ratelimit.go        # Token bucket rate limiter
├── attackdetector.go   # Detect SQLi/XSS/scanner patterns
├── ipblocklist.go      # IP ban list + persistence
├── loadprotector.go    # Concurrent/body/timeout limits
├── logger.go           # Structured JSON logger
├── middleware.go       # ประกอบ chain ทั้งหมด
└── README.md
```

ตัวอย่างการใช้: `main.go.example`

---

## 🚀 ติดตั้ง

1. Copy ทั้งโฟลเดอร์ไปไว้ใน `your-project/security/`
2. แก้ import path ใน `main.go` ตาม module ของคุณ
3. ติดตั้ง dependency (ใช้ stdlib ทั้งหมด):

```bash
go mod init yourapp
go mod tidy
```

4. คอมไพล์:

```bash
go build -o server .
./server
```

> ⚠️ ต้องการ Go 1.21+ เพราะใช้ `log/slog`

---

## 🧪 ทดสอบ

```bash
# ปกติ
curl http://localhost:8080/
# → "Hello, secure world!"

# SQL injection → ban
curl "http://localhost:8080/?id=1' OR 1=1--"
# → 403 Forbidden (และ IP จะอยู่ใน banned_ips.json)

# sqlmap UA → ban ทันที
curl -A "sqlmap/1.7.2" http://localhost:8080/
# → 403 Forbidden

# Nikto-style path → ban
curl http://localhost:8080/.env
# → 403 Forbidden

# Rate limit
for i in {1..30}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/; done
# → 200 200 ... 429 429 ...
```

---

## ⚙️ Config Reference

### RateLimit

| Field | Default | คำอธิบาย |
|---|---|---|
| `RequestsPerSecond` | 10 | จำนวน req/วินาที ต่อ IP |
| `Burst` | 20 | burst สูงสุด |
| `CleanupInterval` | 5m | ลบ IP ที่ไม่ active |
| `TrustedProxies` | localhost | CIDR ของ reverse proxy |

### Blocklist

| Field | Default | คำอธิบาย |
|---|---|---|
| `PersistFile` | `./banned_ips.json` | ไฟล์เก็บ ban list |
| `DefaultBanTime` | 24h | ban นานเท่าไหร่ |
| `StrikeThreshold` | 1 | จำนวนครั้งที่เจอ pattern ก่อน ban |
| `StrikeWindow` | 10m | window สำหรับนับ strike |
| `Whitelist` | localhost | IP ที่ไม่โดน ban |

### LoadProtect

| Field | Default | คำอธิบาย |
|---|---|---|
| `MaxConcurrentRequests` | 1000 | request พร้อมกันทั้ง server |
| `MaxConcurrentPerIP` | 20 | request พร้อมกันต่อ IP |
| `MaxRequestBodyBytes` | 1 MB | ขนาด body สูงสุด |
| `RequestTimeout` | 30s | timeout ทั้ง request |

---

## 🎯 Patterns ที่ detect ได้

### SQL Injection
- UNION-based: `UNION SELECT`
- Boolean: `OR 1=1`, `AND 'a'='a'`
- Time-based: `SLEEP()`, `BENCHMARK()`, `pg_sleep()`, `WAITFOR DELAY`
- Stacked: `; DROP TABLE`
- Information schema probing
- `LOAD_FILE`, `INTO OUTFILE`
- Comment markers: `--`, `#`, `/* */`

### Scanner User-Agents
sqlmap, nikto, nessus, nmap, masscan, **rustscan**, acunetix, burp, zaproxy, wpscan, dirbuster, gobuster, ffuf, feroxbuster, nuclei, hydra, medusa, wfuzz, havij, w3af, wapiti, openvas, metasploit, netsparker, qualys, และอื่นๆ

### Nikto-style paths
`/cgi-bin/`, `/.env`, `/.git/`, `/wp-admin/`, `/phpmyadmin/`, `/server-status`, `/console/`, `/jmx-console/`, ฯลฯ

### XSS
- `<script>`, `javascript:`, `onerror=`, `onload=`
- `<iframe>`, `<svg onload=>`, `eval()`

### Path Traversal
- `../`, `..\`, URL-encoded variants
- `/etc/passwd`, `/proc/self/`, `C:\Windows\`

### Command Injection
- `; cat`, `| ls`, `` `cmd` ``, `$(cmd)`

---

## 🔧 ใช้งาน Custom

### เพิ่ม custom pattern

```go
stack.Detector.AddPattern(`(?i)secret_string_to_block`)
```

### Ban IP ด้วยมือ

```go
stack.Blocklist.Ban("1.2.3.4", "manual ban", 24*time.Hour)
```

### Unban

```go
stack.Blocklist.Unban("1.2.3.4")
```

### Whitelist เพิ่ม

```go
cfg.Blocklist.Whitelist = []string{"127.0.0.1", "::1", "10.0.0.5"}
```

---

## 📊 ดู log

```bash
# Tail real-time
tail -f ./logs/security.log | jq

# ดูแต่ attack
tail -f ./logs/security.log | jq 'select(.severity=="critical")'

# นับ attack per IP
cat ./logs/security.log | jq -r '.ip' | sort | uniq -c | sort -rn
```

---

## ⚠️ ข้อควรระวัง

1. **X-Forwarded-For spoofing** — middleware จะเชื่อ XFF เฉพาะเมื่อ request มาจาก trusted proxy CIDR เท่านั้น ตั้ง `TrustedProxies` ให้ตรงกับ reverse proxy (nginx/Cloudflare) ของคุณ

2. **In-memory state** — banned IP, rate limit counter เก็บใน RAM ถ้า server restart จะหาย (ยกเว้น banned list ที่ persist) ถ้ามี multi-instance ต้องใช้ Redis แทน

3. **False positive** — บาง pattern อาจ match user input ปกติ ตรวจ log ก่อน production ถ้ามี false positive เยอะ ลด `StrikeThreshold` เป็น 2-3

4. **Body scan** — middleware อ่าน POST form แล้ว scan ถ้า body เป็น JSON ต้อง custom เพิ่ม (ดู attackdetector.go)

5. **TLS** — middleware นี้ไม่ทำ TLS — ใช้ nginx/caddy เป็น reverse proxy + TLS termination

6. **Admin endpoint** — `/admin/banned` ใน example ไม่มี auth — ใส่ JWT/session check ก่อน deploy

---

## 🔐 ลำดับ Middleware ใน Chain

```
Request
  ↓
[1] Request Logger      ← log ทุก request
  ↓
[2] Timeout             ← TimeoutHandler
  ↓
[3a] Concurrent Total   ← จำกัด total
  ↓
[3b] Per-IP Concurrent  ← จำกัดต่อ IP
  ↓
[3c] Body Size Limit    ← MaxBytesReader
  ↓
[4] IP Blocklist        ← block IP ที่ ban แล้ว (เร็วสุด)
  ↓
[5] Rate Limiter        ← token bucket
  ↓
[6] Attack Detector     ← scan pattern → strike → ban
  ↓
[7] Security Headers    ← เพิ่ม response header
  ↓
Your Handler
```

ทำไมต้องเรียงแบบนี้:
- **Blocklist อยู่ก่อน Rate Limit** — IP ที่ ban แล้วไม่ต้องเปลือง bucket
- **Body limit อยู่นอก Detector** — กัน body ใหญ่เกินก่อน parse
- **Timeout อยู่นอกสุด** — ครอบ handler ที่อาจ block

---

## 📚 References

- [OWASP Automated Threat Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [CRS (ModSecurity Core Rule Set)](https://coreruleset.org/)
- [Go net/http best practices](https://blog.cloudflare.com/exposing-go-on-the-internet/)
