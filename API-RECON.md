# API Reconnaissance — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — Reconnaissance & Attack Surface Mapping
>
> **Context:** API reconnaissance is the phase that determines how thorough the rest of the API security assessment will be. The API surface in a modern enterprise application is rarely what the documentation says it is — there are deprecated endpoints that still respond, internal APIs exposed through misconfigured gateways, mobile API backends with different rate limiting, and undocumented admin endpoints that only appear in the JavaScript bundle. This document covers how I systematically map the complete API attack surface before testing a single vulnerability.

---

## 🧠 Enterprise API Recon Is Different From Standard Recon

```
Standard web app recon asks: "What pages exist?"
API recon asks:
  → "What API versions are deployed?" (old ones often weaker)
  → "Are there separate mobile API endpoints?" (often less hardened)
  → "Are internal APIs exposed through the public gateway?" (common misconfiguration)
  → "What microservices are accessible from this context?" (internal assessment)
  → "What does the JavaScript bundle reveal about undocumented endpoints?" (reliable source)
  → "Is there API documentation that lists more than the UI uses?" (free schema)

The gap between documented API and actual API is where findings live.
Developers build the documented API for the frontend.
They build other APIs for internal tools, mobile apps, reporting, admin.
Those other APIs are what I look for in recon.
```

---

## 🔍 Phase 1 — Documentation Discovery

### Finding Swagger / OpenAPI Specifications

```bash
# Systematic check for all common API documentation paths
API_DOC_PATHS=(
  "swagger.json"
  "swagger.yaml"
  "swagger-ui.html"
  "swagger-ui/index.html"
  "swagger/index.html"
  "swagger/v1/swagger.json"
  "swagger/v2/swagger.json"
  "v1/swagger.json"
  "v2/swagger.json"
  "v3/swagger.json"
  "api-docs"
  "api-docs/v1"
  "api-docs/v2"
  "api/swagger.json"
  "api/openapi.json"
  "api/openapi.yaml"
  "openapi.json"
  "openapi.yaml"
  "openapi/v3/api-docs"
  "v1/api-docs"
  "v2/api-docs"
  "v3/api-docs"
  "docs"
  "api/docs"
  "documentation"
  ".well-known/openid-configuration"
)

TARGET="https://api.company.com"
for path in "${API_DOC_PATHS[@]}"; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null)
  [[ "$code" == "200" ]] && echo "FOUND: $TARGET/$path"
done

# If Swagger/OpenAPI found — download it:
curl -s https://api.company.com/v2/api-docs | jq . > swagger_spec.json

# Extract all endpoints from OpenAPI spec:
cat swagger_spec.json | jq -r '.paths | keys[]' | sort
# Lists every documented endpoint — your testing matrix

# Import to Postman:
# Postman → Import → OpenAPI file → Collection created with all endpoints
```

### GraphQL Schema Discovery

```bash
# Check for GraphQL endpoint:
for path in graphql graphql/v1 api/graphql gql graph; do
  curl -s -X POST "https://app.company.com/$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' 2>/dev/null | \
    grep -q "Query" && echo "GraphQL at /$path"
done

# If found — run introspection:
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ __schema { types { name } } }"}' | \
  jq '.data.__schema.types[].name' | grep -v "__"
```

---

## 🔍 Phase 2 — API Version Enumeration

Old API versions are consistently the most vulnerable. Teams secure the current version and forget about the previous one.

```bash
# Version enumeration — test every common pattern
echo "=== Testing API versions ==="
for v in v1 v2 v3 v4 v5 beta alpha dev internal latest next \
          api/v1 api/v2 api/v3 1.0 2.0 3.0; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/$v/users" \
    -H "Authorization: Bearer TOKEN" 2>/dev/null)
  echo "$v: HTTP $code"
done

# Interpretation:
# v1: 200 → Old version still active → TEST IT (likely less hardened)
# v2: 200 → Current version
# v3: 404 → Not deployed
# v4: 403 → Exists but restricted → try access bypass
# beta: 200 → Beta endpoint → test for pre-production security gaps

# If both v1 and v2 exist — compare security:
# Test IDOR on v1: GET /api/v1/users/1042 → should 403 (your ID is 1099)
# Test IDOR on v2: GET /api/v2/users/1042 → may properly enforce auth
# If v1 returns data and v2 does not = v1 missing auth checks

# Using ffuf for systematic version discovery:
ffuf -u https://api.company.com/FUZZ/users \
  -w versions_wordlist.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,401,403 \
  -fs [404_size]
```

---

## 🔍 Phase 3 — JavaScript Bundle Analysis

The most reliable source of undocumented API endpoints in modern enterprise SPAs.

```bash
# Step 1: Find all JavaScript bundle files
curl -s https://app.company.com/ | grep -oP 'src="[^"]+\.js"' | \
  sed 's/src="//g' | sed 's/"//g'

# Step 2: Download and analyse the main bundle
curl -s "https://app.company.com/static/js/main.abc123.js" -o main.js

# Step 3: Extract API endpoint patterns
grep -oE '["'"'"'](/api/[^"'"'"']+)["'"'"']' main.js | sort -u

# Step 4: Extract more patterns
cat main.js | grep -oP '(fetch|axios\.(get|post|put|delete|patch))\(['"'"'"]([^'"'"'"]+)['"'"'"]' | \
  grep -oP '/[a-z0-9/_-]+' | sort -u

# Common patterns in enterprise React/Angular apps:
# "/api/v1/users"
# "/api/v2/admin/config"
# "/api/internal/metrics"
# "/api/reports/export"
# "/api/v1/webhooks"

# Step 5: Check for source maps (full source code exposure)
curl -sI "https://app.company.com/static/js/main.abc123.js.map" | \
  grep "HTTP/"
# HTTP/1.1 200 = source map exposed = full original source code accessible
# Download: curl -s https://app.company.com/static/js/main.abc123.js.map > sourcemap.json

# Step 6: Extract API endpoints from source map
cat sourcemap.json | jq '.sourcesContent[]' | \
  grep -oE '"(/api/[^"]+)"' | sort -u

# Step 7: Hardcoded secrets in JS bundles
grep -iE "(api_key|apiKey|secret|password|token|bearer|AKIA)" main.js | \
  grep -v "example\|test\|sample\|placeholder"
```

---

## 🔍 Phase 4 — Mobile API Endpoint Discovery

Enterprise mobile applications frequently use separate API endpoints with different (weaker) security controls.

```bash
# Method 1: Proxy mobile app traffic through Burp
# Android: configure HTTP proxy in WiFi settings → point to Burp
# iOS: configure HTTP proxy in WiFi settings → point to Burp
# Then use the mobile app for all features while Burp captures traffic

# What to look for:
# → Different base URL: api-mobile.company.com vs api.company.com
# → Different auth header: X-Mobile-Auth vs Authorization: Bearer
# → Different endpoints: /mobile/v2/ vs /api/v2/
# → Missing rate limiting on mobile endpoints
# → Less validation on mobile request parameters

# Method 2: Decompile Android APK
# Install: jadx (Java decompiler for APK)
jadx -d output_dir app.apk
grep -r "api\|https\|baseUrl\|endpoint" output_dir/sources/ | \
  grep -iE "(company\.com|api\.|/v[0-9]/)" | sort -u

# Method 3: Extract iOS app strings
# From IPA: unzip app.ipa → extract binary → strings binary
strings Payload/App.app/App | grep -iE "(https://|/api/|/v[0-9]/)"

# Common findings from mobile API recon:
# → Mobile endpoint has no WAF (direct API access)
# → Rate limiting absent on mobile OTP verification
# → Debug endpoints accessible: /api/debug/, /api/test/
# → API version mismatch: mobile uses v1 while web uses v2
```

---

## 🔍 Phase 5 — Postman Collection Discovery

Enterprise teams frequently publish Postman collections publicly or leave them in public GitHub repositories.

```bash
# Search GitHub for Postman collections:
# github.com/search?q=company.com+postman&type=code
# github.com/search?q=api.company.com+collection&type=code

# Search for exported Postman environment files:
# These contain base URLs, auth tokens, API keys

# Google dorking for exposed Postman collections:
# site:github.com "company.com" "postman_collection"
# site:github.com "api.company.com" filename:*.json

# What leaked Postman collections contain:
# → All API endpoints including undocumented ones
# → Authentication headers and tokens (sometimes live production tokens)
# → Example request bodies with field names
# → Environment variables (may include API keys, passwords)

# If a Postman collection is found:
# Import to Postman → Collection Runner → run all requests with own auth token
# Compare expected vs actual responses
```

---

## 🔍 Phase 6 — API Gateway Analysis

Enterprise APIs often sit behind API gateways (AWS API Gateway, Kong, Apigee). Gateway misconfigurations expose internal APIs.

```bash
# Identify API gateway from response headers:
curl -sI https://api.company.com/v1/users | grep -iE \
  "x-amzn-requestid|x-kong-|apigee-|x-ratelimit|x-powered-by"

# AWS API Gateway indicators:
# x-amzn-requestid: abc-123
# x-amz-apigw-id: xyz

# Test for gateway path bypass:
# Gateway may enforce auth on /api/v1/* but miss /api/v1//  (double slash)
curl -s "https://api.company.com//api/v1/users" \
  -H "Accept: application/json"

# Test for direct backend access (bypass gateway entirely):
# If backend IP is discoverable (Shodan, nmap, error messages):
curl -s "http://10.0.14.55:8080/api/v1/users" \
  -H "Host: api.company.com"
# Direct backend access bypasses gateway auth, rate limiting, WAF

# Test stage variables (AWS API Gateway):
# /prod/, /staging/, /dev/, /test/ as path prefixes
for stage in prod staging dev test v1 v2; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://abc123.execute-api.eu-west-1.amazonaws.com/$stage/users" 2>/dev/null)
  echo "$stage: $code"
done
```

---

## 🔍 Phase 7 — Wayback Machine API History

```bash
# Historical API endpoints often remain active but are no longer documented
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.company.com/api/*&output=json&fl=original&collapse=urlkey&limit=2000" | \
  jq -r '.[][0]' | \
  sort -u | \
  grep -iE "/api/|/v[0-9]/" > wayback_api_endpoints.txt

# What historical endpoints reveal:
# → /api/v1/ that was "retired" but still responds
# → /api/admin/ from before it was restricted
# → /api/internal/ that should never have been public
# → /api/debug/ from development that was never removed

# Probe which historical endpoints still respond:
cat wayback_api_endpoints.txt | \
  while read url; do
    code=$(curl -so /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    [[ "$code" =~ ^(200|401|403)$ ]] && echo "$code $url"
  done
```

---

## 🗂️ API Recon Output — Building the Testing Matrix

```
After completing all recon phases, organise findings into a priority matrix:

Priority 1 — Immediate (test in first hour):
  Swagger/OpenAPI spec found → import to Postman, all endpoints documented
  GraphQL introspection accessible → full schema available
  Old API version (v1 alongside v2) → test v1 for missing auth checks
  Hardcoded credentials in JS bundle → test immediately

Priority 2 — High (test second):
  Undocumented endpoints from JS analysis → test for missing auth
  Mobile API endpoints → test rate limiting and auth separately
  Historical endpoints from Wayback → test for still-active deprecated paths
  Source map exposed → review source code for hidden endpoints and logic

Priority 3 — Standard coverage:
  All endpoints from API spec → systematic BOLA + auth testing
  API versions → compare security posture of each
  JWT/auth mechanisms → full auth attack suite

Testing matrix format:
  Endpoint                    | Method | Auth | ID Params | Priority
  /api/v1/users/{id}          | GET    | Yes  | user_id   | High (BOLA)
  /api/v1/admin/users         | GET    | ?    | -         | Critical (auth check)
  /api/v2/webhooks            | POST   | Yes  | url param | High (SSRF)
  /api/internal/metrics       | GET    | ?    | -         | High (unauth?)
  /graphql (with introspect)  | POST   | No   | -         | Critical (schema exposed)
```

---

## 📋 Enterprise Report — API Recon Findings

```
Finding Title: Undocumented Internal API Endpoints Accessible via JavaScript Bundle Analysis

Severity: High

Discovery method:
  JavaScript source map exposed at:
  https://app.company.com/static/js/main.abc123.js.map

  Endpoints extracted from source map not present in Swagger documentation:
  /api/v1/admin/users        → GET returns all users (tested in Finding #2)
  /api/v1/internal/config    → GET returns application configuration
  /api/v1/debug/env          → GET returns environment variables
  /api/v1/reports/bulk-export → POST exports all data without rate limiting

  All four endpoints responded to requests using a standard user Bearer token.
  Three of four returned data that should require admin-level access.

Impact:
  Complete API attack surface was mapped from a single publicly accessible
  source map file. Undocumented endpoints bypassed all known access controls
  because they were not included in the security review scope.

Remediation:
  Remove source map files from production deployments:
  → webpack.config.js: devtool: false (production build)
  → Or serve .map files only from internal IP ranges via CDN/nginx rules
  Audit all endpoints in JS source for access control completeness
  Include all endpoints in security review scope regardless of documentation status
```

---

## 🧭 Key Takeaways

**1. JavaScript bundle analysis is the most reliable API recon source.**
Swagger documentation only lists what someone intentionally documented. The JavaScript bundle contains every API endpoint the frontend calls — including admin endpoints added at 11pm before a release, internal analytics calls, and deprecated endpoints that nobody removed. Always analyse the JS bundle before starting vulnerability testing.

**2. Old API versions are the highest-return API testing target.**
`/api/v2/users/1042` may properly enforce IDOR protection. `/api/v1/users/1042` — which was supposed to be retired but still responds — may not. I have found multiple Critical IDOR and auth bypass findings exclusively on deprecated API versions that the security team had stopped reviewing. Always enumerate and test all active versions.

**3. Source map exposure is an immediate Critical finding.**
A deployed `.js.map` file contains the complete original source code of the frontend application. It reveals every API endpoint, every authentication pattern, every commented-out debug feature, and sometimes hardcoded secrets. It is a higher-value finding than most injection vulnerabilities.

**4. Mobile API endpoints frequently have weaker security posture than web.**
The web API endpoint at `api.company.com` may have a WAF, rate limiting, and thorough access controls. The mobile API endpoint at `api-mobile.company.com` — built six months later by a different team — often has none of these. Always identify and test mobile API endpoints separately.

---

## 🔗 References
- [OWASP API Security — Excessive Data Exposure](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [PortSwigger API Testing Research](https://portswigger.net/web-security/api-testing)
- [SecLists API Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
