# API Security — Enterprise Penetration Testing Series

<div align="center">

[![Author](https://img.shields.io/badge/Author-Dheeraj%20Kumar%20Jayaswal-2E6DA4?style=for-the-badge&logo=person&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Experience](https://img.shields.io/badge/Experience-5%2B%20Years%20Enterprise%20AppSec-FF6B35?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Role](https://img.shields.io/badge/Role-Technology%20Lead%20%E2%80%93%20Offensive%20Security-2ECC71?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Org](https://img.shields.io/badge/Infosys%20Limited-Pune%2C%20India-0078D6?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>

---

## 🎯 What This Series Is

This is not a beginner's guide to what APIs are. This is a field-tested, enterprise-grade reference documenting how I test API security in real engagements — at Infosys, across BFSI, healthcare, retail, and technology clients.

Every write-up in this series reflects an attack pattern I have confirmed in production enterprise environments. Every report template reflects the format I submit to clients. Every tool command is one I run in real assessments.

**The gap this series fills:**

Most API security resources cover the theory. This series covers the practice — specifically the practice in enterprise environments where the stakes are GDPR compliance, PCI-DSS certification, and real user data at scale.

---

## 🧠 Why API Security Is Where the Real Findings Are

```
The shift to API-first architecture has fundamentally changed the attack surface.

Traditional web app (2010-2015):
  Browser → HTML form → Server → HTML response
  Attack surface: visible form fields, URL parameters

Modern enterprise application (2020-present):
  React/Angular SPA → REST/GraphQL API → Microservices → Databases
  Attack surface: JSON bodies, auth tokens, HTTP methods,
                  API versioning, inter-service trust, mass assignment

The developer assumption that breaks enterprise APIs:
  "Only our frontend calls these endpoints"
  → Wrong. Any HTTP client with a valid token can call them.
  → The API must enforce access control itself.
  → The UI filtering is not a security control.

What this means for enterprise testing:
  → BOLA/IDOR is the most common Critical finding (not SQLi)
  → Mass assignment via undocumented fields is frequently missed
  → Old API versions are consistently less secure than current ones
  → Mobile API backends have weaker controls than web backends
  → GraphQL introspection hands attackers the complete data model
```

---

## 📚 Series Contents

### 🔷 Foundation

| # | Topic | Description | Key Enterprise Findings |
|---|---|---|---|
| 01 | [REST API Security](./API_REST_Security_Enterprise.md) | HTTP methods, status codes, BOLA, mass assignment, injection, rate limiting | BOLA across all HTTP methods, NoSQL injection, 422-as-schema-leak |
| 02 | [API Authentication Methods](./API_Auth_Methods_Enterprise.md) | JWT (5 attacks), API keys, OAuth 2.0, Basic Auth, session cookies | JWT weak secret cracking, OAuth state bypass, RS256→HS256 confusion |
| 03 | [GraphQL Security](./API_GraphQL_Enterprise.md) | Introspection, BOLA, batching, nesting DoS, SSRF via mutations | Unauthenticated introspection, batching rate-limit bypass, field-level BOLA |
| 04 | [API Reconnaissance](./API_Recon_Enterprise.md) | Source map analysis, version enumeration, mobile API discovery, gateway bypass | Source map RCE chain, old API version auth bypass, hardcoded secrets in JS |
| 05 | [Postman for API Testing](./API_Postman_Enterprise.md) | Spec import, environment management, test scripts, CI/CD integration | Automated BOLA sweep, dynamic token refresh, Newman pipeline integration |

---

## 🏆 OWASP API Security Top 10 Coverage

| OWASP API Risk | Write-up Coverage | Severity in Enterprise |
|---|---|---|
| API1 — Broken Object Level Authorization | REST API, GraphQL | Critical |
| API2 — Broken Authentication | Auth Methods | Critical |
| API3 — Broken Object Property Level Auth | REST API (Mass Assignment) | High–Critical |
| API4 — Unrestricted Resource Consumption | REST API (Rate Limiting), GraphQL (Batching) | Medium–High |
| API5 — Broken Function Level Authorization | REST API, GraphQL | Critical |
| API6 — Unrestricted Access to Sensitive Flows | REST API (Business Logic) | High |
| API7 — Server Side Request Forgery | GraphQL (Mutations) | Critical |
| API8 — Security Misconfiguration | API Recon, GraphQL | High–Critical |
| API9 — Improper Inventory Management | API Recon (Version Enum) | High |
| API10 — Unsafe Consumption of APIs | Auth Methods (OAuth) | High |

---

## 🔑 My Most Impactful Enterprise API Findings (Patterns)

The vulnerability classes I find most consistently across enterprise API engagements:

```
1. BOLA on all HTTP methods — not just GET
   Developers protect GET endpoints for IDOR.
   PUT and DELETE on the same resource often have no check.
   One IDOR finding becomes three Critical findings.

2. JWT HS256 weak secrets
   Early Spring Boot tutorials used "secret" as the example signing key.
   Production apps were built from those tutorials.
   Hashcat + rockyou.txt cracks them in seconds.

3. Excessive data exposure — the DTO gap
   Backend returns the full database object.
   Frontend displays 4 fields.
   The API response contains 47 fields including password_hash and salary.
   No attack required — just Burp Suite and careful observation.

4. Old API version missing auth checks
   /api/v2/users/1042 → correctly returns 403 (ownership enforced)
   /api/v1/users/1042 → returns 200 with full data (old version, no check)
   "Deprecated" does not mean "disabled."

5. GraphQL introspection in production
   One query hands the attacker the complete data model.
   Type names like "AdminConfig" and "EmployeePayroll" are the roadmap.
   Disable it unconditionally in production.

6. Mass assignment at registration
   Teams add protection to profile update endpoints.
   They forget the registration endpoint.
   POST /register with role=admin — accepted more often than it should be.
```

---

## 🛠️ Tools Used in This Series

| Tool | Primary Role | Coverage |
|---|---|---|
| **Burp Suite Pro** | Core manual testing, request manipulation | All write-ups |
| **Postman** | Structured collection testing, CI/CD integration | Day 05 |
| **ffuf** | API endpoint and parameter fuzzing | Day 04 |
| **Nuclei** | Automated CVE and misconfiguration scanning | OSINT phase |
| **cURL** | Quick PoC verification, report evidence | All write-ups |
| **jwt.io** | JWT inspection and decoding | Day 02 |
| **Hashcat** | JWT secret cracking (-m 16500) | Day 02 |
| **InQL (Burp)** | GraphQL schema visualisation and test generation | Day 03 |
| **Autorize (Burp)** | Automated BOLA/IDOR detection | Day 01 |

---

## 📐 My API Testing Methodology — 6 Phases

```
Phase 1: DOCUMENTATION DISCOVERY (30 minutes)
  → Find Swagger/OpenAPI spec → import to Postman
  → Check for GraphQL introspection
  → Extract API endpoints from JavaScript bundles
  → Enumerate API versions (v1, v2, beta, internal)

Phase 2: AUTHENTICATION ANALYSIS (30 minutes)
  → Identify auth mechanism (JWT, API key, cookie, OAuth)
  → JWT: decode, check algorithm, test weak secret
  → Test unauthenticated access to all discovered endpoints
  → Test token replay after logout

Phase 3: BOLA / IDOR SWEEP (1-2 hours)
  → Create two test accounts
  → Configure Autorize with victim's token
  → Test all HTTP methods (GET, PUT, DELETE, PATCH) with victim IDs
  → Test IDOR in URL path, query string, body, custom headers

Phase 4: DATA EXPOSURE AUDIT (30 minutes)
  → Compare UI rendering vs raw API response body
  → Document all fields present but not displayed
  → Test export/bulk endpoints for excessive data

Phase 5: INJECTION & BUSINESS LOGIC (1-2 hours)
  → SQLi in all string parameters
  → NoSQL injection in JSON body
  → Rate limiting on auth and OTP endpoints
  → Mass assignment at registration and profile update

Phase 6: DOCUMENTATION & REPORTING
  → CVSS score every finding
  → cURL reproduction command for every PoC
  → Secure code fix in application's language
  → Postman collection delivered to dev team
```

---

## 📋 Quick Reference — API Testing Checklist

```
DISCOVERY
☐ Swagger/OpenAPI spec found and imported to Postman?
☐ GraphQL introspection accessible (with/without auth)?
☐ JavaScript bundle analysed for undocumented endpoints?
☐ API versions enumerated: v1, v2, beta, internal, mobile?
☐ Source maps accessible (.js.map files)?

AUTHENTICATION
☐ All endpoints tested without Authorization header?
☐ JWT algorithm: alg:none, weak secret, RS256→HS256?
☐ Token replay after logout?
☐ OAuth state parameter present and validated?
☐ API keys found in JS bundles?

BOLA / AUTHORIZATION
☐ Two test accounts configured?
☐ Autorize running with victim token?
☐ GET, PUT, DELETE, PATCH all tested with victim IDs?
☐ Admin-prefixed queries/mutations tested with standard token?
☐ Mass assignment: role, is_admin, plan fields injected?

DATA EXPOSURE
☐ API response compared against UI display?
☐ Hidden fields documented: password_hash, salary, national_id?
☐ Export endpoints tested for bulk data access?

INJECTION & RATE LIMITING
☐ SQLi in all string parameters?
☐ NoSQL injection in JSON body?
☐ 50 rapid requests to auth endpoint — 429 returned?
☐ SSTI: {{7*7}}, ${7*7} in template fields?

GRAPHQL SPECIFIC
☐ Schema download attempted?
☐ Admin mutations tested with standard token?
☐ Batching: 50 queries in one request?
☐ SSRF in URL-accepting mutations?
```

---

## 🏢 Enterprise vs Bug Bounty — The Key Differences

```
Bug bounty:          Find one bug → report → collect reward
Enterprise testing:  Systematic coverage of agreed scope → professional report → remediation support

What enterprise API testing adds:
  ✓ Scope document review before touching a single endpoint
  ✓ Rate limiting awareness (shared/production environments)
  ✓ SOC notification when active scanning begins
  ✓ Evidence collection standards (every finding needs reproducible PoC)
  ✓ CVSS scoring and business impact statements
  ✓ Secure code fixes in the application's language
  ✓ Postman collection delivered as remediation aid
  ✓ Retest after fixes (closing the loop)

The methodology is what separates a professional engagement
from a skilled individual doing their best ad hoc.
```

---

## 🎓 My Professional Background

**15+ years in IT | 5+ years in offensive security | Infosys Limited**

I started as a full-stack developer — ASP.NET, SQL Server, JavaScript. That developer background is my biggest edge in API security testing. I understand why APIs are built the way they are, which shortcuts are taken under deadline pressure, and where access control checks get missed when teams are moving fast.

**Domain experience:** BFSI · Healthcare · Retail · E-commerce · Freight Logistics · Education

**Certifications:**
- CEH — EC-Council (2021)
- AWS Certified Solutions Architect (2022)
- OSCP — OffSec (In Progress 2025-2026)
- IIT Kanpur Executive Cert in Cyber Security (In Progress 2025-2026)

---

## 🔗 Connect

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Email](https://img.shields.io/badge/Email-jaiswal.dheeraj123%40gmail.com-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:jaiswal.dheeraj123@gmail.com)

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

</div>

---

## 🔗 References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy — API Testing](https://portswigger.net/web-security/api-testing)
- [OWASP Web Security Testing Guide — API Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-API_Testing/)
- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
