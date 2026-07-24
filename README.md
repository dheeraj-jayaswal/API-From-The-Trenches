<div align="center">

# API Security — Enterprise Penetration Testing Series

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Experience](https://img.shields.io/badge/Experience-5%2B%20Years%20Enterprise%20AppSec-FF6B35?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Role](https://img.shields.io/badge/Role-Technology%20Lead%20--%20Offensive%20Security-2ECC71?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)
[![Org](https://img.shields.io/badge/Infosys%20Limited-Pune%2C%20India-0078D6?style=for-the-badge)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>

---

## 🎯 What This Series Is

This is not a beginner's guide to what APIs are. This is a field-tested, enterprise-grade reference documenting how I test API security in real engagements at Infosys, across regulated and high-stakes enterprise sectors.

Every write-up in this series reflects an attack pattern I have confirmed in production enterprise environments. Every report template reflects the format I submit to clients. Every tool command is one I run in real assessments.

**The gap this series fills:**

Most API security resources cover the theory. This series covers the practice — specifically the practice in enterprise environments where the stakes are regulatory compliance, contractual data-protection obligations, and real user data at scale.

---

## 🧭 How This Fits With My Other Repos

| Repo | What it's for |
|---|---|
| **API-From-The-Trenches** *(this repo)* | The deep, technical API security reference — full methodology, OWASP API Top 10 mapping, tool workflows, signature findings |
| [From-Dev-To-Attacker](https://github.com/dheeraj-jayaswal/From-Dev-To-Attacker)'s `api-security/` folder | Shorter "why this vulnerability exists" companion pieces from a developer's lens, with enterprise domain-impact framing — read those first for intuition, come here for full depth |
| [Bug-Bounty-Hunting-Companion](https://github.com/dheeraj-jayaswal/Bug-Bounty-Hunting-Companion) | Real disclosed HackerOne reports turned into reproducible checklists |
| [AppSec-From-The-Trenches](https://github.com/dheeraj-jayaswal/AppSec-From-The-Trenches) | Broader enterprise AppSec knowledge base beyond just APIs |

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

| # | Topic | File | Key Enterprise Findings |
|---|---|---|---|
| 01 | REST API Security | [Rest-API.md](Rest-API.md) | BOLA across all HTTP methods, NoSQL injection, schema-leak via error codes |
| 02 | API Authentication Methods | [AUTH-Methods.md](AUTH-Methods.md) | JWT weak secret cracking, OAuth state bypass, RS256→HS256 confusion |
| 03 | GraphQL Security | [GraphQL.md](GraphQL.md) | Unauthenticated introspection, batching rate-limit bypass, field-level BOLA |
| 04 | API Reconnaissance | [API-RECON.md](API-RECON.md) | Source map RCE chain, old API version auth bypass, hardcoded secrets in JS |
| 05 | Postman for API Testing | [POSTMAN.md](POSTMAN.md) | Automated BOLA sweep, dynamic token refresh, Newman pipeline integration |

### 🔷 OWASP API Top 10 & Access Control

| # | Topic | File |
|---|---|---|
| 06 | Broken Object Level Authorization | [Broken-Object-Level-Authorization.md](Broken-Object-Level-Authorization.md) |
| 07 | Broken Authentication | [API-Broken-Authentication.md](API-Broken-Authentication.md) |
| 08 | Mass Assignment | [Mass-Assignment.md](Mass-Assignment.md) |
| 09 | Rate Limiting | [API-Rate-Limiting.md](API-Rate-Limiting.md) |
| 10 | Broken Function Level Authorization | [Broken-Function-Level-Authorization.md](Broken-Function-Level-Authorization.md) |
| 11 | SSRF via API Mutations | [API-SSRF.md](API-SSRF.md) |
| 12 | API Versioning Security | [API-Versioning-Security.md](API-Versioning-Security.md) |
| 13 | OpenAPI / Swagger Security | [OpenAPI-Swagger-Security.md](OpenAPI-Swagger-Security.md) |
| 14 | API7–API10 Coverage | [API-OWASP-7-to-10.md](API-OWASP-7-to-10.md) |

### 🔷 Tooling

| # | Topic | File |
|---|---|---|
| 15 | Burp Suite Pro for API Testing | [Burp-Suite-Pro-for-API-Security-Testing.md](Burp-Suite-Pro-for-API-Security-Testing.md) |

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
| **Postman** | Structured collection testing, CI/CD integration | Postman guide |
| **ffuf** | API endpoint and parameter fuzzing | Recon |
| **Nuclei** | Automated CVE and misconfiguration scanning | Recon phase |
| **cURL** | Quick PoC verification, report evidence | All write-ups |
| **jwt.io** | JWT inspection and decoding | Auth Methods |
| **Hashcat** | JWT secret cracking (-m 16500) | Auth Methods |
| **InQL (Burp)** | GraphQL schema visualisation and test generation | GraphQL |
| **Autorize (Burp)** | Automated BOLA/IDOR detection | BOLA |

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
```

---

## 🎓 My Professional Background

**15+ years in IT | 5+ years in offensive security | Infosys Limited**

I started as a full-stack developer — ASP.NET, SQL Server, JavaScript. That developer background is my biggest edge in API security testing. I understand why APIs are built the way they are, which shortcuts are taken under deadline pressure, and where access control checks get missed when teams are moving fast.

**Domain experience:** Income Tax · Banking · Retail · E-commerce · Freight Logistics · Education

**Certifications:**

- CEH — EC-Council (2021)
- AWS Certified Solutions Architect – Associate (2022)
- AWS Certified Cloud Practitioner (2022)
- OSCP — OffSec (In Progress 2025-2026)
- IIT Kanpur Executive Cert in Cyber Security (In Progress 2025-2026)

---

## 📄 License

[![License](https://img.shields.io/badge/license-CC%20BY%204.0-blue)](LICENSE.md)
[![Last Commit](https://img.shields.io/github/last-commit/dheeraj-jayaswal/API-From-The-Trenches)](https://github.com/dheeraj-jayaswal/API-From-The-Trenches/commits/main)

⭐ If this helped you, consider starring the repo — it helps others find it too.
---

## 🔗 Connect

[LinkedIn](https://linkedin.com/in/dheerajkumarjayaswal) · [Email](mailto:jaiswal.dheeraj123@gmail.com)

*Open to consulting, collaboration, and security discussions.*

---

## 🔗 References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy — API Testing](https://portswigger.net/web-security/api-testing)
- [OWASP Web Security Testing Guide — API Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-API_Testing/)
- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
