# Postman for API Security Testing — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — Tooling & Workflow
>
> **Context:** Postman occupies a specific role in my enterprise API testing workflow that Burp Suite does not easily replicate: structured, collection-based testing with automation, environment management, and test scripts. When a Swagger/OpenAPI specification is available, importing it into Postman instantly creates a complete, organised testing environment for every API endpoint. When it is not available, I build the collection incrementally from Burp traffic. This document covers how I use Postman professionally in enterprise API security assessments.

---

## 🧠 Postman vs Burp Suite — When to Use Each

```
Burp Suite:
  ✓ Intercepting and modifying live traffic
  ✓ Deep manual testing: injection, fuzzing, encoding manipulation
  ✓ Automated scanning (Pro)
  ✓ IDOR testing with Autorize extension
  ✓ When you need to modify requests at the raw HTTP level
  ✓ Evidence capture for pentest reports (screenshots + request history)

Postman:
  ✓ Structured testing from OpenAPI/Swagger specification
  ✓ Managing multiple authentication environments (test/staging/prod)
  ✓ Collection Runner for batch-executing test sequences
  ✓ Pre/post-request scripting for dynamic auth token management
  ✓ Test assertions for automated regression testing
  ✓ Sharing test collections with development teams
  ✓ API contract testing (does response match specification?)

Enterprise workflow:
  Burp = primary manual testing tool
  Postman = structured coverage tool and developer handoff format
  Both run simultaneously — Burp proxies Postman traffic for dual coverage
```

---

## ⚙️ Enterprise Setup — Environment Configuration

### Creating Environments for Each Testing Context

```javascript
// Postman Environments panel → New Environment

// Environment: "API Testing — Staging"
Variables:
  base_url:         https://staging-api.company.com
  admin_token:      eyJhbGciOiJIUzI1NiJ9...(admin account)
  user_token:       eyJhbGciOiJIUzI1NiJ9...(standard user)
  victim_token:     eyJhbGciOiJIUzI1NiJ9...(second test account for IDOR)
  attacker_user_id: 1099
  victim_user_id:   1042

// Environment: "API Testing — Production" (read-only testing only)
  base_url:         https://api.company.com
  user_token:       eyJhbGciOiJIUzI1NiJ9...(own test account only)

// Use variables in requests:
// GET {{base_url}}/api/v1/users/{{victim_user_id}}
// Authorization: Bearer {{user_token}}

// This lets you switch between environments with one click
// Same collection, different auth contexts
```

### Collection-Level Authentication

```javascript
// Set auth at collection level — applies to all requests:
// Collection → Edit → Authorization tab

// Type: Bearer Token
// Token: {{user_token}}   ← references environment variable

// Individual requests inherit this automatically
// Override at request level when testing specific auth scenarios

// For API key authentication:
// Type: API Key
// Key: X-API-Key
// Value: {{api_key}}
// Add to: Header
```

---

## 🔧 Importing OpenAPI/Swagger Specs

When a Swagger specification is available, this is the single most efficient setup step in an API security assessment.

```
Import workflow:
  1. File → Import → select swagger.json or openapi.yaml
     Or: Import from URL: https://api.company.com/v2/api-docs
  2. Postman creates a collection with every documented endpoint
  3. All endpoints organised by tag/category
  4. Request bodies pre-populated with example values
  5. Path parameters detected automatically

After import:
  → Review every endpoint (look for admin, internal, undocumented paths)
  → Set environment variables for auth tokens
  → Check if API spec contains more endpoints than the UI exposes
  → Note any endpoints marked "deprecated" — test these specifically
  → Compare spec endpoints vs JS bundle endpoints (gaps = undocumented paths)

Value of spec import vs manual collection building:
  Manual: 2-3 hours to document 50 endpoints from Burp traffic
  Spec import: 2 minutes → 50 endpoints ready to test
  The saved time goes directly into testing depth
```

---

## 🔐 Authentication Management in Postman

### Dynamic Token Refresh with Pre-Request Scripts

```javascript
// Pre-request script — auto-refresh token before each request
// Eliminates manual token updates during long testing sessions

pm.sendRequest({
    url: pm.environment.get('base_url') + '/api/v1/auth/login',
    method: 'POST',
    header: { 'Content-Type': 'application/json' },
    body: {
        mode: 'raw',
        raw: JSON.stringify({
            email: pm.environment.get('test_email'),
            password: pm.environment.get('test_password')
        })
    }
}, function (err, response) {
    if (!err && response.code === 200) {
        const token = response.json().access_token;
        pm.environment.set('user_token', token);
        console.log('Token refreshed successfully');
    }
});
```

### Multi-Role Testing Setup

```javascript
// Switch between roles easily for access control testing

// Pre-request script for admin-role requests:
pm.request.headers.add({
    key: 'Authorization',
    value: 'Bearer ' + pm.environment.get('admin_token')
});

// Pre-request script for standard-user requests:
pm.request.headers.add({
    key: 'Authorization',
    value: 'Bearer ' + pm.environment.get('user_token')
});

// For IDOR testing — add victim's user_id to request URL:
// GET {{base_url}}/api/v1/users/{{victim_user_id}}
// Authorization: Bearer {{user_token}}    ← attacker's token, victim's ID
```

---

## 🔍 Test Scripts for Automated Security Checks

Test scripts run after each request and automatically flag security issues.

```javascript
// Test 1: Check for sensitive data in response (data exposure detection)
pm.test("No password hashes in response", function () {
    const body = pm.response.text();
    pm.expect(body).to.not.include('password_hash');
    pm.expect(body).to.not.include('$2a$');     // bcrypt prefix
    pm.expect(body).to.not.include('$2b$');
});

pm.test("No salary data exposed to standard user", function () {
    if (pm.environment.get('current_role') === 'user') {
        const jsonBody = pm.response.json();
        pm.expect(jsonBody).to.not.have.property('salary');
        pm.expect(jsonBody).to.not.have.property('national_id');
    }
});

// Test 2: BOLA detection — response should not belong to another user
pm.test("Response belongs to authenticated user (BOLA check)", function () {
    const jsonBody = pm.response.json();
    const myUserId = parseInt(pm.environment.get('attacker_user_id'));
    const victimUserId = parseInt(pm.environment.get('victim_user_id'));
    
    // If we requested victim's resource, it should NOT be returned
    if (pm.request.url.toString().includes(victimUserId)) {
        pm.expect(pm.response.code).to.be.oneOf([403, 404]);
    }
});

// Test 3: Missing authentication check
pm.test("Endpoint requires authentication", function () {
    // This test runs after removing the auth header
    // 200 = CRITICAL — unauthenticated access
    pm.expect(pm.response.code).to.not.equal(200);
});

// Test 4: Rate limiting check
pm.test("Rate limiting enforced after multiple attempts", function () {
    // Run Collection Runner 50 times, check if 429 appears
    const attempts = pm.environment.get('request_count') || 0;
    pm.environment.set('request_count', parseInt(attempts) + 1);
    
    if (parseInt(attempts) > 10) {
        pm.expect(pm.response.code).to.equal(429,
            'Expected 429 after 10 attempts — rate limiting missing');
    }
});

// Test 5: Stack trace / sensitive error information
pm.test("Error response does not contain stack trace", function () {
    if (pm.response.code >= 400) {
        const body = pm.response.text();
        pm.expect(body).to.not.include('StackTrace');
        pm.expect(body).to.not.include('at System.');
        pm.expect(body).to.not.include('Exception');
        pm.expect(body).to.not.include('C:\\inetpub');
        pm.expect(body).to.not.include('/var/www');
    }
});

// Test 6: Response time monitoring (DoS / slow query detection)
pm.test("Response time within acceptable range", function () {
    pm.expect(pm.response.responseTime).to.be.below(2000,
        'Response took >2 seconds — potential injection or DoS vector');
});
```

---

## 🔄 Collection Runner for Systematic Testing

```javascript
// Run scenarios across the entire collection:

// Scenario 1: Test all endpoints without authentication
// → Set: Authorization = empty in collection-level auth
// → Run Collection Runner
// → Any 200 responses = unauthenticated endpoint = finding

// Scenario 2: IDOR sweep — test all endpoints with victim's IDs
// → Set environment: attacker uses own token
//   but requests reference victim_user_id
// → Run Collection Runner
// → Log any 200 responses with victim's data

// Scenario 3: Mass assignment sweep
// → Add custom header to all PUT/POST requests: X-Extra-Fields: true
// → Include role, is_admin fields in all request bodies
// → Run Collection Runner
// → Check responses for reflected privileged fields

// Collection Runner settings:
// Iterations: 1
// Delay: 100ms (respectful rate to avoid impacting server)
// Data file: can supply a CSV of test IDs for IDOR iteration
// Results: export as JSON/HTML for evidence
```

---

## 🏢 Proxying Postman Through Burp Suite

This combination gives you the best of both tools simultaneously.

```
Setup:
  1. Burp → Proxy → Options → Proxy Listeners → 127.0.0.1:8080
  2. Postman → Settings → Proxy
     → Use custom proxy configuration
     → HTTP: 127.0.0.1:8080
     → HTTPS: 127.0.0.1:8080
     → Disable SSL verification (Burp intercepts TLS)
  3. Install Burp CA certificate in Postman's certificate store

Benefits:
  → Every Postman request appears in Burp HTTP History
  → Can send any Postman-generated request to Burp Repeater
  → Burp Scanner runs against Postman-discovered endpoints
  → Autorize monitors Postman requests for IDOR automatically
  → Complete evidence trail in Burp project file

Enterprise workflow:
  1. Import Swagger spec to Postman
  2. Route Postman through Burp proxy
  3. Run Collection Runner → all 60 endpoints tested systematically
  4. Burp captures all traffic → JS Miner finds additional endpoints
  5. Autorize flags any IDOR in the collection run
  6. Manual deep-dive in Burp Repeater on flagged findings
```

---

## 📤 Sharing Collections With Development Teams

After the engagement, I deliver the Postman collection to the development team as part of the remediation support.

```
What the collection contains:
  → All tested endpoints documented
  → Test scripts that automatically detect security issues
  → Environment files for test/staging (no production credentials)
  → Example requests showing each vulnerability found
  → Pre-request scripts for authentication management

Why this adds value:
  → Developers can run the collection after implementing fixes
  → Security tests run automatically in CI/CD via Newman (Postman CLI)
  → The test assertions catch regressions if vulnerabilities are reintroduced
  → Reduces the need for manual retest engagement for fixing verification

Newman CI/CD integration:
  newman run collection.json \
    --environment staging.json \
    --reporters cli,junit \
    --reporter-junit-export results.xml
  → Integrates into Jenkins, GitHub Actions, Azure DevOps
  → Security test results visible in pipeline dashboard
```

---

## 📋 Enterprise Report — Postman Evidence Standard

```
For Postman-discovered findings, evidence format:

1. Collection Runner report (exported HTML/JSON)
   → Shows all endpoints tested, all assertions passed/failed
   → Provides systematic coverage evidence

2. Specific finding screenshot:
   Request tab: method, URL, headers, body
   Response tab: status code, response time, body
   Tests tab: which assertions passed/failed

3. Collection Runner IDOR sweep results:
   "Collection Runner executed 47 requests with victim user credentials.
    23 requests returned 200 OK with victim user data.
    24 requests correctly returned 403 Forbidden.
    IDOR confirmed on 23 endpoints — see individual findings for details."
```

---

## 🧭 Key Takeaways

**1. Import the Swagger spec first — it is the fastest path to complete coverage.**
Manually building a 60-endpoint API collection from Burp traffic takes hours. Importing the OpenAPI spec takes 2 minutes and produces a more complete, organised collection. The time saved is testing time gained.

**2. Test scripts that catch security issues turn Postman into a regression testing tool.**
Adding assertions for "no password_hash in response" and "requires authentication" to the collection means the development team can run the same tests after each sprint. Security findings that were fixed can automatically detect if they regress.

**3. Proxy Postman through Burp — always.**
The combination of Postman's structured collection testing and Burp's traffic interception and analysis gives you complete coverage from both angles simultaneously. Postman provides breadth; Burp provides depth.

**4. Share the collection with the development team as a deliverable.**
A Postman collection with security test scripts is a higher-value deliverable than a PDF report alone. Developers can run it themselves, integrate it into CI/CD, and use it to verify fixes. This is the difference between a pentest that improves security posture and one that just produces paperwork.

---

## 🔗 References
- [Postman Documentation](https://learning.postman.com/docs/)
- [Newman CLI Documentation](https://learning.postman.com/docs/running-collections/using-newman-cli/command-line-integration-with-newman/)
- [OWASP API Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-API_Testing/)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 5+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
