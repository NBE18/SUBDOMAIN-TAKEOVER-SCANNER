
---

### Step Four: The `VULNERABILITY.md` (For Interviewers)

Create `docs/VULNERABILITY.md` and paste this. This is where you explain *why* this tool matters. Interviewers love this because it proves you understand the business impact.

```markdown
# Understanding Cloud Asset Takeover

## What is Subdomain Takeover?

Subdomain takeover occurs when a subdomain (e.g., `blog.example.com`) has a DNS record (usually a CNAME) pointing to a cloud service (e.g., AWS S3, GitHub Pages), but the corresponding resource on that cloud service has been deleted or expired.

Because the DNS record still exists, an attacker can register the unclaimed resource under their own account. When they do, they gain full control over the subdomain.

## The Attack Flow

1. **Creation**: A company creates an S3 bucket named `company-assets` and points `assets.company.com` to it via CNAME.
2. **Deletion**: The company migrates to a new provider and deletes the S3 bucket.
3. **The Mistake**: The company forgets to delete the DNS record for `assets.company.com`.
4. **Exploitation**: An attacker notices the dangling DNS record, creates their own S3 bucket named `company-assets`, and serves malicious JavaScript. Now, `assets.company.com` is serving the attacker's content.

## Why is this Critical?

1. **Phishing**: Attackers can host legitimate-looking login pages on the trusted domain (`login.company.com`).
2. **Cookie Stealing**: If the parent domain sets cookies on `.company.com`, the attacker's subdomain can receive them.
3. **Bypassing CSP**: Many Content Security Policies allow scripts from `*.company.com`. The attacker's subdomain now qualifies.

## How This Tool Helps

This tool automates the discovery of dangling CNAME records and verifies if the cloud resource is actually unclaimed by checking the HTTP response. It provides a crucial line of defense in continuous security auditing.
