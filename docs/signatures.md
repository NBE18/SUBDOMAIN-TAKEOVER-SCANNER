# Contributing to the Signature Database

The power of this scanner lies in its `signatures.json` file. This file allows the scanner to support any cloud provider without requiring changes to the Python code.

## How to Add a New Cloud Provider

If you find a new cloud service vulnerable to subdomain takeover, you can add it by submitting a pull request with a new entry in `signatures.json`.

### Step 1: Find the CNAME Pattern
Identify the domain that the vulnerable service uses. For example, if a deleted resource points to `my-bucket.s3.amazonaws.com`, the pattern is `*.s3.amazonaws.com`.

### Step 2: Find the HTTP Fingerprint
When you visit the unclaimed domain, what error message does the provider return? 
For example, AWS returns `<Code>NoSuchBucket</Code>`.

### Step 3: Add the JSON Object

```json
  "provider_key": {
    "provider": "Full Provider Name",
    "status": "vulnerable", 
    "cname_patterns": [
      "*.provider.com"
    ],
    "http_fingerprint": "The exact error string",
    "alternative_fingerprints": [
      "Backup error string if applicable"
    ],
    "severity": "high",
    "notes": "Any caveats (e.g., 'Requires domain verification')."
  }
