# Architecture & Design

This tool is built with a modular architecture to ensure speed, accuracy, and maintainability. The core logic is decoupled from the data (signatures) and the presentation (CLI).

## 1. The Core Pipeline

The scanning process follows a strict pipeline to minimize false positives:

1. **DNS Resolution (`resolver.py`)**: 
   - Takes a subdomain and queries its `CNAME` records.
   - Follows multi-hop chains (e.g., `a.com -> b.com -> c.s3.amazonaws.com`) with a `MAX_HOPS` limit of 10 to prevent infinite loops.
   - Returns the final CNAME target.

2. **Signature Matching (`matcher.py`)**:
   - Loads the `signatures.json` database.
   - Uses `fnmatch` to compare the final CNAME target against known cloud provider patterns (e.g., `*.s3.amazonaws.com`).
   - If a match is found, it returns the provider's specific HTTP fingerprint (e.g., `NoSuchBucket`).

3. **HTTP Verification (`verifier.py`)**:
   - Sends a GET request to the original subdomain.
   - Disables SSL verification (`verify=False`) because dangling domains often have invalid certificates.
   - Reads the response body and searches for the expected fingerprint.
   - If the fingerprint is found, the subdomain is marked as **VULNERABLE**.

## 2. Concurrency Model

To handle large lists of subdomains efficiently, the tool uses Python's `concurrent.futures.ThreadPoolExecutor` (found in `main.py`).

- **Why Threading?** The bottleneck in this tool is network I/O (DNS queries and HTTP requests), not CPU processing. Threading allows the tool to wait for multiple network requests simultaneously, drastically reducing scan times.
- **Thread Safety**: The signature database is loaded into memory **once** at startup and passed to each thread as a read-only object. No shared state is mutated during the scan, preventing race conditions.
