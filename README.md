# Dangling DNS & Cloud Takeover Scanner

A high-performance, multi-threaded offensive reconnaissance tool designed to identify dangling DNS CNAME records vulnerable to Cloud Asset Takeover (Subdomain Takeover).

## Features

- **Multi-threaded Engine**: Asynchronously scans large lists of subdomains using `concurrent.futures`.
- **CNAME Chain Resolution**: Follows multi-hop CNAME chains to find the final cloud provider target.
- **Provider Fingerprinting**: Matches CNAME targets against a curated database of cloud providers (AWS, Azure, GitHub, Heroku, etc.).
- **Active HTTP Verification**: Proactively fetches the HTTP response to verify if the cloud resource is unclaimed by matching specific error fingerprints.
- **Extensible Signature Database**: Easily add new cloud providers via a simple `signatures.json` file.
- **JSON Export**: Output results to JSON for integration with other pipelines (e.g., reporting, Slack alerts).
##  Documentation

For more technical details, please refer to the `docs/` folder:

- [Architecture & Design](docs/ARCHITECTURE.md) - How the core pipeline and multi-threading works.
- [Signature Database Guide](docs/SIGNATURES.md) - How to contribute new cloud provider fingerprints.
- [Understanding the Vulnerability](docs/VULNERABILITY.md) - The impact and mechanics of Cloud Asset Takeover.
## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/subdomain-takeover-scanner.git
   cd subdomain-takeover-scanner