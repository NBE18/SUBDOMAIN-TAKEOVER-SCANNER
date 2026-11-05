import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from resolver import resolve_cname_chain
from matcher import load_signatures, match_signature
from verifier import verify_http

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def process_subdomain(subdomain, signatures):
    """The worker function run by each thread."""
    subdomain = subdomain.strip()
    if not subdomain:
        return None

    result = {
        "subdomain": subdomain,
        "cname": None,
        "provider": None,
        "status": "clean",
        "details": ""
    }

    # 1. Resolve DNS
    dns_result = resolve_cname_chain(subdomain)
    if not dns_result['final_target']:
        result["details"] = "No CNAME record found"
        return result
    
    result["cname"] = dns_result['final_target']

    # 2. Match Signature
    match = match_signature(dns_result['final_target'], signatures)
    if not match:
        result["details"] = "CNAME points to unknown provider"
        return result
    
    result["provider"] = match["provider"]

    # 3. Verify HTTP
    verify = verify_http(subdomain, match)
    
    if verify["vulnerable"]:
        result["status"] = "VULNERABLE"
        result["details"] = f"Matched fingerprint: '{verify['fingerprint_matched']}' (HTTP {verify['status_code']})"
    else:
        result["status"] = "safe"
        if verify["error"]:
            result["details"] = f"HTTP Error: {verify['error']}"
        else:
            result["details"] = f"Resource is active (HTTP {verify['status_code']})"

    return result

def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-d", "--domain", help="Single domain to test (e.g., blog.example.com)")
    parser.add_argument("-f", "--file", help="File containing a list of subdomains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    
    args = parser.parse_args()

    if not args.domain and not args.file:
        print("[-] You must provide either --domain or --file")
        parser.print_help()
        sys.exit(1)

    # Load signatures once
    try:
        signatures = load_signatures()
    except Exception as e:
        print(f"[-] Error loading signatures.json: {e}")
        sys.exit(1)

    # Collect targets
    targets = []
    if args.domain:
        targets.append(args.domain)
    if args.file:
        try:
            with open(args.file, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)

    print(f"[*] Loaded {len(signatures)} cloud provider signatures.")
    print(f"[*] Scanning {len(targets)} subdomains with {args.threads} threads...\n")

    results = []
    
    # Multithreading magic
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_subdomain = {executor.submit(process_subdomain, sub, signatures): sub for sub in targets}
        
        for future in as_completed(future_to_subdomain):
            try:
                res = future.result()
                if res:
                    results.append(res)
                    # Print progress as it happens
                    status_color = "\033[91m" if res["status"] == "VULNERABLE" else "\033[92m"
                    reset_color = "\033[0m"
                    print(f"{status_color}[{res['status'].upper()}]{reset_color} {res['subdomain']} -> {res['cname'] or 'N/A'} ({res['provider'] or 'Unknown'}) | {res['details']}")
            except Exception as e:
                print(f"[-] Thread error: {e}")

    # Save output if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()