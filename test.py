from resolver import resolve_cname_chain
from matcher import load_signatures, match_signature
from verifier import verify_http

signatures = load_signatures()

test_domains = [
    "fake-bucket.s3.amazonaws.com",
    "pages.github.com",
    "mailgun.bitly.com",       # Historically vulnerable (Heroku)
    "pages.github.com"  
]

for subdomain in test_domains:
    print(f"\n--- Testing {subdomain} ---")
    
    dns_result = resolve_cname_chain(subdomain)
    if not dns_result['final_target']:
        print("No CNAME target found.")
        continue

    match = match_signature(dns_result['final_target'], signatures)
    if not match:
        print("No cloud provider signature matched.")
        continue
        
    print(f"MATCH: {match['provider']} (Status: {match['status']})")
    print(f"Target CNAME: {dns_result['final_target']}")
    
    # --- NEW HTTP VERIFICATION ---
    print("Sending HTTP request to verify...")
    verify_result = verify_http(subdomain, match)
    
    if verify_result["vulnerable"]:
        print(f" VULNERABLE! Fingerprint matched: '{verify_result['fingerprint_matched']}'")
        print(f"   HTTP Status: {verify_result['status_code']}")
    else:
        if verify_result["error"]:
            print(f" SAFE (or unresolvable). HTTP Error: {verify_result['error']}")
        else:
            print(f" SAFE. Resource is active (HTTP {verify_result['status_code']}), but no vulnerability fingerprint found.")