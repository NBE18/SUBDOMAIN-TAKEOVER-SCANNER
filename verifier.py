import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def verify_http(subdomain, match_info, timeout=10):
    """
    Make an HTTP request to the subdomain and check if the response
    contains the expected fingerprint.
    """
    result = {
        "vulnerable": False,
        "status_code": None,
        "fingerprint_matched": None,
        "error": None
    }

    # Get the expected fingerprints from the signature
    primary_fp = match_info.get("http_fingerprint")
    alt_fps = match_info.get("alternative_fingerprints", [])
    all_fps = [primary_fp] + alt_fps if primary_fp else alt_fps

    # We try HTTPS first, fallback to HTTP if it fails
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            # We use verify=False to ignore SSL cert errors (dangling domains often have bad certs)
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            result["status_code"] = response.status_code
            body = response.text

            # Check if any fingerprint is in the body
            for fp in all_fps:
                if fp.lower() in body.lower():
                    result["vulnerable"] = True
                    result["fingerprint_matched"] = fp
                    return result

            # If we got a response but no fingerprint, we can stop checking
            # (no need to try HTTP if HTTPS worked and didn't match)
            return result 

        except requests.exceptions.RequestException as e:
            result["error"] = f"{scheme.upper()} failed: {str(e)}"
            # Continue to try HTTP if HTTPS failed
            continue

    return result