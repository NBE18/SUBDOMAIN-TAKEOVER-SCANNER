import json
import fnmatch
import os

def load_signatures(filepath="signatures.json"):
    """Load the signatures.json file from the project directory."""
    # Ensure the path is relative to the current script's directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(base_dir, filepath)
    
    with open(full_path, "r") as f:
        return json.load(f)

def match_signature(final_target, signatures):
    """
    Match final_target against all cname_patterns in signatures.
    Returns a dict with the matched provider info, or None if no match.
    """
    if not final_target:
        return None

    target_lower = final_target.lower()

    for key, sig in signatures.items():
        for pattern in sig.get("cname_patterns", []):
            if fnmatch.fnmatch(target_lower, pattern.lower()):
                return {
                    "provider_key": key,
                    "provider": sig["provider"],
                    "status": sig["status"],
                    "http_fingerprint": sig["http_fingerprint"],
                    "alternative_fingerprints": sig.get("alternative_fingerprints", []),
                    "severity": sig.get("severity", "unknown"),
                    "notes": sig.get("notes", "")
                }
    return None