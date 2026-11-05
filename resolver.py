import dns.resolver
import dns.exception

MAX_HOPS = 10
DNS_TIMEOUT = 5

def resolve_cname_chain(subdomain: str) -> dict:
    """
    Resolve the CNAME chain for a given subdomain.

    Returns a dict:
    {
        "subdomain": str,
        "chain": [str, ...],       # each CNAME target in order
        "final_target": str|None,  # last CNAME target, or None if no CNAME
        "error": str|None
    }
    """
    result = {
        "subdomain": subdomain,
        "chain": [],
        "final_target": None,
        "error": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    current = subdomain
    visited = set()

    for _ in range(MAX_HOPS):
        if current in visited:
            result["error"] = f"CNAME loop detected at {current}"
            break
        visited.add(current)

        try:
            answers = resolver.resolve(current, "CNAME")
        except dns.resolver.NoAnswer:
            # No CNAME at this name. If we already have a chain, current is terminal.
            break
        except dns.resolver.NXDOMAIN:
            result["error"] = f"NXDOMAIN at {current}"
            break
        except dns.resolver.NoNameservers:
            result["error"] = f"No nameservers for {current}"
            break
        except dns.exception.Timeout:
            result["error"] = f"DNS timeout at {current}"
            break
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
            break

        # answers may contain one or more CNAME records.
        # We take the first target and continue from there.
        if len(answers) == 0:
            break

        target = str(answers[0].target).rstrip(".")
        result["chain"].append(target)
        current = target
    else:
        result["error"] = f"Exceeded {MAX_HOPS} hops"

    if result["chain"]:
        result["final_target"] = result["chain"][-1]

    return result