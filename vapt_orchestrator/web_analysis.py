# vapt_orchestrator/web_analysis.py

from typing import List, Dict, Any
from urllib.parse import urlparse


def summarize_https_posture(httpx_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze HTTPX results and determine HTTPS-only / Mixed / HTTP-only posture per host.

    Produces findings like:
    {
      "tool": "https_posture",
      "host": "example.com",
      "posture": "https_only_observed" | "mixed_http_https" | "http_only_observed" | "unknown",
      "saw_http": bool,
      "saw_https": bool,
      "example_urls": [ "https://example.com", "http://example.com" ]
    }
    """
    by_host: Dict[str, Dict[str, Any]] = {}

    for f in httpx_findings:
        url = f.get("url") or ""
        if not url:
            continue

        parsed = urlparse(url)
        host = parsed.hostname or url
        scheme = (parsed.scheme or "").lower()

        if host not in by_host:
            by_host[host] = {
                "tool": "https_posture",
                "host": host,
                "saw_http": False,
                "saw_https": False,
                "example_urls": set(),
            }

        if scheme == "http":
            by_host[host]["saw_http"] = True  # keep typo? better correct: but I'll use saw_http
        elif scheme == "https":
            by_host[host]["saw_https"] = True

        if len(by_host[host]["example_urls"]) < 3:
            by_host[host]["example_urls"].add(url)

    results: List[Dict[str, Any]] = []
    for host, data in by_host.items():
        saw_http = data.get("saw_http", False)
        saw_https = data.get("saw_https", False)

        if saw_https and not saw_http:
            posture = "https_only_observed"
        elif saw_https and saw_http:
            posture = "mixed_http_https"
        elif saw_http and not saw_https:
            posture = "http_only_observed"
        else:
            posture = "unknown"

        results.append(
            {
                "tool": "https_posture",
                "host": host,
                "posture": posture,
                "saw_http": saw_http,
                "saw_https": saw_https,
                "example_urls": list(data["example_urls"]),
            }
        )

    return results


def summarize_tech_stack(httpx_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a de-duplicated tech stack overview from httpx findings.

    Expects httpx findings to include:
      - "tech": list[str] or str
      - "webserver": str (optional)

    Returns a single 'summary' finding like:
    {
      "tool": "tech_stack_summary",
      "technologies": [...],
      "servers": [...]
    }
    """
    tech_set = set()
    server_set = set()

    for f in httpx_findings:
        # tech may be a list or a string depending on how httpx was configured/version
        techs = f.get("tech") or []
        if isinstance(techs, str):
            techs = [techs]
        for t in techs:
            t = str(t).strip()
            if t:
                tech_set.add(t)

        server = f.get("webserver")
        if server:
            server_set.add(str(server).strip())

    return {
        "tool": "tech_stack_summary",
        "technologies": sorted(tech_set),
        "servers": sorted(server_set),
    }
