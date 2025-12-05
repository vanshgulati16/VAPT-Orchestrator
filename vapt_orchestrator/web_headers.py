# vapt_orchestrator/web_headers.py

from typing import List, Dict, Any
from urllib.parse import urlparse

import requests


def _analyze_cookies(set_cookie_values: List[str]) -> Dict[str, Any]:
    """Very simple cookie flag analysis across all Set-Cookie headers."""
    any_secure = False
    any_httponly = False
    any_samesite = False

    for raw in set_cookie_values:
        lower = raw.lower()
        if "secure" in lower:
            any_secure = True
        if "httponly" in lower:
            any_httponly = True
        if "samesite" in lower:
            any_samesite = True

    return {
        "any_cookie_secure": any_secure,
        "any_cookie_httponly": any_httponly,
        "any_cookie_samesite": any_samesite,
    }


def _extract_header_flags(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Extract important security header information.
    """
    hsts = headers.get("Strict-Transport-Security")
    csp = headers.get("Content-Security-Policy")
    xfo = headers.get("X-Frame-Options")
    xxss = headers.get("X-XSS-Protection")
    refpol = headers.get("Referrer-Policy")

    # Collect all Set-Cookie headers (requests exposes it in .headers as merged string; we can split)
    set_cookie_raw = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            # Some servers send a single big header with multiple cookies separated by comma or newline.
            # We don't try to perfectly parse; we just scan for flags.
            parts = str(v).split(",")
            set_cookie_raw.extend(parts)

    cookie_flags = _analyze_cookies(set_cookie_raw)

    return {
        "has_hsts": bool(hsts),
        "hsts_value": hsts or "",
        "has_csp": bool(csp),
        "csp_value": csp or "",
        "has_xfo": bool(xfo),
        "xfo_value": xfo or "",
        "has_xxss": bool(xxss),
        "xxss_value": xxss or "",
        "has_referrer_policy": bool(refpol),
        "referrer_policy_value": refpol or "",
        **cookie_flags,
    }


def analyze_security_headers(
    httpx_findings: List[Dict[str, Any]],
    max_urls: int = 15,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Take httpx findings (live endpoints) and fetch a small sample
    to analyze security-related headers.

    Produces one finding per URL like:
    {
      "tool": "security_headers",
      "url": "...",
      "host": "...",
      "status_code": int,
      ...header flags...
    }
    """
    if not httpx_findings:
        return []

    # Prefer HTTPS URLs first, then HTTP, to keep it meaningful
    https_urls: List[str] = []
    http_urls: List[str] = []

    for f in httpx_findings:
        url = f.get("url") or ""
        if url.startswith("https://"):
            https_urls.append(url)
        elif url.startswith("http://"):
            http_urls.append(url)

    # Deduplicate while preserving order
    def unique(seq: List[str]) -> List[str]:
        seen = set()
        out = []
        for item in seq:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    https_urls = unique(https_urls)
    http_urls = unique(http_urls)

    # Sample up to max_urls total
    urls_to_check = (https_urls + http_urls)[:max_urls]

    results: List[Dict[str, Any]] = []

    for url in urls_to_check:
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "VAPT-Orchestrator/1.0"},
                verify=True,  # we expect HTTPS to be valid; failures will be noted
            )
        except Exception as e:
            parsed = urlparse(url)
            results.append(
                {
                    "tool": "security_headers",
                    "url": url,
                    "host": parsed.hostname or url,
                    "status_code": None,
                    "error": str(e),
                    "has_hsts": False,
                    "has_csp": False,
                    "has_xfo": False,
                    "has_xxss": False,
                    "has_referrer_policy": False,
                    "any_cookie_secure": False,
                    "any_cookie_httponly": False,
                    "any_cookie_samesite": False,
                }
            )
            continue

        hdr_flags = _extract_header_flags(resp.headers)
        parsed = urlparse(resp.url or url)

        result = {
            "tool": "security_headers",
            "url": resp.url or url,
            "host": parsed.hostname or url,
            "status_code": resp.status_code,
            "error": "",
            **hdr_flags,
        }
        results.append(result)

    return results
