# vapt_orchestrator/outdated_components.py

from typing import List, Dict, Any

def analyze_outdated_components(httpx_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Placeholder for outdated component detection.
    Currently extracts naive version fingerprints if present in httpx fields.
    You can replace with real logic later.
    """
    components = []

    for item in httpx_findings:
        techs = item.get("technologies") or []
        url = item.get("url")

        for tech in techs:
            # Very basic pattern: technology "name version"
            parts = tech.split(" ")
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                components.append({
                    "name": name,
                    "version": version,
                    "example_url": url,
                    "source": tech,
                })

    return {
        "tool": "outdated_components",
        "components": components,
    }
