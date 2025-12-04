from typing import List, Dict, Any
import xml.etree.ElementTree as ET
import json
from pathlib import Path



# ------------- NMAP -------------

def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    root = ET.fromstring(xml_content)
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        host_addr = addr_el.get("addr", "")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port_id = port_el.get("portid")
            protocol = port_el.get("protocol", "tcp")

            state_el = port_el.find("state")
            service_el = port_el.find("service")

            state = state_el.get("state") if state_el is not None else "unknown"
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else ""
            version = service_el.get("version") if service_el is not None else ""

            if state != "open":
                continue

            findings.append(
                {
                    "tool": "nmap",
                    "host": host_addr,
                    "port": int(port_id) if port_id else None,
                    "protocol": protocol,
                    "service": service_name,
                    "state": state,
                    "product": product,
                    "version": version,
                }
            )
    return findings


# ------------- NUCLEI -------------

def parse_nuclei_json(jsonl_content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for line in jsonl_content.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {}) or {}

        findings.append(
            {
                "tool": "nuclei",
                "template_id": obj.get("templateID"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "host": obj.get("host"),
                "matched_at": obj.get("matched-at") or obj.get("matched"),
                "type": obj.get("type"),
                "timestamp": obj.get("timestamp"),
            }
        )

    return findings


# ------------- SUBFINDER -------------

def parse_subfinder_jsonl(jsonl_content: str) -> List[Dict[str, Any]]:
    """
    Subfinder JSONL lines usually look like:
    {"host":"sub.example.com","source":"crtsh"}
    """
    findings: List[Dict[str, Any]] = []

    for line in jsonl_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = obj.get("host") or obj.get("subdomain") or obj.get("ip")
        if not host:
            continue

        findings.append(
            {
                "tool": "subfinder",
                "host": host,
                "source": obj.get("source"),
            }
        )
    return findings


# ------------- HTTPX -------------

def parse_httpx_jsonl(jsonl_content: str) -> List[Dict[str, Any]]:
    """
    httpx JSONL lines contain at least:
    - url
    - status_code
    - title (optional)
    - webserver / tech (optional)

    We ONLY keep responses with status_code 200 or 302.
    """
    findings: List[Dict[str, Any]] = []

    for line in jsonl_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = obj.get("url")
        if not url:
            continue

        status = obj.get("status_code")
        try:
            status_int = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_int = None

        # Only keep 200 and 302
        if status_int not in (200, 302):
            continue

        findings.append(
            {
                "tool": "httpx",
                "url": url,
                "status_code": status_int,
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
                "tech": obj.get("tech"),
                "content_length": obj.get("content_length"),
            }
        )
    return findings

def parse_subfinder_list(path: str) -> List[Dict[str, Any]]:
    """
    Parses a TXT file produced by subfinder (-o), one subdomain per line,
    into normalized findings.
    """
    findings: List[Dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return findings

    for line in p.read_text(encoding="utf-8").splitlines():
        host = line.strip()
        if not host:
            continue
        findings.append(
            {
                "tool": "subfinder",
                "host": host,
                "source": "subfinder-txt",
            }
        )
    return findings



# ------------- FFUF -------------

def parse_ffuf_json(json_content: str) -> List[Dict[str, Any]]:
    """
    ffuf JSON output typically looks like:
    {
      "results": [
        {
          "url": "...",
          "status": 200,
          "length": 1234,
          "words": 10,
          "lines": 20
        },
        ...
      ]
    }
    """
    findings: List[Dict[str, Any]] = []

    try:
        obj = json.loads(json_content)
    except json.JSONDecodeError:
        return findings

    results = obj.get("results") or []
    for r in results:
        findings.append(
            {
                "tool": "ffuf",
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "words": r.get("words"),
                "lines": r.get("lines"),
            }
        )

    return findings


