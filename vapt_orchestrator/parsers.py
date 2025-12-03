# vapt_orchestrator/parsers.py
from typing import List, Dict, Any
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses Nmap XML output into a list of normalized finding dicts.

    Each finding example:
    {
        "tool": "nmap",
        "host": "192.168.1.10",
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "state": "open",
        "product": "OpenSSH",
        "version": "8.2p1"
    }
    """
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

            # Only store open ports
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
