# vapt_orchestrator/report_generator.py
from typing import List, Dict, Any


def generate_markdown_report(
    target: str,
    findings: List[Dict[str, Any]],
    llm_summary: str,
    timestamp: str,
) -> str:
    """
    Generates a simple Markdown report from the findings and LLM summary.
    """

    header = f"# VAPT Assessment Report\n\n"
    meta = f"- **Target**: `{target}`\n- **Timestamp (UTC)**: `{timestamp}`\n\n"
    disclaimer = (
        "> **Disclaimer:** This report is generated for authorized security testing only.\n\n"
    )

    summary_section = "## Executive Summary\n\n" + llm_summary + "\n\n"

    details_section = "## Technical Details (Nmap Findings)\n\n"
    if not findings:
        details_section += "_No open ports or services identified in this basic scan._\n"
    else:
        details_section += "| Host | Port | Protocol | Service | Product | Version |\n"
        details_section += "|------|------|----------|---------|---------|---------|\n"
        for f in findings:
            details_section += (
                f"| {f.get('host')} | {f.get('port')} | {f.get('protocol')} | "
                f"{f.get('service')} | {f.get('product') or ''} | {f.get('version') or ''} |\n"
            )

    return header + meta + disclaimer + summary_section + details_section
