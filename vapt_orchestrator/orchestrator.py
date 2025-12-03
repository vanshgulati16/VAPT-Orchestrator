# vapt_orchestrator/orchestrator.py
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from .tool_runners import run_nmap_basic
from .parsers import parse_nmap_xml
from .llm_client import LLMClient
from .report_generator import generate_markdown_report


class VAPTOrchestrator:
    """
    High-level controller that:
    - Plans which tools to run (via LLM in future)
    - Executes tools
    - Aggregates and parses results
    - Asks LLM to summarize findings
    - Writes final report
    """

    def __init__(self, reports_dir: str = "reports") -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.llm = LLMClient()

    def run_assessment(self, target: str, output_path: Optional[str] = None) -> str:
        print(f"[+] Starting assessment for target: {target}")

        # 1) (Future) ask LLM to plan the scan;
        # for now we just run basic nmap
        print("[+] Running nmap (basic TCP scan)...")
        nmap_output_xml = run_nmap_basic(target)

        # 2) Parse tool outputs into a normalized findings list
        print("[+] Parsing nmap results...")
        nmap_findings = parse_nmap_xml(nmap_output_xml)

        all_findings: List[Dict[str, Any]] = []
        all_findings.extend(nmap_findings)

        # 3) Ask LLM to summarize & prioritize
        print("[+] Asking LLM to summarize findings...")
        llm_summary = self.llm.summarize_findings(
            target=target,
            findings=all_findings,
        )

        # 4) Generate Markdown report
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        if output_path:
            report_path = Path(output_path)
        else:
            report_path = self.reports_dir / f"{target}-{timestamp}.md"

        print("[+] Generating Markdown report...")
        report_markdown = generate_markdown_report(
            target=target,
            findings=all_findings,
            llm_summary=llm_summary,
            timestamp=timestamp,
        )

        report_path.write_text(report_markdown, encoding="utf-8")
        return str(report_path)
