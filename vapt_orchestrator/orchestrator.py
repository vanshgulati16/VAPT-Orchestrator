# vapt_orchestrator/orchestrator.py

from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import re

from .tool_runners import (
    run_nmap_basic, run_nuclei_basic, run_subfinder_domains,
    run_httpx_single, run_httpx_from_file, run_ffuf_dir
)
from .parsers import (
    parse_nmap_xml, parse_nuclei_json, parse_subfinder_list,
    parse_httpx_jsonl, parse_ffuf_json
)
from .llm_client import LLMClient
from .report_generator import generate_markdown_report, generate_html_report
from .web_analysis import summarize_https_posture, summarize_tech_stack
from .web_headers import analyze_security_headers
from .mindmap_builder import build_markmap_markdown


def _extract_host(u): return urlparse(u).hostname or u
def _safe(v): return re.sub(r"[^A-Za-z0-9_.-]", "_", v)


class VAPTOrchestrator:
    def __init__(self, reports_dir="reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.llm = LLMClient()

    def run_assessment(
        self, target, output_path=None, profile=None, environment=None,
        tool_overrides=None, plan_only=False,
        mind_map=False, mind_map_max_pages=150, mind_map_max_depth=2
    ):
        print(f"[+] Starting assessment: {target}")

        host = _extract_host(target)
        plan = self.llm.plan_toolchain(target=target)
        plan["environment"] = environment or "dev"
        if profile: plan["profile"] = profile

        # Apply plan/defaults
        use_subfinder = plan.get("use_subfinder", True)
        use_httpx = plan.get("use_httpx", True)
        use_nmap = plan.get("use_nmap", True)
        use_nuclei = plan.get("use_nuclei", True)
        use_ffuf = plan.get("use_ffuf", False)
        sev = plan.get("nuclei_severities", ["medium", "high", "critical"])

        # CLI overrides
        if tool_overrides:
            for k, v in tool_overrides.items():
                key = k.replace("use_", "")
                locals()[key] = v

        findings = []
        tool_summaries = []

        # ---------------- MINDMAP ----------------
        if mind_map:
            try:
                print("[+] Building mindmap (Markmap)…")
                mm = build_markmap_markdown(
                    start_url=target,
                    max_pages=mind_map_max_pages,
                    max_depth=mind_map_max_depth,
                )
                findings.append(mm)
                tool_summaries.append(
                    f"Mindmap generated (pages={mind_map_max_pages}, depth={mind_map_max_depth})"
                )
                print("[✓] Mindmap completed.")
            except Exception as e:
                print(f"[!] Mindmap failed: {e}")


        # ---------- Subfinder ----------
        sub_file = None
        if use_subfinder:
            try:
                print("[+] Subfinder...")
                sub_file = run_subfinder_domains(host)
                subs = parse_subfinder_list(sub_file)
                findings.extend(subs)
                tool_summaries.append(f"Subfinder discovered {len(subs)} subdomains.")
            except:
                pass

        # ---------- httpx ----------
        httpx_data = []
        if use_httpx:
            try:
                httpx_file = run_httpx_from_file(sub_file) if sub_file else run_httpx_single(target)
                httpx_data = parse_httpx_jsonl(httpx_file)
                findings.extend(httpx_data)
            except:
                pass

        # ---------- Web Analysis ----------
        if httpx_data:
            try: findings.extend(summarize_https_posture(httpx_data))
            except: pass

            try:
                ts = summarize_tech_stack(httpx_data)
                if ts.get("servers") or ts.get("technologies"):
                    findings.append(ts)
            except: pass

            try: findings.extend(analyze_security_headers(httpx_data))
            except: pass

        # ---------- Nmap ----------
        if use_nmap:
            try:
                xml = run_nmap_basic(host)
                findings.extend(parse_nmap_xml(xml))
            except:
                pass

        # ---------- Nuclei ----------
        if use_nuclei:
            try:
                nf = run_nuclei_basic(target, sev)
                if nf:
                    findings.extend(parse_nuclei_json(nf))
            except:
                pass

        # ---------- FFUF ----------
        if use_ffuf:
            try:
                ff = run_ffuf_dir(target)
                findings.extend(parse_ffuf_json(ff))
            except:
                pass

        # ---------- LLM Summary ----------
        summary = self.llm.summarize_findings(target, findings)

        # ---------- Write Reports ----------
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base = Path(output_path).with_suffix("") if output_path else self.reports_dir / (_safe(target) + "-" + ts)

        md_file = base.with_suffix(".md")
        html_file = base.with_suffix(".html")

        md_file.write_text(generate_markdown_report(target, findings, summary, ts, plan, tool_summaries))
        html_file.write_text(generate_html_report(target, findings, summary, ts, plan, tool_summaries))

        print("[+] Markdown:", md_file)
        print("[+] HTML:", html_file)
        return str(md_file)
