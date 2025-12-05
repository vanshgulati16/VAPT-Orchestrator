# vapt_orchestrator/orchestrator.py

from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import re

from .tool_runners import (
    run_nmap_basic,
    run_nuclei_basic,
    run_subfinder_domains,
    run_httpx_single,
    run_httpx_from_file,
    run_ffuf_dir,
)
from .parsers import (
    parse_nmap_xml,
    parse_nuclei_json,
    parse_subfinder_list,
    parse_httpx_jsonl,
    parse_ffuf_json,
)
from .llm_client import LLMClient
from .report_generator import (
    generate_markdown_report,
    generate_html_report,
)
from .web_analysis import summarize_https_posture, summarize_tech_stack
from .web_headers import analyze_security_headers



def _extract_host(target: str) -> str:
    """
    For tools that want just a domain/host (no scheme/path),
    extract a clean host from a URL or return the original string.
    """
    parsed = urlparse(target)
    if parsed.scheme:
        # handles https://zomato.com, https://zomato.com/path, etc.
        return parsed.hostname or target
    return target


def _safe_basename(value: str) -> str:
    """
    Turn a target string (which may contain : / ? etc.) into a safe filename base.
    Example: "https://zomato.com" -> "https___zomato.com"
             "127.0.0.1"         -> "127.0.0.1"
    """
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return safe or "report"


class VAPTOrchestrator:
    """
    High-level controller that:
    - Asks LLM to plan which tools to run
    - Applies profile presets and CLI overrides
    - Executes tools (nmap, nuclei, subfinder, httpx, ffuf)
    - Aggregates and parses results
    - Performs web analysis (HTTPS posture, tech stack) based on httpx
    - Asks LLM to summarize findings
    - Writes Markdown + HTML reports
    """

    def __init__(self, reports_dir: str = "reports") -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.llm = LLMClient()

    def run_assessment(
        self,
        target: str,
        output_path: Optional[str] = None,
        profile: Optional[str] = None,
        environment: Optional[str] = None,
        tool_overrides: Optional[Dict[str, bool]] = None,
        plan_only: bool = False,
    ) -> str:
        print(f"[+] Starting assessment for target: {target}")

        # Split once so all tools use consistent host/url
        host_only = _extract_host(target)   # e.g. "zomato.com" from "https://zomato.com"
        url_for_http = target               # still use full URL for httpx/nuclei if provided

        # 1) Ask LLM to plan which tools to run
        print("[+] Asking LLM to plan toolchain...")
        plan = self.llm.plan_toolchain(target=target)

        # Inject environment/profile into plan for reporting
        plan["environment"] = environment or plan.get("environment") or "dev"
        if profile:
            plan["profile"] = profile

        # Base flags from LLM plan
        use_nmap = bool(plan.get("use_nmap", True))
        use_nuclei = bool(plan.get("use_nuclei", True))
        use_subfinder = bool(plan.get("use_subfinder", False))
        use_httpx = bool(plan.get("use_httpx", False))
        use_ffuf = bool(plan.get("use_ffuf", False))
        nuclei_severities = plan.get("nuclei_severities", ["medium", "high", "critical"])

        # 1a) Apply profile presets (before CLI overrides)
        if profile == "web-recon":
            # Focused on web-facing: recon + httpx + nuclei
            use_nmap = False
            use_subfinder = True
            use_httpx = True
            use_nuclei = True
            use_ffuf = False
            nuclei_severities = ["info", "low", "medium", "high", "critical"]
        elif profile == "infra":
            # Internal/infra: ports + vuln templates
            use_nmap = True
            use_subfinder = False
            use_httpx = False
            use_nuclei = True
            use_ffuf = False
        elif profile == "full":
            # Everything turned on
            use_nmap = True
            use_subfinder = True
            use_httpx = True
            use_nuclei = True
            use_ffuf = True

        # 1b) Apply explicit CLI overrides (highest priority)
        overrides = tool_overrides or {}
        if "use_nmap" in overrides:
            use_nmap = bool(overrides["use_nmap"])
        if "use_nuclei" in overrides:
            use_nuclei = bool(overrides["use_nuclei"])
        if "use_subfinder" in overrides:
            use_subfinder = bool(overrides["use_subfinder"])
        if "use_httpx" in overrides:
            use_httpx = bool(overrides["use_httpx"])
        if "use_ffuf" in overrides:
            use_ffuf = bool(overrides["use_ffuf"])

        # Reflect final decisions back into plan for reporting
        plan["use_nmap"] = use_nmap
        plan["use_nuclei"] = use_nuclei
        plan["use_subfinder"] = use_subfinder
        plan["use_httpx"] = use_httpx
        plan["use_ffuf"] = use_ffuf
        plan["nuclei_severities"] = nuclei_severities

        print(
            "[+] Final toolchain configuration:\n"
            f"    environment={plan.get('environment')}, profile={plan.get('profile', 'auto')}\n"
            f"    nmap={use_nmap}, nuclei={use_nuclei}, subfinder={use_subfinder}, httpx={use_httpx}, ffuf={use_ffuf}\n"
            f"    nuclei_severities={nuclei_severities}"
        )

        if plan_only:
            print("[+] Plan-only mode enabled; no tools will be executed.")
            return ""

        all_findings: List[Dict[str, Any]] = []
        tool_summaries: List[str] = []

        # 2) Run tools according to the final configuration

        # ---------------- Subfinder (recon) – TXT file + parsed findings ----------------
        subfinder_file_path: Optional[str] = None
        if use_subfinder:
            try:
                print("[+] Running subfinder (subdomain discovery)...")
                subfinder_file_path = run_subfinder_domains(host_only)
                print(f"[+] Subfinder output saved to: {subfinder_file_path}")

                print("[+] Parsing subfinder results...")
                sub_findings = parse_subfinder_list(subfinder_file_path)
                all_findings.extend(sub_findings)
                tool_summaries.append(
                    f"Subfinder for passive subdomain discovery on {host_only} "
                    f"(results written to {subfinder_file_path})."
                )

                print(f"[+] Subfinder discovered {len(sub_findings)} subdomains.")
            except Exception as e:
                print(f"[!] Subfinder failed: {e}")
                subfinder_file_path = None

        # ---------------- httpx (probe) – list file if subfinder used, else single URL ----------------
        httpx_findings: List[Dict[str, Any]] = []
        if use_httpx:
            try:
                if subfinder_file_path:
                    print("[+] Running httpx (HTTP probe on subfinder TXT file)...")
                    httpx_jsonl = run_httpx_from_file(subfinder_file_path)
                    tool_summaries.append(
                        "httpx for HTTP probing of subfinder-discovered subdomains (filtered to 200/302)."
                    )
                else:
                    print("[+] Running httpx (HTTP probe on single target)...")
                    httpx_jsonl = run_httpx_single(url_for_http)
                    tool_summaries.append(
                        "httpx for HTTP probing of the primary target (filtered to 200/302)."
                    )

                print("[+] Parsing httpx results...")
                httpx_findings = parse_httpx_jsonl(httpx_jsonl)
                all_findings.extend(httpx_findings)
                print(f"[+] httpx identified {len(httpx_findings)} live endpoints (200/302).")
            except Exception as e:
                print(f"[!] httpx failed: {e}")

        # ---------------- Web analysis based on httpx (HTTPS posture, tech stack) ----------------
        if httpx_findings:
            try:
                print("[+] Analyzing HTTPS posture from httpx findings...")
                https_posture = summarize_https_posture(httpx_findings)
                all_findings.extend(https_posture)
                tool_summaries.append("HTTPS posture analysis derived from httpx results.")
                print(f"[+] HTTPS posture summary generated for {len(https_posture)} hosts.")
            except Exception as e:
                print(f"[!] HTTPS posture analysis failed: {e}")

            try:
                print("[+] Summarizing web tech stack from httpx findings...")
                tech_stack_summary = summarize_tech_stack(httpx_findings)
                # Only add if something meaningful is present
                if tech_stack_summary.get("technologies") or tech_stack_summary.get("servers"):
                    all_findings.append(tech_stack_summary)
                    tool_summaries.append("Tech stack summary derived from httpx results.")
                    print(
                        f"[+] Tech stack summary includes "
                        f"{len(tech_stack_summary.get('technologies', []))} technologies and "
                        f"{len(tech_stack_summary.get('servers', []))} servers."
                    )
            except Exception as e:
                print(f"[!] Tech stack summarization failed: {e}")

            try:
                print("[+] Fetching sample URLs to analyze security headers (HSTS, CSP, cookies, etc.)...")
                header_findings = analyze_security_headers(httpx_findings)
                all_findings.extend(header_findings)
                tool_summaries.append(
                    "Security header analysis (HSTS, CSP, XFO, X-XSS-Protection, Referrer-Policy, cookies) "
                    "on a sample of live httpx endpoints."
                )
                print(f"[+] Security headers analyzed for {len(header_findings)} URLs.")
            except Exception as e:
                print(f"[!] Security header analysis failed: {e}")


        # ---------------- Nmap (network) – host/IP only ----------------
        if use_nmap:
            try:
                print("[+] Running nmap (basic TCP scan)...")
                nmap_output_xml = run_nmap_basic(host_only)
                print("[+] Parsing nmap results...")
                nmap_findings = parse_nmap_xml(nmap_output_xml)
                all_findings.extend(nmap_findings)
                tool_summaries.append(
                    f"Nmap basic TCP scan with service detection (-sV, -T4) on {host_only}."
                )
            except Exception as e:
                print(f"[!] Nmap failed: {e}")

        # ---------------- Nuclei (HTTP vuln templates) – URL-based ----------------
        if use_nuclei:
            try:
                print("[+] Running nuclei (HTTP template-based scan)...")
                nuclei_output_jsonl = run_nuclei_basic(
                    target=url_for_http,
                    severities=nuclei_severities,
                )
                if nuclei_output_jsonl:
                    print("[+] Parsing nuclei results...")
                    nuclei_findings = parse_nuclei_json(nuclei_output_jsonl)
                    all_findings.extend(nuclei_findings)
                else:
                    print("[+] No nuclei output to parse.")
                tool_summaries.append(
                    f"Nuclei scan with severities: {', '.join(nuclei_severities)}."
                )
            except Exception as e:
                print(f"[!] Nuclei failed: {e}")

        # ---------------- ffuf (dir brute forcing) – optional, wordlist via env ----------------
        if use_ffuf:
            try:
                print("[+] Running ffuf (directory fuzzing)...")
                ffuf_json = run_ffuf_dir(base_url=url_for_http)
                print("[+] Parsing ffuf results...")
                ffuf_findings = parse_ffuf_json(ffuf_json)
                all_findings.extend(ffuf_findings)
                tool_summaries.append(
                    "ffuf directory fuzzing using wordlist from FFUF_WORDLIST env var (404 filtered)."
                )
            except Exception as e:
                print(f"[!] ffuf failed: {e}")

        # 3) Ask LLM to summarize & prioritize
        print("[+] Asking LLM to summarize findings...")
        llm_summary = self.llm.summarize_findings(
            target=target,
            findings=all_findings,
        )

        # 4) Generate reports (Markdown + HTML) with a SAFE filename base
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        safe_target = _safe_basename(target)

        if output_path:
            md_path = Path(output_path)
            base = md_path.with_suffix("")
        else:
            base = self.reports_dir / f"{safe_target}-{timestamp}"
            md_path = base.with_suffix(".md")

        html_path = base.with_suffix(".html")

        print("[+] Generating Markdown report...")
        report_markdown = generate_markdown_report(
            target=target,
            findings=all_findings,
            llm_summary=llm_summary,
            timestamp=timestamp,
            plan=plan,
            tool_summaries=tool_summaries,
        )
        md_path.write_text(report_markdown, encoding="utf-8")

        print("[+] Generating HTML report...")
        report_html = generate_html_report(
            target=target,
            findings=all_findings,
            llm_summary=llm_summary,
            timestamp=timestamp,
            plan=plan,
            tool_summaries=tool_summaries,
        )
        html_path.write_text(report_html, encoding="utf-8")

        print(f"[+] Markdown report: {md_path}")
        print(f"[+] HTML report:     {html_path}")
        print(f"[+] Assessment complete. Report saved to: {md_path}")

        return str(md_path)
