import os
import json
from typing import List, Dict, Any

from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables from .env
load_dotenv()


class LLMClient:
    """
    Wrapper around Google Gemini for:
    - planning which tools to run
    - summarizing scan findings
    """

    def __init__(
        self,
        model_name: str = "gemini-2.5-flash",
    ) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY not found. Make sure it's set in your environment or .env file."
            )

        genai.configure(api_key=api_key)
        self.model_name = model_name
        self.model = genai.GenerativeModel(model_name)

    # -------- Toolchain planning --------

    def plan_toolchain(self, target: str) -> Dict[str, Any]:
        """
        Ask Gemini to decide which tools to run for a given target.
        Returns a dict like:
        {
          "use_nmap": true,
          "use_nuclei": true,
          "use_subfinder": true,
          "use_httpx": true,
          "use_ffuf": false,
          "use_xsstrike": false,
          "use_gittools": false,
          "nuclei_severities": ["medium","high","critical"],
          "rationale": "..."
        }
        """
        prompt = f"""
You are an experienced VAPT automation engineer.

You are helping to plan an automated scan for the target: "{target}".

Available tools:

1) "nmap"
   - Basic TCP port scan with service detection.
   - Good for IPs / hosts / infrastructure.

2) "nuclei"
   - HTTP template-based vulnerability scanner.
   - Works best on HTTP/HTTPS targets.

3) "subfinder"
   - Passive subdomain discovery.
   - Useful when the target is a domain and broad recon is allowed.

4) "httpx"
   - HTTP probe for alive hosts / web services.
   - Often used after subfinder or on a single URL/host.

5) "ffuf"
   - Directory / parameter brute forcing on a base URL containing 'FUZZ'.
   - Requires a wordlist to be configured separately.
   - Use it when directory/content discovery is likely valuable.

Return ONLY valid JSON, no extra text, in the following format:

{{
  "use_nmap": true,
  "use_nuclei": true,
  "use_subfinder": true,
  "use_httpx": true,
  "use_ffuf": false,
  "use_xsstrike": false,
  "use_gittools": false,
  "nuclei_severities": ["medium", "high", "critical"],
  "rationale": "short explanation of why you chose these tools"
}}

Guidelines:
- For bare IPs / hosts, nmap is almost always useful.
- For domains and web apps, consider subfinder + httpx + nuclei.
- Use ffuf only if directory brute forcing makes sense (and keep it optional).
- Use xsstrike only when the target is a single web URL with query parameters.
- Use gittools only if the target looks like it might expose .git or is an explicit .git URL.
"""

        try:
            response = self.model.generate_content(prompt)
            text = getattr(response, "text", "").strip()
            if not text:
                raise ValueError("Empty response from LLM for planning.")
            plan = self._extract_json(text)

            # sane defaults if fields missing
            plan.setdefault("use_nmap", True)
            plan.setdefault("use_nuclei", True)
            plan.setdefault("use_subfinder", False)
            plan.setdefault("use_httpx", False)
            plan.setdefault("use_ffuf", False)
            plan.setdefault("nuclei_severities", ["medium", "high", "critical"])
            return plan
        except Exception as e:
            print(f"[!] LLM toolchain planning error for model '{self.model_name}': {e}")
            # Safe minimal default
            return {
                "use_nmap": True,
                "use_nuclei": True,
                "use_subfinder": False,
                "use_httpx": False,
                "use_ffuf": False,
                "use_xsstrike": False,
                "use_gittools": False,
                "nuclei_severities": ["medium", "high", "critical"],
                "rationale": "Fallback default plan used due to LLM error.",
            }

    def _extract_json(self, text: str) -> Dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(text[start : end + 1])
            raise

    # -------- Summary generation --------

    def _build_summary_prompt(self, target: str, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return f"""
You are a security expert.

A basic automated VAPT run was executed against the target `{target}` and **no significant open services or findings were identified**.

Write a short security summary explaining:
- What this means from a risk perspective
- What limitations this automated run may have
- Which follow-up actions or deeper tests could still be relevant

Keep it concise, in 2–4 short paragraphs, targeting a technical but non-expert audience.
"""

        lines = []
        for f in findings[:80]:
            tool = f.get("tool")
            if tool == "nmap":
                lines.append(
                    f"- [nmap] {f.get('host')}:{f.get('port')} ({f.get('protocol')}) → "
                    f"{f.get('service')} {f.get('product') or ''} {f.get('version') or ''}".strip()
                )
            elif tool == "nuclei":
                lines.append(
                    f"- [nuclei] {f.get('host')} → {str(f.get('severity') or '').upper()} "
                    f"{f.get('template_id')}: {f.get('name')} @ {f.get('matched_at')}"
                )
            elif tool == "subfinder":
                lines.append(
                    f"- [subfinder] Discovered subdomain: {f.get('host')} (source: {f.get('source')})"
                )
            elif tool == "httpx":
                lines.append(
                    f"- [httpx] {f.get('url')} → {f.get('status_code')} "
                    f"({f.get('title') or 'no title'})"
                )
            elif tool == "ffuf":
                lines.append(
                    f"- [ffuf] {f.get('url')} → status {f.get('status')}, length {f.get('length')}"
                )
            else:
                lines.append(f"- [{tool}] {f}")

        findings_block = "\n".join(lines)

        return f"""
You are a senior VAPT (Vulnerability Assessment and Penetration Testing) expert.

You are given the consolidated results of an automated scan against the target `{target}`.
Multiple tools may have been used (nmap, nuclei, subfinder, httpx, ffuf, xsstrike, gittools). Here is a compact view of the findings:

{findings_block}

Tasks:
1. Provide a short **executive summary** (2–3 paragraphs) for a technical but non-security-expert stakeholder.
2. Highlight the **key risks** based on open services, web exposures, potential vulnerabilities, and any .git exposures.
3. Suggest **high-level next steps** for deeper testing or hardening, but do NOT invent vulnerabilities that are not implied.
4. Keep the tone professional and concise.

Do not include raw tool output; only summarize the implications and next steps.
"""

    def summarize_findings(self, target: str, findings: List[Dict[str, Any]]) -> str:
        prompt = self._build_summary_prompt(target, findings)

        try:
            response = self.model.generate_content(prompt)
            summary = getattr(response, "text", None)
            if not summary:
                raise ValueError("LLM response did not contain text.")
            return summary.strip()
        except Exception as e:
            msg = str(e)
            print(f"[!] LLM error for model '{self.model_name}': {msg}")
            return self._fallback_summary(target, findings)

    def _fallback_summary(self, target: str, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return (
                f"No significant findings were identified on target `{target}` during this basic automated run.\n\n"
                "From a network-exposure standpoint, this likely reduces the externally visible attack surface; "
                "however, it does not guarantee the absence of vulnerabilities. Additional testing such as:\n"
                "- Web application testing\n"
                "- Authenticated internal scans\n"
                "- Configuration and hardening reviews\n"
                "may still be necessary depending on the environment and threat model."
            )

        lines = [
            f"A basic automated assessment was performed against `{target}` and the following notable items were identified:\n"
        ]

        for f in findings:
            tool = f.get("tool")
            if tool == "nmap":
                lines.append(
                    f"- [nmap] {f.get('host')}:{f.get('port')} ({f.get('protocol')}) "
                    f"→ {f.get('service')} {f.get('product') or ''} {f.get('version') or ''}".strip()
                )
            elif tool == "nuclei":
                lines.append(
                    f"- [nuclei] {f.get('host')} → {str(f.get('severity') or '').upper()} "
                    f"{f.get('template_id')}: {f.get('name')} @ {f.get('matched_at')}"
                )
            elif tool == "subfinder":
                lines.append(
                    f"- [subfinder] Subdomain: {f.get('host')} (source: {f.get('source')})"
                )
            elif tool == "httpx":
                lines.append(
                    f"- [httpx] {f.get('url')} → {f.get('status_code')} ({f.get('title') or 'no title'})"
                )
            elif tool == "ffuf":
                lines.append(
                    f"- [ffuf] {f.get('url')} → status {f.get('status')}, length {f.get('length')}"
                )
            else:
                lines.append(f"- [{tool}] {f}")

        lines.append(
            "\nThese items should be reviewed for:\n"
            "- Patch and version currency\n"
            "- Strong authentication and access control\n"
            "- Reduction or hardening of unnecessary services and endpoints\n"
            "- Protection of sensitive repositories or configuration data\n"
        )
        lines.append(
            "For a more detailed analysis, run additional targeted manual testing against "
            "the most sensitive services, high/critical nuclei findings, suspected XSS vectors, "
            "and any exposed Git repositories."
        )
        return "\n".join(lines)
