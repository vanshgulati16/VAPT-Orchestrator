from typing import List, Dict, Any


def _md_escape(value: Any) -> str:
    """
    Escape characters that break Markdown tables, e.g. '|'.
    """
    return ("" if value is None else str(value)).replace("|", "\\|")


def _split_findings_by_tool(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        tool = f.get("tool", "unknown")
        by_tool.setdefault(tool, []).append(f)
    return by_tool


def _bucket_nuclei_by_severity(nuclei_findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "OTHER": [],
    }
    for f in nuclei_findings:
        sev = (f.get("severity") or "").upper()
        if sev in buckets:
            buckets[sev].append(f)
        else:
            buckets["OTHER"].append(f)
    return buckets


def generate_markdown_report(
    target: str,
    findings: List[Dict[str, Any]],
    llm_summary: str,
    timestamp: str,
    plan: Dict[str, Any],
    tool_summaries: List[str],
) -> str:
    """
    Generates a Markdown report with:
    - meta info
    - scan plan & tools
    - Recon tables (Subfinder + httpx)
    - Web posture & tech stack sections
    - Technical tables (Nmap + Nuclei + ffuf)
    - Risk summary by severity (from Nuclei)
    - LLM narrative summary at the end
    """

    header = "# VAPT Assessment Report\n\n"
    environment = plan.get("environment", "dev")
    profile = plan.get("profile", "auto")
    meta = (
        f"- **Target**: `{target}`\n"
        f"- **Environment**: `{environment}`\n"
        f"- **Profile**: `{profile}`\n"
        f"- **Timestamp (UTC)**: `{timestamp}`\n"
        f"- **Tools planned by AI**: "
        f"Nmap: {'Yes' if plan.get('use_nmap', True) else 'No'}, "
        f"Nuclei: {'Yes' if plan.get('use_nuclei', False) else 'No'}, "
        f"Subfinder: {'Yes' if plan.get('use_subfinder', False) else 'No'}, "
        f"httpx: {'Yes' if plan.get('use_httpx', False) else 'No'}, "
        f"ffuf: {'Yes' if plan.get('use_ffuf', False) else 'No'}\n\n"
    )
    disclaimer = (
        "> **Disclaimer:** This report is generated for authorized security testing only. "
        "Automated results may contain false positives and should be validated.\n\n"
    )

    plan_section = "## Scan Plan & Toolchain\n\n"
    if tool_summaries:
        plan_section += "The following tools and configurations were used:\n\n"
        for s in tool_summaries:
            plan_section += f"- {s}\n"
        plan_section += "\n"
    rationale = plan.get("rationale")
    if rationale:
        plan_section += f"**AI Rationale:** {rationale}\n\n"

    by_tool = _split_findings_by_tool(findings)

    # ---------------- Recon Section (Subfinder + httpx) ----------------
    recon_section = "## Reconnaissance\n\n"

    # Subfinder
    subfinder_findings = by_tool.get("subfinder", [])
    recon_section += "### Subfinder (Subdomain Discovery)\n\n"
    if not subfinder_findings:
        recon_section += "_No subdomains were discovered by Subfinder in this run._\n\n"
    else:
        recon_section += "| Subdomain | Source |\n"
        recon_section += "|-----------|--------|\n"
        for f in subfinder_findings:
            recon_section += f"| `{f.get('host')}` | {f.get('source') or ''} |\n"
        recon_section += "\n"

    # httpx
    httpx_findings = by_tool.get("httpx", [])
    recon_section += "### httpx (Live HTTP Services)\n\n"
    if not httpx_findings:
        recon_section += "_No live HTTP(S) endpoints (200/302) were identified by httpx in this run._\n\n"
    else:
        recon_section += "| URL | Status | Title | Webserver | Content Length |\n"
        recon_section += "|-----|--------|-------|-----------|----------------|\n"
        for f in httpx_findings:
            recon_section += (
                f"| `{f.get('url')}` | {f.get('status_code')} | "
                f"{_md_escape(f.get('title'))} | "
                f"{_md_escape(f.get('webserver'))} | "
                f"{f.get('content_length') or ''} |\n"
            )
        recon_section += "\n"

    # ---------------- Web posture & tech stack ----------------
    posture_section = "## Web Security Posture & Tech Stack\n\n"

    # HTTPS posture
    https_posture_findings = by_tool.get("https_posture", [])
    posture_section += "### HTTPS Posture (derived from httpx)\n\n"
    if not https_posture_findings:
        posture_section += "_No HTTPS posture data was derived (likely due to no httpx findings)._\
n\n"
    else:
        posture_section += "| Host | Posture | Saw HTTP | Saw HTTPS | Example URLs |\n"
        posture_section += "|------|---------|----------|-----------|--------------|\n"
        for f in https_posture_findings:
            posture_label = (f.get("posture") or "").replace("_", " ")
            examples = ", ".join(f.get("example_urls") or [])
            posture_section += (
                f"| `{f.get('host')}` | {posture_label} | "
                f"{'Yes' if f.get('saw_http') else 'No'} | "
                f"{'Yes' if f.get('saw_https') else 'No'} | "
                f"{_md_escape(examples)} |\n"
            )
        posture_section += "\n"

    # Tech stack summary
    tech_stack_list = by_tool.get("tech_stack_summary", [])
    posture_section += "### Tech Stack Overview (from httpx)\n\n"
    if not tech_stack_list:
        posture_section += "_No tech stack information was derived from httpx findings._\n\n"
    else:
        summary = tech_stack_list[0]  # we only ever add one summary
        techs = summary.get("technologies") or []
        servers = summary.get("servers") or []
        if not techs and not servers:
            posture_section += "_No tech stack information was derived from httpx findings._\n\n"
        else:
            if servers:
                posture_section += "- **Web Servers:** " + ", ".join(f"`{s}`" for s in servers) + "\n"
            if techs:
                posture_section += "- **Technologies / Frameworks:** " + ", ".join(
                    f"`{t}`" for t in techs
                ) + "\n"
            posture_section += "\n"

    # Secuirty Header summary
    security_section = "## Security Headers Overview\n\n"
    security_header_findings = by_tool.get("security_headers", [])

    if not security_header_findings:
        security_section += "_No security header checks were performed or no data was collected._\n\n"
    else:
        security_section += (
            "| URL | Status | HSTS | CSP | X-Frame-Options | X-XSS-Protection | "
            "Referrer-Policy | Any Secure Cookie | Any HttpOnly Cookie |\n"
        )
        security_section += (
            "|-----|--------|------|-----|-----------------|------------------|"
            "----------------|------------------|---------------------|\n"
        )
        for f in security_header_findings:
            security_section += (
                f"| `{f.get('url')}` | {f.get('status_code') or ''} | "
                f"{'Yes' if f.get('has_hsts') else 'No'} | "
                f"{'Yes' if f.get('has_csp') else 'No'} | "
                f"{'Yes' if f.get('has_xfo') else 'No'} | "
                f"{'Yes' if f.get('has_xxss') else 'No'} | "
                f"{'Yes' if f.get('has_referrer_policy') else 'No'} | "
                f"{'Yes' if f.get('any_cookie_secure') else 'No'} | "
                f"{'Yes' if f.get('any_cookie_httponly') else 'No'} |\n"
            )
        security_section += "\n"

    # ---------------- Technical Details (Nmap + Nuclei + ffuf) ----------------
    details_section = "## Technical Findings\n\n"

    # Nmap section
    nmap_findings = by_tool.get("nmap", [])
    details_section += "### Nmap Findings\n\n"
    if not nmap_findings:
        details_section += "_No open ports were identified by Nmap in this run._\n\n"
    else:
        details_section += "| Host | Port | Protocol | Service | Product | Version |\n"
        details_section += "|------|------|----------|---------|---------|---------|\n"
        for f in nmap_findings:
            details_section += (
                f"| {f.get('host')} | {f.get('port')} | {f.get('protocol')} | "
                f"{f.get('service')} | {f.get('product') or ''} | {f.get('version') or ''} |\n"
            )
        details_section += "\n"

    # Nuclei section (raw table)
    nuclei_findings = by_tool.get("nuclei", [])
    details_section += "### Nuclei Findings\n\n"
    if not nuclei_findings:
        details_section += "_No nuclei findings were recorded in this run._\n\n"
    else:
        details_section += "| Severity | Template ID | Name | Host | Matched At |\n"
        details_section += "|----------|------------|------|------|------------|\n"
        for f in nuclei_findings:
            details_section += (
                f"| {str(f.get('severity') or '').upper()} | {f.get('template_id') or ''} | "
                f"{_md_escape(f.get('name'))} | {f.get('host') or ''} | {f.get('matched_at') or ''} |\n"
            )
        details_section += "\n"

    # ffuf section
    ffuf_findings = by_tool.get("ffuf", [])
    details_section += "### ffuf (Directory/Content Discovery)\n\n"
    if not ffuf_findings:
        details_section += "_No ffuf findings were recorded in this run._\n\n"
    else:
        details_section += "| URL | Status | Length | Words | Lines |\n"
        details_section += "|-----|--------|--------|-------|-------|\n"
        for f in ffuf_findings:
            details_section += (
                f"| `{f.get('url')}` | {f.get('status')} | {f.get('length')} | "
                f"{f.get('words')} | {f.get('lines')} |\n"
            )
        details_section += "\n"

    # ---------------- Risk Summary by Severity (from Nuclei) ----------------
    risk_section = "## Risk Summary by Severity (Nuclei)\n\n"
    if not nuclei_findings:
        risk_section += "_No Nuclei vulnerabilities detected; risk classification not available for this run._\n\n"
    else:
        buckets = _bucket_nuclei_by_severity(nuclei_findings)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"]:
            group = buckets.get(sev, [])
            if not group:
                continue
            risk_section += f"### {sev.title()} ({len(group)})\n\n"
            for f in group[:5]:
                host = f.get("host") or ""
                tid = f.get("template_id") or ""
                name = f.get("name") or ""
                matched = f.get("matched_at") or ""
                risk_section += (
                    f"- `{host}` — **{tid}**: {name}"
                    + (f" (matched at: `{matched}`)" if matched else "")
                    + "\n"
                )
            if len(group) > 5:
                risk_section += f"- _+ {len(group) - 5} more {sev.lower()} findings not listed here._\n"
            risk_section += "\n"

    # ---------------- LLM Executive Summary at the end ----------------
    summary_section = "## Executive Narrative Summary\n\n" + llm_summary.strip() + "\n\n"

    return header + meta + disclaimer + plan_section + recon_section + posture_section + security_section + details_section + risk_section + summary_section


def generate_html_report(
    target: str,
    findings: List[Dict[str, Any]],
    llm_summary: str,
    timestamp: str,
    plan: Dict[str, Any],
    tool_summaries: List[str],
) -> str:
    """
    HTML report with:
    - meta
    - scan plan
    - Recon tables (Subfinder + httpx)
    - Web posture & tech stack
    - Technical tables (Nmap + Nuclei + ffuf)
    - Risk summary by severity
    - LLM narrative summary at the end
    """

    by_tool = _split_findings_by_tool(findings)
    nmap_findings = by_tool.get("nmap", [])
    nuclei_findings = by_tool.get("nuclei", [])
    subfinder_findings = by_tool.get("subfinder", [])
    httpx_findings = by_tool.get("httpx", [])
    ffuf_findings = by_tool.get("ffuf", [])
    https_posture_findings = by_tool.get("https_posture", [])
    tech_stack_list = by_tool.get("tech_stack_summary", [])
    nuclei_buckets = _bucket_nuclei_by_severity(nuclei_findings)
    security_header_findings = by_tool.get("security_headers", [])


    environment = plan.get("environment", "dev")
    profile = plan.get("profile", "auto")
    

    def esc(s: Any) -> str:
        return ("" if s is None else str(s)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html lang='en'>")
    html.append("<head>")
    html.append("<meta charset='utf-8' />")
    html.append(f"<title>VAPT Report - {esc(target)}</title>")
    html.append(
        "<style>"
        "body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; margin: 2rem; }"
        "h1, h2, h3 { color: #111827; }"
        "table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }"
        "th, td { border: 1px solid #e5e7eb; padding: 0.5rem; font-size: 0.9rem; }"
        "th { background: #f3f4f6; text-align: left; }"
        ".meta { font-size: 0.9rem; color: #4b5563; margin-bottom: 1rem; }"
        ".badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-size: 0.75rem; }"
        ".sev-CRITICAL { background: #fee2e2; color: #b91c1c; }"
        ".sev-HIGH { background: #ffedd5; color: #c2410c; }"
        ".sev-MEDIUM { background: #fef9c3; color: #854d0e; }"
        ".sev-LOW { background: #ecfeff; color: #155e75; }"
        "</style>"
    )
    html.append("</head>")
    html.append("<body>")

    # Header + meta
    html.append("<h1>VAPT Assessment Report</h1>")
    html.append("<div class='meta'>")
    html.append(f"<div><strong>Target:</strong> <code>{esc(target)}</code></div>")
    html.append(f"<div><strong>Timestamp (UTC):</strong> <code>{esc(timestamp)}</code></div>")
    html.append(f"<div><strong>Environment:</strong> <code>{esc(environment)}</code></div>")
    html.append(f"<div><strong>Profile:</strong> <code>{esc(profile)}</code></div>")
    html.append(
        f"<div><strong>Tools planned by AI:</strong> "
        f"Nmap: {'Yes' if plan.get('use_nmap', True) else 'No'}, "
        f"Nuclei: {'Yes' if plan.get('use_nuclei', False) else 'No'}, "
        f"Subfinder: {'Yes' if plan.get('use_subfinder', False) else 'No'}, "
        f"httpx: {'Yes' if plan.get('use_httpx', False) else 'No'}, "
        f"ffuf: {'Yes' if plan.get('use_ffuf', False) else 'No'}</div>"
    )
    html.append(
        "<div><strong>Disclaimer:</strong> This report is generated for authorized security testing only. "
        "Automated results may contain false positives and should be validated.</div>"
    )
    html.append("</div>")

    # Plan section
    html.append("<h2>Scan Plan &amp; Toolchain</h2>")
    if tool_summaries:
        html.append("<ul>")
        for s in tool_summaries:
            html.append(f"<li>{esc(s)}</li>")
        html.append("</ul>")
    rationale = plan.get("rationale")
    if rationale:
        html.append(f"<p><strong>AI Rationale:</strong> {esc(rationale)}</p>")

    # ---------------- Recon Section ----------------
    html.append("<h2>Reconnaissance</h2>")

    # Subfinder
    html.append("<h3>Subfinder (Subdomain Discovery)</h3>")
    if not subfinder_findings:
        html.append("<p><em>No subdomains were discovered by Subfinder in this run.</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>Subdomain</th><th>Source</th></tr></thead>")
        html.append("<tbody>")
        for f in subfinder_findings:
            html.append(
                "<tr>"
                f"<td><code>{esc(f.get('host'))}</code></td>"
                f"<td>{esc(f.get('source'))}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # httpx
    html.append("<h3>httpx (Live HTTP Services)</h3>")
    if not httpx_findings:
        html.append("<p><em>No live HTTP(S) endpoints (200/302) were identified by httpx in this run.</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Webserver</th><th>Content Length</th></tr></thead>")
        html.append("<tbody>")
        for f in httpx_findings:
            html.append(
                "<tr>"
                f"<td><code>{esc(f.get('url'))}</code></td>"
                f"<td>{esc(f.get('status_code'))}</td>"
                f"<td>{esc(f.get('title'))}</td>"
                f"<td>{esc(f.get('webserver'))}</td>"
                f"<td>{esc(f.get('content_length'))}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # ---------------- Web posture & tech stack ----------------
    html.append("<h2>Web Security Posture &amp; Tech Stack</h2>")

    # HTTPS posture
    html.append("<h3>HTTPS Posture (derived from httpx)</h3>")
    if not https_posture_findings:
        html.append("<p><em>No HTTPS posture data was derived (likely due to no httpx findings).</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>Host</th><th>Posture</th><th>Saw HTTP</th><th>Saw HTTPS</th><th>Example URLs</th></tr></thead>")
        html.append("<tbody>")
        for f in https_posture_findings:
            posture_label = (f.get("posture") or "").replace("_", " ")
            examples = ", ".join(f.get("example_urls") or [])
            html.append(
                "<tr>"
                f"<td><code>{esc(f.get('host'))}</code></td>"
                f"<td>{esc(posture_label)}</td>"
                f"<td>{'Yes' if f.get('saw_http') else 'No'}</td>"
                f"<td>{'Yes' if f.get('saw_https') else 'No'}</td>"
                f"<td>{esc(examples)}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # Tech stack
    html.append("<h3>Tech Stack Overview (from httpx)</h3>")
    if not tech_stack_list:
        html.append("<p><em>No tech stack information was derived from httpx findings.</em></p>")
    else:
        summary = tech_stack_list[0]
        techs = summary.get("technologies") or []
        servers = summary.get("servers") or []
        if not techs and not servers:
            html.append("<p><em>No tech stack information was derived from httpx findings.</em></p>")
        else:
            if servers:
                html.append(
                    "<p><strong>Web Servers:</strong> "
                    + ", ".join(f"<code>{esc(s)}</code>" for s in servers)
                    + "</p>"
                )
            if techs:
                html.append(
                    "<p><strong>Technologies / Frameworks:</strong> "
                    + ", ".join(f"<code>{esc(t)}</code>" for t in techs)
                    + "</p>"
                )
    
    # ---------------- Security Headers ----------------
    html.append("<h2>Security Headers Overview</h2>")
    if not security_header_findings:
        html.append("<p><em>No security header checks were performed or no data was collected.</em></p>")
    else:
        html.append("<table>")
        html.append(
            "<thead><tr>"
            "<th>URL</th>"
            "<th>Status</th>"
            "<th>HSTS</th>"
            "<th>CSP</th>"
            "<th>X-Frame-Options</th>"
            "<th>X-XSS-Protection</th>"
            "<th>Referrer-Policy</th>"
            "<th>Any Secure Cookie</th>"
            "<th>Any HttpOnly Cookie</th>"
            "</tr></thead>"
        )
        html.append("<tbody>")
        for f in security_header_findings:
            html.append(
                "<tr>"
                f"<td><code>{esc(f.get('url'))}</code></td>"
                f"<td>{esc(f.get('status_code'))}</td>"
                f"<td>{'Yes' if f.get('has_hsts') else 'No'}</td>"
                f"<td>{'Yes' if f.get('has_csp') else 'No'}</td>"
                f"<td>{'Yes' if f.get('has_xfo') else 'No'}</td>"
                f"<td>{'Yes' if f.get('has_xxss') else 'No'}</td>"
                f"<td>{'Yes' if f.get('has_referrer_policy') else 'No'}</td>"
                f"<td>{'Yes' if f.get('any_cookie_secure') else 'No'}</td>"
                f"<td>{'Yes' if f.get('any_cookie_httponly') else 'No'}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")


    # ---------------- Technical Findings ----------------
    html.append("<h2>Technical Findings</h2>")

    # Nmap table
    html.append("<h3>Nmap Findings</h3>")
    if not nmap_findings:
        html.append("<p><em>No open ports were identified by Nmap in this run.</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>")
        html.append("<tbody>")
        for f in nmap_findings:
            html.append(
                "<tr>"
                f"<td>{esc(f.get('host'))}</td>"
                f"<td>{esc(f.get('port'))}</td>"
                f"<td>{esc(f.get('protocol'))}</td>"
                f"<td>{esc(f.get('service'))}</td>"
                f"<td>{esc(f.get('product'))}</td>"
                f"<td>{esc(f.get('version'))}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # Nuclei table
    html.append("<h3>Nuclei Findings</h3>")
    if not nuclei_findings:
        html.append("<p><em>No nuclei findings were recorded in this run.</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>Severity</th><th>Template ID</th><th>Name</th><th>Host</th><th>Matched At</th></tr></thead>")
        html.append("<tbody>")
        for f in nuclei_findings:
            sev = (f.get("severity") or "").upper()
            sev_class = f"sev-{sev}" if sev else ""
            html.append(
                "<tr>"
                f"<td><span class='badge {sev_class}'>{esc(sev or '')}</span></td>"
                f"<td>{esc(f.get('template_id'))}</td>"
                f"<td>{esc(f.get('name'))}</td>"
                f"<td>{esc(f.get('host'))}</td>"
                f"<td>{esc(f.get('matched_at'))}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # ffuf table
    html.append("<h3>ffuf (Directory/Content Discovery)</h3>")
    if not ffuf_findings:
        html.append("<p><em>No ffuf findings were recorded in this run.</em></p>")
    else:
        html.append("<table>")
        html.append("<thead><tr><th>URL</th><th>Status</th><th>Length</th><th>Words</th><th>Lines</th></tr></thead>")
        html.append("<tbody>")
        for f in ffuf_findings:
            html.append(
                "<tr>"
                f"<td><code>{esc(f.get('url'))}</code></td>"
                f"<td>{esc(f.get('status'))}</td>"
                f"<td>{esc(f.get('length'))}</td>"
                f"<td>{esc(f.get('words'))}</td>"
                f"<td>{esc(f.get('lines'))}</td>"
                "</tr>"
            )
        html.append("</tbody></table>")

    # ---------------- Risk Summary by Severity ----------------
    html.append("<h2>Risk Summary by Severity (Nuclei)</h2>")
    if not nuclei_findings:
        html.append("<p><em>No Nuclei vulnerabilities detected; risk classification not available for this run.</em></p>")
    else:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"]:
            group = nuclei_buckets.get(sev, [])
            if not group:
                continue
            html.append(f"<h3>{esc(sev.title())} ({len(group)})</h3>")
            html.append("<ul>")
            for f in group[:5]:
                host = esc(f.get("host") or "")
                tid = esc(f.get("template_id") or "")
                name = esc(f.get("name") or "")
                matched = esc(f.get("matched_at") or "")
                extra = f" (matched at: <code>{matched}</code>)" if matched else ""
                html.append(
                    f"<li><code>{host}</code> — <strong>{tid}</strong>: {name}{extra}</li>"
                )
            if len(group) > 5:
                html.append(
                    f"<li><em>+ {len(group) - 5} more {sev.lower()} findings not listed here.</em></li>"
                )
            html.append("</ul>")

    # ---------------- LLM Executive Summary at the end ----------------
    html.append("<h2>Executive Narrative Summary</h2>")
    for para in llm_summary.split("\n\n"):
        para = para.strip()
        if para:
            html.append(f"<p>{esc(para)}</p>")

    html.append("</body></html>")
    return "\n".join(html)
