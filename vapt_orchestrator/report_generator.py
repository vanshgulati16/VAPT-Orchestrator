# vapt_orchestrator/report_generator.py

from typing import List, Dict, Any
import json

def _split(findings):
    out = {}
    for f in findings:
        out.setdefault(f.get("tool","unknown"), []).append(f)
    return out

def esc(s):
    return ("" if s is None else str(s)).replace("<","&lt;").replace(">","&gt;")


# ---------------------------------------------------------
# MARKDOWN
# ---------------------------------------------------------
def generate_markdown_report(target, findings, summary, ts, plan, tools):
    by = _split(findings)

    md = [
        "# VAPT Report",
        f"- Target: `{target}`",
        f"- Timestamp: `{ts}`",
        "",
        "## Mind Map",
    ]

    mindmaps = by.get("mindmap") or []
    if mindmaps:
        md.append("```markdown")
        md.append(mindmaps[0].get("markmap_markdown", ""))
        md.append("```")
    else:
        md.append("_Mindmap not generated (run with --mind-map to enable)._")

    md.append("\n## Executive Summary\n")
    md.append(summary or "_No summary_")

    return "\n".join(md)


# ---------------------------------------------------------
# HTML WITH MARKMAP AUTORENDER
# ---------------------------------------------------------
def generate_html_report(target, findings, summary, ts, plan, tools):

    by = _split(findings)
    mindmaps = by.get("mindmap") or []
    markmap_md = mindmaps[0].get("markmap_markdown", "") if mindmaps else ""

    html = []
    html.append("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>VAPT Report</title>
<!-- Markmap browser bundle: provides window.markmap.{Transformer, Markmap} -->
<script src="https://cdn.jsdelivr.net/npm/markmap-lib@0.15.7/dist/browser/index.min.js"></script>
<style>
body { font-family: Inter, sans-serif; padding:20px; }
.tabs { display:flex; gap:.5rem; margin-bottom:1rem; }
.tab { padding:.5rem .7rem; background:#eee; cursor:pointer; border-radius:.4rem; }
.tab.active { background:#0ea5e9; color:#fff; }
.section { display:none; }
.section.active { display:block; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; vertical-align: top; }
th { background: #f3f4f6; text-align: left; }
tr:nth-child(even) { background: #f9fafb; }
code { background:#f3f4f6; padding:0.1rem 0.25rem; border-radius:0.25rem; }
</style>
</head>
<body>
""")

    # Tabs
    html.append("""
<div class="tabs">
  <div class="tab active" data-tab="mind">Mind Map</div>
  <div class="tab" data-tab="summary">Summary</div>
  <div class="tab" data-tab="findings">Findings</div>
</div>
""")

    # ------------------------- MINDMAP TAB -------------------------
    html.append("<div id='mindmap' class='section active'>")

    if not markmap_md:
        html.append("<p><em>No mindmap generated (run with --mind-map to enable).</em></p>")
    else:
        # Show raw markdown as a fallback, and attempt to render an interactive Markmap
        # using the markmap-lib browser bundle. If JS fails, the markdown is still visible.
        html.append("""
<div style="width:100%; height:100%; min-height:800px;">
  <pre id="mindmap-pre" style="white-space:pre-wrap; font-size:0.85rem;">""" + esc(markmap_md) + """</pre>
  <textarea id="mindmap-md" style="display:none;">""" + esc(markmap_md) + """</textarea>
  <svg id="markmap-svg" style="width:100%; height:1000px;"></svg>
</div>

<script>
window.addEventListener("DOMContentLoaded", () => {
  const mdEl = document.getElementById("mindmap-md");
  const preEl = document.getElementById("mindmap-pre");
  if (!mdEl || !window.markmap) return;
  const md = mdEl.value;
  try {
    const { Transformer, Markmap } = window.markmap;
    const transformer = new Transformer();
    const { root } = transformer.transform(md); // transform markdown to tree
    Markmap.create("#markmap-svg", null, root);
    if (preEl) preEl.style.display = "none";
  } catch (e) {
    // On error, just leave the raw markdown visible as a fallback
    console && console.error && console.error("Markmap render failed:", e);
  }
});
</script>
""")

    html.append("</div>")


    # Summary tab
    html.append("<div id='summary' class='section'>")
    html.append("<h2>Executive Summary</h2>")
    html.append("<p>" + esc(summary or "_No summary_") + "</p>")
    html.append("</div>")

    # ------------------------- FINDINGS TAB -------------------------
    html.append("<div id='findings' class='section'>")
    html.append(f"<h2>Findings for {esc(target)}</h2>")

    # Show per-tool tables, excluding the synthetic mindmap entry itself.
    for tool_name, items in by.items():
        if tool_name == "mindmap":
            continue
        if not items:
            continue

        html.append(f"<h3>{esc(tool_name.title())} ({len(items)})</h3>")

        # Collect all keys used by this tool's findings (excluding 'tool')
        cols = []
        seen = set()
        for it in items:
            for k in it.keys():
                if k == "tool":
                    continue
                if k not in seen:
                    seen.add(k)
                    cols.append(k)

        if not cols:
            # Fallback: just dump JSON if no simple columns
            html.append("<pre><code>" + esc(json.dumps(items, indent=2)) + "</code></pre>")
            continue

        # Render table header
        html.append("<table>")
        html.append("<thead><tr>")
        for c in cols:
            html.append(f"<th>{esc(c)}</th>")
        html.append("</tr></thead>")

        # Rows
        html.append("<tbody>")
        for it in items:
            html.append("<tr>")
            for c in cols:
                v = it.get(c, "")
                if isinstance(v, (dict, list)):
                    cell = json.dumps(v, indent=2)
                else:
                    cell = str(v)
                html.append("<td><code>" + esc(cell) + "</code></td>")
            html.append("</tr>")
        html.append("</tbody></table>")

    if len(by.keys() - {"mindmap"}) == 0:
        html.append("<p><em>No other tool findings were recorded.</em></p>")

    html.append("</div>")

    # Tab switching
    html.append("""
<script>
document.querySelectorAll('.tab').forEach(t=>{
  t.onclick = ()=>{
    document.querySelectorAll('.tab').forEach(a=>a.classList.remove('active'));
    t.classList.add('active');
    let id = t.dataset.tab;
    document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
    document.getElementById(id).classList.add('active');
  };
});
</script>
""")

    html.append("</body></html>")
    return "\n".join(html)

