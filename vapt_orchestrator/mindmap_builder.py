"""
Mindmap Builder Module — Returns Markmap Markdown
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Tuple

requests.packages.urllib3.disable_warnings()

JS_FUNCTION_REGEX = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\(")
FETCH_REGEX = re.compile(r"fetch\(['\"]([^'\"]+)['\"]")
AXIOS_REGEX = re.compile(r"axios\.(get|post|put|delete)\(['\"]([^'\"]+)['\"]")
XHR_REGEX = re.compile(r"open\(['\"](GET|POST|PUT|DELETE)['\"],\s*['\"]([^'\"]+)['\"]")


def crawl_site(start_url: str, max_pages: int = 200, max_depth: int = 2):
    visited: Set[str] = set()
    pages: Dict[str, Dict] = {}
    external_domains: Set[str] = set()
    js_functions: Set[str] = set()
    api_endpoints: Set[str] = set()

    queue: List[Tuple[str, int]] = [(start_url, 0)]
    domain = urlparse(start_url).netloc

    session = requests.Session()
    session.headers.update({
        "User-Agent": "MindmapCrawler/1.0"
    })

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue

        visited.add(url)
        pages[url] = {"depth": depth, "links": []}

        try:
            resp = session.get(url, timeout=6, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue

        # Internal + external links
        for a in soup.find_all("a", href=True):
            href = a["href"].split("#")[0].strip()
            if not href or href.startswith(("mailto:", "javascript:")):
                continue

            full = urljoin(url, href)
            parsed = urlparse(full)

            if parsed.netloc == domain:
                pages[url]["links"].append(full)
                if full not in visited:
                    queue.append((full, depth + 1))
            else:
                external_domains.add(parsed.netloc)

        # JS files
        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                js_url = urljoin(url, src)
                parsed = urlparse(js_url)
                if parsed.netloc != domain:
                    external_domains.add(parsed.netloc)
                    continue
                try:
                    js_text = session.get(js_url, timeout=4, verify=False).text
                except Exception:
                    continue
            else:
                js_text = s.string or ""

            for m in JS_FUNCTION_REGEX.findall(js_text):
                js_functions.add(m)

            for m in FETCH_REGEX.findall(js_text):
                api_endpoints.add(m)

            for _, endpoint in AXIOS_REGEX.findall(js_text):
                api_endpoints.add(endpoint)

            for _, endpoint in XHR_REGEX.findall(js_text):
                api_endpoints.add(endpoint)

    return pages, external_domains, js_functions, api_endpoints


def build_markmap_markdown(start_url: str, max_pages=200, max_depth=2):
    pages, external, js_funcs, api_calls = crawl_site(start_url, max_pages, max_depth)

    md: List[str] = []
    md.append(f"# Website Mind Map: {start_url}\n")

    md.append("## Pages")
    for url, info in sorted(pages.items(), key=lambda x: x[1]["depth"]):
        indent = "  " * info["depth"]
        md.append(f"{indent}- {url}")

    md.append("\n## External References")
    md.extend(f"- {x}" for x in sorted(external)) if external else md.append("- None")

    md.append("\n## JavaScript Functions")
    md.extend(f"- `{x}()`" for x in sorted(js_funcs)) if js_funcs else md.append("- None")

    md.append("\n## API Endpoints")
    md.extend(f"- `{x}`" for x in sorted(api_calls)) if api_calls else md.append("- None")

    # This structure is consumed by the report generator to render a Markmap mindmap.
    # The key `markmap_markdown` is expected by the reporting code.
    return {
        "tool": "mindmap",
        "markmap_markdown": "\n".join(md),
        "start_url": start_url,
        "max_pages": max_pages,
        "max_depth": max_depth,
    }
