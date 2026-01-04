# vapt_orchestrator/web_crawler.py

from typing import Dict, Any, List, Set, Tuple
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from collections import deque
import time

USER_AGENT = "VAPT-Orchestrator-MindMap/1.0"

def _same_domain(a: str, b: str) -> bool:
    try:
        return urlparse(a).hostname == urlparse(b).hostname
    except Exception:
        return False

def build_mind_map(
    start_url: str,
    max_pages: int = 200,
    max_depth: int = 2,
    timeout: float = 5.0,
    delay: float = 0.1,
    respect_same_host: bool = True,
) -> Dict[str, Any]:
    queued: deque[Tuple[str,int]] = deque()
    queued.append((start_url, 0))
    seen: Set[str] = set([start_url])
    nodes_index: Dict[str,int] = {start_url: 0}
    nodes: List[Dict[str, Any]] = [{"id": 0, "url": start_url, "title": ""}]
    edges: List[Dict[str,int]] = []

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    while queued and len(nodes) < max_pages:
        url, depth = queued.popleft()
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            content = resp.text
            final_url = resp.url
        except Exception as e:
            idx = nodes_index.get(url)
            if idx is None:
                idx = len(nodes)
                nodes_index[url] = idx
                nodes.append({"id": idx, "url": url, "title": f"ERROR: {e}"})
            continue

        if final_url != url and final_url not in nodes_index and (not respect_same_host or _same_domain(start_url, final_url)):
            idx = len(nodes)
            nodes_index[final_url] = idx
            nodes.append({"id": idx, "url": final_url, "title": ""})
            edges.append({"source": nodes_index[url], "target": idx})

        soup = BeautifulSoup(content, "html.parser")
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""
        node_idx = nodes_index.get(final_url) or nodes_index.get(url)
        if node_idx is None:
            node_idx = len(nodes)
            nodes_index[final_url] = node_idx
            nodes.append({"id": node_idx, "url": final_url, "title": title})
        else:
            nodes[node_idx]["title"] = title or nodes[node_idx].get("title", "")

        anchors = set()
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if href.startswith("mailto:") or href.startswith("javascript:") or href.startswith("tel:"):
                continue
            try:
                joined = urljoin(final_url, href.split('#')[0])
            except Exception:
                continue
            if not joined:
                continue
            if respect_same_host and not _same_domain(start_url, joined):
                continue
            anchors.add(joined)

        for target in anchors:
            if target not in nodes_index:
                tidx = len(nodes)
                nodes_index[target] = tidx
                nodes.append({"id": tidx, "url": target, "title": ""})
            edges.append({"source": nodes_index[final_url], "target": nodes_index[target]})
            if target not in seen and depth + 1 <= max_depth and len(nodes) < max_pages:
                seen.add(target)
                queued.append((target, depth + 1))

        time.sleep(delay)

    return {
        "tool": "mind_map",
        "start_url": start_url,
        "nodes": nodes,
        "edges": edges,
    }
