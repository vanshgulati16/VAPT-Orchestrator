import os
import subprocess
from pathlib import Path
from typing import List, Optional
import shutil


def _safe_name(value: str) -> str:
    """Sanitize a string so it can be used safely in filenames."""
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in value)


def ensure_tool_available(tool_name: str) -> None:
    """
    Check if a command-line tool is available in PATH.
    Raises RuntimeError with a clear message if not found.
    """
    if shutil.which(tool_name) is None:
        raise RuntimeError(
            f"Required tool '{tool_name}' is not installed or not in PATH. "
            f"Please install '{tool_name}' and try again."
        )


# ---------------- NMAP ----------------

def run_nmap_basic(target: str, output_dir: str = "tmp") -> str:
    """
    Runs a basic nmap TCP scan against the target and returns the XML output as a string.
    Requires `nmap` to be installed on the system.

    NOTE: Use only against targets you are explicitly authorized to test.
    """
    ensure_tool_available("nmap")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_target = _safe_name(target)
    output_file = Path(output_dir) / f"nmap_{safe_target}.xml"

    cmd = [
        "nmap",
        "-sV",
        "-T4",
        "-oX", str(output_file),
        target,
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] Nmap returned a non-zero exit code.")
        if result.stderr:
            print("[!] Nmap stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "Nmap did not produce the expected XML output file. "
            "Check the target, parameters, and permissions."
        )

    return output_file.read_text(encoding="utf-8")


# ---------------- NUCLEI ----------------

def run_nuclei_basic(
    target: str,
    output_dir: str = "tmp",
    severities: Optional[List[str]] = None,
) -> str:
    """
    Runs a basic nuclei scan against the target and returns the JSONL output as a string.
    Requires `nuclei` to be installed.

    NOTE:
    - `target` should be something nuclei can understand (e.g. https://example.com or an IP).
    - Use only against targets you are explicitly authorized to test.
    """
    ensure_tool_available("nuclei")

    if not severities:
        severities = ["medium", "high", "critical"]

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_target = _safe_name(target)
    output_file = Path(output_dir) / f"nuclei_{safe_target}.jsonl"

    severity_arg = ",".join(severities)

    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity_arg,
        "-jsonl",
        "-o", str(output_file),
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] Nuclei returned a non-zero exit code.")
        if result.stderr:
            print("[!] Nuclei stderr:")
            print(result.stderr)

    if not output_file.exists():
        print(
            "[!] Nuclei did not produce the expected JSON output file. "
            "Continuing without nuclei findings for this run."
        )
    # Return empty string if nothing was produced
        return ""

    return output_file.read_text(encoding="utf-8")


# ---------------- SUBFINDER ----------------

def run_subfinder_domains(domain: str, output_dir: str = "tmp") -> str:
    """
    Runs subfinder for a single domain and writes subdomains to a TXT file
    (one per line). Returns the path to that TXT file.

    NOTE: Use only against authorized targets.
    """
    ensure_tool_available("subfinder")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_domain = _safe_name(domain)
    output_file = Path(output_dir) / f"subfinder_{safe_domain}.txt"

    cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-o", str(output_file),  # TXT file: one subdomain/line
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] Subfinder returned a non-zero exit code.")
        if result.stderr:
            print("[!] Subfinder stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "Subfinder did not produce the expected TXT output file. "
            "Check the domain, parameters, and permissions."
        )

    return str(output_file)


# ---------------- HTTPX ----------------

def run_httpx_single(target: str, output_dir: str = "tmp") -> str:
    """
    Runs httpx against a single target URL/host and returns JSONL output as string.
    Uses -j (JSONL) + -o.

    `target` can be https://sub.example.com or just sub.example.com.

    NOTE: Use only against authorized targets.
    """
    ensure_tool_available("httpx")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_target = _safe_name(target)
    output_file = Path(output_dir) / f"httpx_{safe_target}.jsonl"

    cmd = [
        "httpx",
        "-u", target,
        "-j",                # JSONL output
        "-o", str(output_file),
        "-silent",
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] httpx returned a non-zero exit code.")
        if result.stderr:
            print("[!] httpx stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "httpx did not produce the expected JSONL output file. "
            "Check the target, parameters, and permissions."
        )

    return output_file.read_text(encoding="utf-8")


def run_httpx_list(targets: List[str], output_dir: str = "tmp") -> str:
    """
    Runs httpx against a list of targets and returns JSONL output as string.
    Uses:
      - input file with one target per line
      - -j (JSONL) + -o for output

    NOTE: Use only against authorized targets.
    """
    ensure_tool_available("httpx")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    input_file = Path(output_dir) / "httpx_targets.txt"
    output_file = Path(output_dir) / "httpx_targets.jsonl"

    # Write targets to input file
    with input_file.open("w", encoding="utf-8") as f:
        for t in targets:
            t = str(t).strip()
            if t:
                f.write(t + "\n")

    cmd = [
        "httpx",
        "-l", str(input_file),
        "-j",
        "-o", str(output_file),
        "-silent",
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] httpx (list) returned a non-zero exit code.")
        if result.stderr:
            print("[!] httpx stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "httpx (list) did not produce the expected JSONL output file. "
            "Check the targets, parameters, and permissions."
        )

    return output_file.read_text(encoding="utf-8")

def run_httpx_from_file(input_file: str, output_dir: str = "tmp") -> str:
    """
    Runs httpx against a list of targets provided via -l <input_file>
    and returns JSONL output as string.

    The input file must contain one target (domain/URL) per line.
    """
    ensure_tool_available("httpx")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_name = _safe_name(Path(input_file).stem)
    output_file = Path(output_dir) / f"httpx_{safe_name}.jsonl"

    cmd = [
        "httpx",
        "-l", input_file,
        "-j",
        "-o", str(output_file),
        "-silent",
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] httpx (file) returned a non-zero exit code.")
        if result.stderr:
            print("[!] httpx stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "httpx (file) did not produce the expected JSONL output file. "
            "Check the targets file, parameters, and permissions."
        )

    return output_file.read_text(encoding="utf-8")



# ---------------- FFUF ----------------

def run_ffuf_dir(
    base_url: str,
    output_dir: str = "tmp",
    wordlist_env_var: str = "FFUF_WORDLIST",
) -> str:
    """
    Runs ffuf for simple directory brute forcing on base_url like:
    http://example.com/FUZZ

    Requires:
    - ffuf installed
    - an environment variable (default FFUF_WORDLIST) pointing to a wordlist path

    Returns ffuf JSON output as a string.
    """
    ensure_tool_available("ffuf")

    wordlist_path = os.getenv(wordlist_env_var)
    if not wordlist_path:
        raise RuntimeError(
            f"FFUF wordlist env var '{wordlist_env_var}' not set. "
            f"Set it to a valid wordlist path to use ffuf."
        )
    if not Path(wordlist_path).exists():
        raise RuntimeError(
            f"FFUF wordlist path '{wordlist_path}' does not exist. "
            "Update the environment variable or path."
        )

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_url = _safe_name(base_url)
    output_file = Path(output_dir) / f"ffuf_{safe_url}.json"

    # Example:
    # ffuf -u http://example.com/FUZZ -w wordlist.txt -o results.json -of json
    cmd = [
        "ffuf",
        "-u", base_url,
        "-w", wordlist_path,
        "-o", str(output_file),
        "-of", "json",
        "-fc", "404",
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("[!] ffuf returned a non-zero exit code.")
        if result.stderr:
            print("[!] ffuf stderr:")
            print(result.stderr)

    if not output_file.exists():
        raise RuntimeError(
            "ffuf did not produce the expected JSON output file. "
            "Check the URL, parameters, and wordlist."
        )

    return output_file.read_text(encoding="utf-8")
