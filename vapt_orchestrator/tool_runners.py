# vapt_orchestrator/tool_runners.py
import subprocess
from pathlib import Path
from typing import Optional
import shutil


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


def run_nmap_basic(target: str, output_dir: str = "tmp") -> str:
    """
    Runs a basic nmap TCP scan against the target and returns the XML output as a string.
    Requires `nmap` to be installed on the system.

    NOTE: Use only against targets you are explicitly authorized to test.
    """

    # 1) Check if nmap is available
    ensure_tool_available("nmap")

    # 2) Prepare output
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_file = Path(output_dir) / f"nmap_{target}.xml"

    cmd = [
        "nmap",
        "-sV",                      # service version detection
        "-T4",                      # faster timing template
        "-oX", str(output_file),    # XML output
        target,
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        # We don't immediately fail, but we give a clear message
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
