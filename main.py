# main.py
import argparse
from vapt_orchestrator.orchestrator import VAPTOrchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-assisted VAPT orchestrator (PoC). For authorized testing only."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target hostname or IP (only for systems you are authorized to test).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional custom output report path (default: reports/<target>-<timestamp>.md)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    orchestrator = VAPTOrchestrator()

    try:
        report_path = orchestrator.run_assessment(
            target=args.target,
            output_path=args.output,
        )
        print(f"[+] Assessment complete. Report saved to: {report_path}")
    except Exception as e:
        # Generic friendly error; avoids full stack trace in normal usage
        print(f"[!] Assessment failed: {e}")


if __name__ == "__main__":
    main()
