# main.py

import argparse
from vapt_orchestrator.orchestrator import VAPTOrchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VAPT Orchestrator - AI-assisted security scanning wrapper."
    )

    # Mutually exclusive: either --target or --targets-file
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        help="Single target (IP, domain, or URL).",
    )
    target_group.add_argument(
        "--targets-file",
        help="File containing multiple targets (one per line). Lines starting with # are ignored.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional explicit Markdown report output (only valid for single-target mode).",
    )

    # Environment flags
    env_group = parser.add_mutually_exclusive_group()
    env_group.add_argument("--prod", action="store_true", help="Mark scan as production.")
    env_group.add_argument("--stage", action="store_true", help="Mark scan as staging.")

    # Profile presets
    parser.add_argument(
        "--profile",
        choices=["web-recon", "infra", "full"],
        help="Optional scan profile preset.",
    )

    # Plan-only preview
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Only show toolchain plan. Do not run tools.",
    )

    # Tool overrides
    parser.add_argument("--use-nmap", action="store_true")
    parser.add_argument("--no-nmap", action="store_true")

    parser.add_argument("--use-nuclei", action="store_true")
    parser.add_argument("--no-nuclei", action="store_true")

    parser.add_argument("--use-subfinder", action="store_true")
    parser.add_argument("--no-subfinder", action="store_true")

    parser.add_argument("--use-httpx", action="store_true")
    parser.add_argument("--no-httpx", action="store_true")

    parser.add_argument("--use-ffuf", action="store_true")
    parser.add_argument("--no-ffuf", action="store_true")

    return parser.parse_args()


def build_tool_overrides(args: argparse.Namespace) -> dict:
    overrides = {}
    if args.use_nmap: overrides["use_nmap"] = True
    if args.no_nmap: overrides["use_nmap"] = False

    if args.use_nuclei: overrides["use_nuclei"] = True
    if args.no_nuclei: overrides["use_nuclei"] = False

    if args.use_subfinder: overrides["use_subfinder"] = True
    if args.no_subfinder: overrides["use_subfinder"] = False

    if args.use_httpx: overrides["use_httpx"] = True
    if args.no_httpx: overrides["use_httpx"] = False

    if args.use_ffuf: overrides["use_ffuf"] = True
    if args.no_ffuf: overrides["use_ffuf"] = False

    return overrides


def load_targets(args: argparse.Namespace) -> list[str]:
    """Load single or multi-target list."""
    if args.targets_file:
        targets = []
        with open(args.targets_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append(line)
        if not targets:
            raise SystemExit(f"[!] No valid targets found in {args.targets_file}")
        return targets
    return [args.target]


def main() -> None:
    args = parse_args()

    # Resolve environment
    if args.prod:
        environment = "prod"
    elif args.stage:
        environment = "stage"
    else:
        environment = None  # orchestrator converts None → "dev" label

    tool_overrides = build_tool_overrides(args)
    targets = load_targets(args)

    orchestrator = VAPTOrchestrator()

    # If user passes -o with multi-target, warn and ignore
    if args.output and len(targets) > 1:
        print("[!] Warning: --output ignored in multi-target mode.")
        output_path = None
    else:
        output_path = args.output

    # Run each target
    for i, target in enumerate(targets, start=1):
        print(f"\n=== [{i}/{len(targets)}] Running assessment for {target} ===")

        orchestrator.run_assessment(
            target=target,
            output_path=output_path,
            profile=args.profile,
            environment=environment,
            tool_overrides=tool_overrides,
            plan_only=args.plan_only,
        )


if __name__ == "__main__":
    main()
