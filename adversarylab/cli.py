"""CI gate: run a campaign locally and exit non-zero when the attack-success rate exceeds a limit."""
from __future__ import annotations

import argparse
import json
import secrets
import sys

from . import core
from .evaluators import generate_sarif_report

TARGETS = ["vulnerable", "hardened", "llm", "agent-unprotected", "agent-sandboxed"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="adversarylab", description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--goal", action="append", default=[], help="attack goal (repeatable)")
    parser.add_argument("--max-asr", type=float, default=0.0, help="highest acceptable attack-success rate")
    parser.add_argument("--deadline", type=float, default=120.0, help="wall-clock limit in seconds")
    parser.add_argument("--concurrency", type=int, default=4, help="number of concurrent worker threads")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--sarif", type=str, default=None, help="write SARIF report to specified file path")
    parser.add_argument("--export", type=str, default=None, help="export full report JSON to file path")
    args = parser.parse_args(argv)

    try:
        if args.target.startswith("agent-"):
            report = core.run_injection_scenario(sandboxed=args.target == "agent-sandboxed")
        else:
            if not args.goal:
                parser.error("--goal is required for this target")
            canary = "CANARY-" + secrets.token_hex(4)
            report = core.run_campaign(
                core.build_target(args.target, canary),
                args.goal,
                canary,
                max_workers=args.concurrency,
                deadline_s=args.deadline,
            )
    except core.ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except core.CampaignTimeout as exc:
        print(f"timeout: {exc}", file=sys.stderr)
        return 3

    asr = report["attack_success_rate"]

    # Write SARIF if requested
    if args.sarif:
        sarif_doc = generate_sarif_report(1, args.target, report.get("results", []))
        with open(args.sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)

    # Write full JSON export if requested
    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if args.json:
        print(json.dumps({k: report[k] for k in ("total", "leaks", "attack_success_rate")}))
    else:
        print(
            f"{args.target}: {report['leaks']}/{report['total']} attacks succeeded "
            f"(ASR {asr:.0%}, limit {args.max_asr:.0%})"
        )

    return 1 if asr > args.max_asr else 0


if __name__ == "__main__":
    sys.exit(main())
