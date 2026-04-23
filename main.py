"""
main.py
Entry point for the LangGraph Threat Intelligence Agent.

Usage:
    python main.py                        # interactive mode
    python main.py --target 8.8.8.8       # single target
    python main.py --target malware.com   # domain
    python main.py --demo                 # runs 3 demo targets
"""

import argparse
import json
import sys
from graph.builder import build_graph

# ── Pretty print helpers ───────────────────────────────────────────────────
COLOURS = {
    "critical": "\033[91m",   # red
    "high":     "\033[91m",   # red
    "medium":   "\033[93m",   # yellow
    "low":      "\033[94m",   # blue
    "clean":    "\033[92m",   # green
    "unknown":  "\033[90m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"

RISK_BARS = {
    "critical": "█████████████████████  CRITICAL",
    "high":     "████████████████       HIGH",
    "medium":   "████████████           MEDIUM",
    "low":      "████████               LOW",
    "clean":    "███                    CLEAN",
}


def print_report(report: dict, target: str):
    risk   = report.get("risk_level", "unknown")
    score  = report.get("risk_score", "?")
    colour = COLOURS.get(risk, "\033[0m")

    print(f"\n{'━'*60}")
    print(f"{BOLD}  Threat Intelligence Report{RESET}")
    print(f"  Target   : {target}")
    print(f"  Risk     : {colour}{RISK_BARS.get(risk, risk.upper())}{RESET}")
    print(f"  Score    : {colour}{score}/100{RESET}")
    print(f"\n  Summary")
    print(f"  {report.get('summary', 'No summary')}")

    indicators = report.get("indicators", [])
    if indicators:
        print(f"\n  Indicators")
        for indicator in indicators:
            print(f"    • {indicator}")

    print(f"\n  Recommendation")
    print(f"    {report.get('recommendation', 'No recommendation')}")
    print(f"{'━'*60}\n")


def run_investigation(target: str, agent):
    """Run a single investigation and print the result."""
    print(f"\n{'='*60}")
    print(f"{BOLD}  Investigating: {target}{RESET}")
    print(f"{'='*60}")

    initial_state = {
        "target":             target,
        "messages":           [],
        "virustotal_result":  {},
        "abuseipdb_result":   {},
        "dns_result":         {},
        "input_valid":        False,
        "input_error":        "",
        "tools_called":       [],
        "loop_count":         0,
        "next_action":        "",
        "risk_report":        {},
    }

    final_state = agent.invoke(initial_state)

    # Handle invalid input
    if not final_state.get("input_valid", False):
        print(f"\n[ERROR] Invalid target: {final_state.get('input_error', 'unknown')}")
        return

    report = final_state.get("risk_report", {})
    if report:
        print_report(report, target)
    else:
        print("\n[ERROR] No report generated")

    return final_state


def main():
    parser = argparse.ArgumentParser(description="LangGraph Threat Intelligence Agent")
    parser.add_argument("--target", type=str, help="IP or domain to investigate")
    parser.add_argument("--demo",   action="store_true", help="Run demo investigations")
    parser.add_argument("--json",   action="store_true", help="Output raw JSON report")
    args = parser.parse_args()

    print(f"\n{BOLD}LangGraph Threat Intelligence Agent{RESET}")
    print("Building agent graph...")
    agent = build_graph()
    print("Agent ready.\n")

    if args.demo:
        # Demo targets — uses mock data if no API keys set
        demo_targets = [
            "8.8.8.8",          # Google DNS — should be clean
            "malware.com",      # should be high/critical (mocked)
            "192.168.1.1",      # private IP — should be blocked by guardrail
        ]
        for target in demo_targets:
            state = run_investigation(target, agent)
            if args.json and state and state.get("risk_report"):
                print(json.dumps(state["risk_report"], indent=2))

    elif args.target:
        state = run_investigation(args.target, agent)
        if args.json and state and state.get("risk_report"):
            print(json.dumps(state["risk_report"], indent=2))

    else:
        # Interactive mode
        print("Enter a target to investigate (IP or domain), or 'quit' to exit.")
        while True:
            try:
                target = input("\nTarget: ").strip()
                if target.lower() in ("quit", "exit", "q"):
                    break
                if target:
                    run_investigation(target, agent)
            except KeyboardInterrupt:
                print("\nExiting.")
                break


if __name__ == "__main__":
    main()