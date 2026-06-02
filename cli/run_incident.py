import argparse
from pathlib import Path

from agents.orchestrator_agent import OrchestratorAgent


def main():
    parser = argparse.ArgumentParser(
        description="Run SOC AI incident workflow from a log string or file."
    )

    parser.add_argument(
        "--log",
        help="Raw log text to analyze."
    )

    parser.add_argument(
        "--file",
        help="Path to a log file to analyze."
    )

    args = parser.parse_args()

    if not args.log and not args.file:
        raise SystemExit("Provide either --log or --file")

    if args.file:
        log_text = Path(args.file).read_text(encoding="utf-8")
    else:
        log_text = args.log

    agent = OrchestratorAgent()
    result = agent.process_log(log_text)

    print("\nSOC AI Workflow Complete\n")
    print("Event Type:", result["soc"]["event_type"])
    print("Severity:", result["soc"]["severity"])
    print("MITRE Technique:", result["mitre"]["technique_id"], result["mitre"]["technique"])

    if result["threat_intel"]:
        print("Threat Intel:")
        for item in result["threat_intel"]:
            print("-", item["indicator"], item["indicator_type"], item["risk_level"])

    print("\nReport generated:")
    print("reports/markdown/orchestrated_incident.md")


if __name__ == "__main__":
    main()
