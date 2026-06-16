import argparse
from pathlib import Path

from agents.orchestrator_agent import OrchestratorAgent


def main():
    parser = argparse.ArgumentParser(
        description="Run SOC AI incident workflow against each line in a log file."
    )

    parser.add_argument("--file", required=True, help="Path to log file.")

    args = parser.parse_args()

    path = Path(args.file)

    if not path.exists():
        raise SystemExit(f"Log file not found: {path}")

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    agent = OrchestratorAgent()

    print(f"Processing {len(lines)} log entries...\n")

    for index, line in enumerate(lines, start=1):
        result = agent.process_log(line)

        print(f"=== Event {index} ===")
        print("Log:", line)
        print("Event Type:", result["soc"]["event_type"])
        print("Severity:", result["soc"]["severity"])
        print("MITRE:", result["mitre"]["technique_id"], result["mitre"]["technique"])

        if result["threat_intel"]:
            for item in result["threat_intel"]:
                print("Indicator:", item["indicator"], item["indicator_type"], item["risk_level"])

        print()

    print("Batch processing complete.")


if __name__ == "__main__":
    main()
