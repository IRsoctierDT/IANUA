# Usage Guide

## Activate Environment

source venv/bin/activate

## Run Single Incident Workflow

python cli/run_incident.py --log "Failed password for root from 10.0.0.5 port 22 ssh2"

## Run Batch Processing

python cli/batch_run_incidents.py --file sample-logs/auth_batch.log

## Generate PDF Report

python agents/incident_report_agent.py
python scripts/convert_report_to_pdf.py

## Run Tests

pytest
