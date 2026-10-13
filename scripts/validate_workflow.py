#!/usr/bin/env python3
"""Fail CI when the exported n8n workflow regains unsafe shell patterns."""
from pathlib import Path
import json
import sys

repo_root = Path(__file__).resolve().parents[1]
workflow = repo_root / "automation n8n" / "Agent_u01 6.json"
data = json.loads(workflow.read_text(encoding="utf-8"))
errors = []

for node in data.get("nodes", []):
    name = node.get("name", "unnamed node")
    parameters = node.get("parameters", {})

    if node.get("type") == "n8n-nodes-base.webhook":
        if parameters.get("authentication") != "headerAuth":
            errors.append(f"{name}: webhook must require Header Auth")
        if "httpHeaderAuth" not in node.get("credentials", {}):
            errors.append(f"{name}: Header Auth credential reference is missing")

    if node.get("type") == "n8n-nodes-base.httpRequest" and "/api/scan-results" in str(parameters.get("url", "")):
        if parameters.get("genericAuthType") != "httpHeaderAuth":
            errors.append(f"{name}: result delivery must use Header Auth")
        if "httpHeaderAuth" not in node.get("credentials", {}):
            errors.append(f"{name}: result-delivery Header Auth credential is missing")

    command = parameters.get("command")
    if not isinstance(command, str):
        continue

    if "sudo -S" in command or 'echo "kali"' in command:
        errors.append(f"{name}: embedded sudo password or stdin password use")
    if "$json.output.cmd" in command or "$json.output.cmd0" in command:
        errors.append(f"{name}: AI-generated command execution")
    if "{{ $json.Target }}" in command:
        errors.append(f"{name}: unvalidated Target interpolation")
    if "{{ $json['Ports?'] }}" in command:
        errors.append(f"{name}: unvalidated Ports interpolation")

for script in (repo_root / "linux bash").glob("*.sh"):
    text = script.read_text(encoding="utf-8")
    if "authorized_keys" in text or "BGSAVE" in text:
        errors.append(f"{script.name}: persistence/write technique is not allowed")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Workflow policy check passed")
