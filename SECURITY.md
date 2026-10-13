# Security Policy

## Authorized use only

This project performs active security reconnaissance. Run it only against systems you own or targets for which you have explicit written authorization. Some scripts are aggressive and may disrupt services.

## Reporting a vulnerability

Use this repository's **Security → Report a vulnerability** workflow. Do not open a public issue containing credentials, exploitable production targets, private scan evidence, or personal data.

Include sanitized reproduction steps, the affected component, impact, and a proposed mitigation when possible.

## Deployment requirements

Before exposing the system outside a local lab:

- authenticate `/send` and `/api/scan-results`;
- authorize and allowlist scan targets;
- validate target IP addresses and ports before invoking any shell command;
- isolate Kali workers and apply CPU, memory, network, and time limits;
- protect n8n, SSH, Gemini, and OpenAI credentials in credential stores;
- disable development consoles and unnecessary H2 features;
- persist jobs and evidence in an access-controlled database;
- keep raw evidence for human verification of AI-generated findings;
- add audit logging, rate limits, cancellation, and approval gates.

## AI safety boundary

LLM output is analysis, not proof. Findings must be traceable to scanner evidence and reviewed by a qualified human before remediation or reporting.
