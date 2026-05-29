# Security Policy

## Reporting a Security Issue

If you find a security vulnerability in the M365 Assessment Toolkit, please do not open a public GitHub issue — public disclosure before a fix is in place puts other users at risk.

**For sensitive security issues:**
Contact directly via [LinkedIn](https://www.linkedin.com/in/malcolm-mcdonald-87228b48) with a brief description of the issue. You will receive a response as quickly as possible.

**For non-sensitive bugs and general issues:**
Open a [GitHub Issue](https://github.com/malcolmmcdonald1982/M365-Assessment-Toolkit/issues) — these are tracked and responded to publicly.

## What counts as a security issue

- A way to extract credentials or tenant data from the tool beyond its intended scope
- A flaw in the update mechanism that could allow arbitrary code execution
- A remediation script that makes unintended changes beyond what is documented
- Any behaviour that contradicts the stated data and privacy principles

## What does not count as a security issue

- The tool requiring elevated permissions to perform remediation — this is by design
- Microsoft API rate limiting or authentication errors — these are external
- Findings that do not apply to a specific tenant configuration

## Security principles

This tool is built on the following principles and any contribution or change must respect them:

- All data stays on the local machine — nothing is transmitted to external servers
- No telemetry, no analytics, no tracking of any kind
- Credentials are never written to disk
- Assessment is read-only by default — the tenant is never modified during a scan
- Remediation requires explicit user approval before any change is made
- Every remediation change is snapshotted before it is applied
- Updates require explicit user approval — the tool never auto-updates silently

## Supported versions

Only the latest release is actively maintained. Always update to the latest version before reporting an issue.

| Version | Supported |
|---|---|
| Latest | ✅ |
| Older versions | ❌ |
