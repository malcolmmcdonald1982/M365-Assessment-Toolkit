# Contributing to M365 Assessment Toolkit

Thank you for your interest in contributing. This project was built by one person, based on real M365 assessment experience, and shared freely with the community. Contributions are welcome from people who share the same values.

## Core principles — non-negotiable

Before contributing, understand what this project stands for:

- **Free, always.** This tool will never be monetised. No subscriptions, no paywalls, no freemium tiers.
- **No data leaves the machine.** No telemetry, no analytics, no usage tracking of any kind — ever.
- **Transparent by design.** All code is open source and publicly auditable. Nothing hidden.
- **Locally run.** The tool runs on the user's machine and connects directly to Microsoft's APIs. No cloud backend, no third-party services.
- **Remediation is always explicit.** The tenant is never modified without deliberate user action and approval.

If a proposed contribution contradicts any of these principles it will not be merged regardless of technical quality.

## How to contribute

**The process is simple — talk first, build second.**

1. **Open an issue** describing your idea, improvement or finding
2. We discuss it — does it fit the project? Is the approach right?
3. Once agreed, build it
4. Submit a pull request for review

This avoids wasted effort and keeps the project coherent. Pull requests submitted without prior discussion may be closed if they don't align with the project direction.

## What contributions are welcome

- **New findings and security checks** — additional M365 misconfigurations worth assessing
- **Investigation scripts** — PowerShell scripts that help a consultant dig deeper into a finding
- **Remediation scripts** — paired fix and rollback scripts for existing findings
- **Documentation improvements** — clearer explanations, better examples, corrected errors
- **UI improvements** — usability, accessibility, visual polish
- **Bug fixes** — anything that causes incorrect behaviour or errors
- **Testing** — validation against different tenant configurations, edge cases

## What is not welcome

- Monetisation of any kind — paid tiers, licence keys, usage limits
- Cloud-connected versions that transmit tenant data externally
- Telemetry, analytics or any form of user tracking
- Changes that weaken the read-only safety of the assessment mode
- Auto-remediation without explicit user approval

## Coding standards

The tool is currently built with Python (backend) and vanilla JavaScript (frontend). PowerShell scripts must be compatible with PowerShell 5.1. If you have a proposal that involves a different approach, raise it as an issue first and we can discuss whether it fits.

Test against a real or sandbox M365 tenant before submitting.

## Finding contributions

New findings should follow the existing pattern:

- A unique ID in the format `MODULE-NNN`
- Severity: Critical / High / Medium / Low
- Title, description, recommendation
- An investigation script where possible
- A remediation + rollback script pair for Tier 1 findings

## Licence

By contributing you agree that your contribution will be licensed under the same MIT licence as the project.

## Contact

For questions before contributing, open an issue or reach out via [LinkedIn](https://www.linkedin.com/in/malcolm-mcdonald-87228b48).
