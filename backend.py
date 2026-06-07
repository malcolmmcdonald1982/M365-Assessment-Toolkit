"""
M365 Assessment Tool — Python Backend v2
M365 Assessment Toolkit

Run with: python backend.py
Requires:  pip install flask flask-cors
Requires:  Node.js + npm install docx (run once in tool folder)

Supports two authentication methods:
  - Interactive:        Browser popup per workload (no setup required)
  - App Registration:  Tenant ID + Client ID + Client Secret (unattended)

Exchange Online, Teams, and SharePoint always use interactive login
regardless of auth method — these workloads do not support app-only
client credential auth via PowerShell in the same way as Graph.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import subprocess, json, os, datetime, csv, io
import urllib.request, urllib.parse, urllib.error

app = Flask(__name__)
CORS(app)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
for d in [SCRIPTS_DIR, OUTPUT_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  FRAMEWORK MAPPING
#  Maps each finding ID to CIS, NIST, ISO, CE, SOC2, CAF, E8, NIS2
#  active_frameworks in the session config controls which are shown
# ─────────────────────────────────────────────────────────────
FRAMEWORK_MAPPING = {
    "ID-001": {
        "cis":  {"id": "5.2.2.2", "title": "MFA enabled for all users", "profile": "E3 L1",
                 "desc": "Enable multifactor authentication for all users in the Microsoft 365 tenant.",
                 "rationale": "This finding directly measures MFA coverage — failing it means this control is unmet for affected users."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "Users, services, and hardware are authenticated before being granted access to systems.",
                 "rationale": "Low MFA coverage means users authenticate with a password alone, failing the second-factor requirement."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Secure authentication controls are implemented for all information systems.",
                 "rationale": "Single-factor access for a significant portion of users fails the secure authentication control."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "MFA is required for all user accounts accessing cloud services.",
                 "rationale": "Cyber Essentials requires MFA for all accounts; low MFA coverage is a direct non-compliance."},
        "soc2": {"id": "CC6.1, CC6.5", "title": "Logical access and MFA enforcement",
                 "desc": "Logical access to systems is restricted and credentials are protected through multi-factor authentication.",
                 "rationale": "Without MFA on all accounts, logical access controls and credential protection requirements are not fully satisfied."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to networks and information systems is limited to authenticated and authorised users.",
                 "rationale": "Password-only authentication for a portion of users fails the CAF requirement for strong authentication."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Multi-factor authentication is used for all privileged access and all remote access to systems.",
                 "rationale": "Essential Eight Maturity Level 2 requires MFA for all users; this finding directly tests that requirement."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Multi-factor authentication or continuous authentication solutions are used to protect access to systems.",
                 "rationale": "NIS2 Article 21(2)(k) mandates MFA; low MFA coverage is a direct gap against this requirement."},
    },
    "ID-002": {
        "cis":  {"id": "1.1.3", "title": "Between two and four global admins designated", "profile": "E3 L1",
                 "desc": "Ensure that between two and four Global Administrators are designated in the tenant.",
                 "rationale": "More than 4 global admins directly violates the upper bound this control establishes."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions and entitlements are managed incorporating the principle of least privilege.",
                 "rationale": "Excessive global admin count violates least privilege — the highest role should be tightly restricted."},
        "iso":  {"id": "A.5.15, A.8.2", "title": "Access control / Privileged access rights",
                 "desc": "Access to information and systems is controlled; privileged access rights are restricted and reviewed.",
                 "rationale": "Excess global admins violate both access control policy and privileged access rights management."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Admin accounts must only be used for admin tasks; the number of admin accounts must be minimised.",
                 "rationale": "Admin account proliferation beyond operational need violates Cyber Essentials user access control."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Access is authorised and role-based; access reviews ensure assignments remain appropriate.",
                 "rationale": "Excess admin roles indicate access reviews are not reducing role assignments to appropriate levels."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to networks and information systems is limited to authenticated and authorised users.",
                 "rationale": "More admins than necessary expands the privilege attack surface, failing least-privilege access control."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Administrative privileges are restricted to those accounts that require them.",
                 "rationale": "Excessive global admins directly violates the requirement to restrict administrative privileges."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access control policies ensure only authorised users hold privileged roles.",
                 "rationale": "Excess global admin accounts are an access control failure under NIS2 human resources and access management."},
    },
    "ID-003": {
        "cis":  {"id": "5.3.1", "title": "Privileged role assignments activated not permanently assigned", "profile": "E5 L1",
                 "desc": "Privileged role assignments should be activated on demand (just-in-time) rather than permanently assigned.",
                 "rationale": "Without PIM, all admin role assignments are permanent — directly violating this just-in-time requirement."},
        "nist": {"id": "PR.AA-02, PR.AA-05", "title": "Identities proofed / access permissions managed",
                 "desc": "Identities are proofed and bound to credentials; access permissions are managed with least privilege.",
                 "rationale": "Permanent privilege assignments fail least-privilege and identity management requirements."},
        "iso":  {"id": "A.8.2, A.5.15", "title": "Privileged access rights / Access control",
                 "desc": "Privileged access rights are restricted, monitored, and controlled throughout their lifecycle.",
                 "rationale": "Permanent admin roles without JIT activation violate privileged access rights management."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Admin accounts must only be used for admin tasks; access should be granted for specific tasks only.",
                 "rationale": "Always-active admin roles violate the Cyber Essentials principle of granting access only when needed."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Access is authorised, role-based, and reviewed; permanent privilege assignments are minimised.",
                 "rationale": "Permanent role assignments without JIT controls indicate inadequate access lifecycle management."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to networks and information systems is limited to authenticated and authorised users.",
                 "rationale": "Permanent privilege without JIT activation fails CAF's access control requirements."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Administrative privileges are restricted and requests are validated and logged.",
                 "rationale": "PIM enforces time-bound admin access; its absence means privileges are permanently and broadly held."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access control policies ensure privileged access is appropriately managed and reviewed.",
                 "rationale": "Permanent unreviewed privilege assignments fail NIS2 access control obligations."},
    },
    "ID-004": {
        "cis":  {"id": "5.1.6.2", "title": "Guest user access is restricted", "profile": "E3 L1",
                 "desc": "Guest user access is restricted to specific organisational resources only.",
                 "rationale": "A large unreviewed guest population indicates guest access restriction controls are not enforced."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions and entitlements are managed incorporating the principle of least privilege.",
                 "rationale": "Unreviewed guest accounts may hold access beyond what is required, violating least privilege."},
        "iso":  {"id": "A.5.18", "title": "Access rights",
                 "desc": "Access rights to information and systems are allocated, reviewed, and revoked appropriately.",
                 "rationale": "Guest accounts are access rights that must be periodically reviewed and revoked when no longer needed."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Accounts must only be given the access they need; guest accounts require review.",
                 "rationale": "A high guest count without review violates the CE requirement to limit access to what is needed."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Access is authorised and reviewed; assignments are revoked when no longer appropriate.",
                 "rationale": "High guest counts indicate access reviews are not identifying and removing unnecessary assignments."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to networks and information systems is limited to authenticated and authorised users.",
                 "rationale": "Unreviewed guest accounts may represent uncontrolled external access to organisational systems."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access control policies ensure external user access is managed and periodically reviewed.",
                 "rationale": "A large unreviewed guest population fails NIS2 access control and asset management obligations."},
    },
    "ID-005": {
        "cis":  None,
        "nist": {"id": "ID.AM-01", "title": "Inventories of hardware managed by the organisation",
                 "desc": "Inventories of software licences and assets managed by the organisation are maintained.",
                 "rationale": "Unused licences indicate the software asset inventory is not being accurately maintained or actioned."},
        "iso":  {"id": "A.5.9", "title": "Inventory of information and other associated assets",
                 "desc": "An inventory of information assets and associated software licences is maintained and kept current.",
                 "rationale": "Unassigned licences represent assets not captured or managed in the organisational inventory."},
        "ce":   None,
        "soc2": {"id": "CC6.2", "title": "Access reviews and timely revocation",
                 "desc": "Access authorisation is reviewed and revoked in a timely manner when no longer appropriate.",
                 "rationale": "Unused licences may indicate orphaned accounts with persistent access that should be revoked."},
        "caf":  {"id": "A2", "title": "Risk Management",
                 "desc": "The organisation maintains a current risk assessment and manages identified risks appropriately.",
                 "rationale": "Uncontrolled licence spend reflects weak asset tracking and risk management practices."},
        "e8":   None,
        "nis2": None,
    },
    "ID-006": {
        "cis":  {"id": "5.2.2.6", "title": "Enable Identity Protection user risk policies", "profile": "E5 L1",
                 "desc": "Enable Identity Protection user risk policies to automatically respond to detected compromised accounts.",
                 "rationale": "Risky users that are not reviewed or remediated show this automated response requirement is unmet."},
        "nist": {"id": "DE.AE-02, ID.RA-01", "title": "Adverse events analysed / vulnerabilities identified",
                 "desc": "Potentially adverse events are analysed; vulnerabilities in assets are identified and recorded.",
                 "rationale": "Unreviewed risky users are unanalysed adverse events that have not been investigated or resolved."},
        "iso":  {"id": "A.8.16, A.5.25", "title": "Monitoring activities / Assessment of security events",
                 "desc": "Security events are monitored, assessed and responded to in a timely manner.",
                 "rationale": "Risky users that are not actioned represent security events that have been detected but not assessed."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Compromised or risky accounts must be remediated promptly to maintain access control integrity.",
                 "rationale": "Active accounts flagged as compromised violate the CE requirement to maintain controlled user access."},
        "soc2": {"id": "CC7.2, CC7.3", "title": "Anomaly detection and security event triage",
                 "desc": "Anomalies are identified, assessed, and responded to; security incidents are contained.",
                 "rationale": "Risky users are anomalies requiring detection and triage — leaving them unreviewed fails both controls."},
        "caf":  {"id": "C1, C2", "title": "Security Monitoring / Proactive Security Event Discovery",
                 "desc": "Security monitoring detects potential incidents; proactive discovery identifies threats before impact.",
                 "rationale": "Unreviewed risky users indicate monitoring has detected events but proactive discovery is not acting on them."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Administrative privileges are restricted and requests are validated and logged.",
                 "rationale": "Compromised accounts — particularly admins — that remain active violate the principle of privilege restriction."},
        "nis2": {"id": "NIS2-b", "title": "Incident handling",
                 "desc": "Incident handling policies ensure cyber incidents are detected, reported, and responded to.",
                 "rationale": "Risky users represent potential account compromises that require incident handling procedures to be applied."},
    },
    "ID-007": {
        "cis":  {"id": "1.1.2", "title": "Two emergency access accounts have been defined", "profile": "E3 L1",
                 "desc": "Create at least two emergency access (break-glass) accounts excluded from all Conditional Access policies.",
                 "rationale": "Absence of emergency access accounts is a direct non-compliance with this CIS control requirement."},
        "nist": {"id": "PR.AA-01, PR.AA-05", "title": "Identities and credentials managed / access permissions managed",
                 "desc": "Identities and credentials for authorised users are managed throughout their lifecycle.",
                 "rationale": "Emergency credentials are a required part of identity lifecycle management for continuity of access."},
        "iso":  {"id": "A.5.17, A.5.15", "title": "Authentication information / Access control",
                 "desc": "Authentication information and access rights are managed with appropriate controls for continuity.",
                 "rationale": "Break-glass accounts require specific authentication and access controls to be effective."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Resilient user access control requires emergency access provision for administration continuity.",
                 "rationale": "Without break-glass accounts, a CA misconfiguration could result in total loss of admin access."},
        "soc2": {"id": "CC6.1, CC6.2", "title": "Logical access restrictions and access reviews",
                 "desc": "Logical access is restricted and authorised; emergency access accounts are managed and monitored.",
                 "rationale": "Continuity of logical access requires defined emergency access accounts for resilience."},
        "caf":  {"id": "B2, A2", "title": "Identity and Access Control / Risk Management",
                 "desc": "Access control and risk management require emergency access provision to manage continuity risk.",
                 "rationale": "Absence of break-glass accounts is an unmitigated access continuity risk."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Administrative privilege procedures include defined emergency access mechanisms.",
                 "rationale": "Defined and monitored break-glass accounts are part of responsible admin privilege management."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access control policies include provisions for emergency access to maintain service continuity.",
                 "rationale": "Emergency access account management is an access control and resilience obligation under NIS2."},
    },
    "SEC-001": {
        "cis":  None,
        "nist": {"id": "ID.RA-01", "title": "Vulnerabilities in assets are identified, validated, and recorded",
                 "desc": "Vulnerabilities in assets are identified, validated, and recorded.",
                 "rationale": "Secure Score aggregates vulnerability and risk findings — a low score indicates they are not being identified and addressed."},
        "iso":  {"id": "A.5.35", "title": "Independent review of information security",
                 "desc": "Information security controls are independently reviewed to verify they are properly implemented.",
                 "rationale": "A low Secure Score indicates significant controls are absent and should trigger independent security review."},
        "ce":   None,
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Tools and processes are in place to detect and respond to threats and vulnerabilities.",
                 "rationale": "A low Secure Score directly indicates that many detection and monitoring controls are not in place."},
        "caf":  {"id": "A2", "title": "Risk Management",
                 "desc": "The organisation maintains a current risk assessment and manages identified risks to an acceptable level.",
                 "rationale": "A Secure Score below 50% directly indicates risk management controls are insufficient."},
        "e8":   None,
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Risk analysis and security policies are implemented and kept current.",
                 "rationale": "A low Secure Score reflects widespread gaps in the risk-based security policy implementation required by NIS2."},
    },
    "SEC-002": {
        "cis":  {"id": "5.2.2.2", "title": "MFA enabled for all users", "profile": "E3 L1",
                 "desc": "Enable multifactor authentication for all users in the Microsoft 365 tenant.",
                 "rationale": "Without Security Defaults or CA policies, there is no mechanism enforcing MFA for all users as required."},
        "nist": {"id": "PR.AA-03, PR.AA-05", "title": "Users authenticated / access permissions managed",
                 "desc": "Users are authenticated and access permissions are managed with appropriate controls.",
                 "rationale": "No baseline enforcement mechanism means authentication and access permissions are effectively uncontrolled."},
        "iso":  {"id": "A.8.5, A.5.15", "title": "Secure Authentication / Access control",
                 "desc": "Secure authentication controls and access policies are implemented across all systems.",
                 "rationale": "Absence of both Security Defaults and CA policies means secure authentication requirements are unmet."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "MFA enforcement is required for all accounts accessing cloud services.",
                 "rationale": "No MFA enforcement mechanism violates Cyber Essentials user access control requirements."},
        "soc2": {"id": "CC6.1, CC6.6", "title": "Logical access and boundary protection",
                 "desc": "Logical access is restricted and boundary controls protect the environment from unauthorised access.",
                 "rationale": "Without Security Defaults or CA, neither logical access controls nor boundary protection are enforced."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to networks and information systems is limited to authenticated and authorised users.",
                 "rationale": "No baseline identity control mechanism fails the CAF requirement for enforced strong authentication."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Multi-factor authentication is used for all privileged access and all remote access to systems.",
                 "rationale": "No MFA enforcement mechanism means Essential Eight MFA requirements cannot be met."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Multi-factor authentication or continuous authentication solutions are used to protect access.",
                 "rationale": "Without an enforcement mechanism, NIS2's MFA mandate cannot be demonstrated as being met."},
    },
    "SEC-003": {
        "cis":  {"id": "5.2.3.1", "title": "Microsoft Authenticator configured to protect against MFA fatigue", "profile": "E3 L1",
                 "desc": "Microsoft Authenticator is configured with number matching and additional context to prevent MFA fatigue attacks.",
                 "rationale": "MFA fatigue protection is not enabled, leaving push-notification MFA vulnerable to approval fatigue attacks."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "Users are authenticated with appropriate strength; authentication methods resist social engineering.",
                 "rationale": "Push-notification MFA without number matching can be bypassed via fatigue attacks, weakening authentication assurance."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Secure authentication controls are implemented and resistant to bypass techniques.",
                 "rationale": "MFA vulnerable to fatigue attacks does not meet secure authentication control requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "MFA methods must be resistant to social engineering and approval fatigue attacks.",
                 "rationale": "Fatigue-susceptible MFA undermines the user access control protections Cyber Essentials requires."},
        "soc2": {"id": "CC6.1, CC6.5", "title": "Logical access and MFA enforcement",
                 "desc": "Logical access controls include MFA enforcement with methods resistant to social engineering.",
                 "rationale": "Push MFA without fatigue protection weakens credential protection, undermining CC6.5."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Authentication mechanisms are resistant to known attack techniques including social engineering.",
                 "rationale": "MFA fatigue is a known attack vector; not mitigating it fails the CAF's access control requirements."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Multi-factor authentication methods are phishing-resistant and resilient to approval fatigue.",
                 "rationale": "ASD Essential Eight requires phishing-resistant MFA; number matching significantly reduces fatigue risk."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Multi-factor authentication solutions are effective and resistant to social engineering bypass.",
                 "rationale": "NIS2 requires effective MFA; methods susceptible to fatigue attacks undermine that effectiveness."},
    },
    "SEC-004": {
        "cis":  {"id": "5.2.3.5", "title": "Weak authentication methods are disabled", "profile": "E3 L1",
                 "desc": "Weak authentication methods (SMS, voice call, email OTP) are disabled in favour of stronger alternatives.",
                 "rationale": "Enabled weak MFA methods can be exploited via SIM swapping or phishing, directly violating this control."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "Authentication methods provide sufficient assurance of user identity to protect sensitive systems.",
                 "rationale": "Interceptable authentication methods (SMS/voice) cannot provide the assurance NIST authentication requires."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Authentication controls are implemented using methods that provide adequate security assurance.",
                 "rationale": "SMS and voice OTP are not considered secure authentication — they fail the ISO secure auth standard."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "MFA methods must provide genuine security; interceptable methods do not meet CE requirements.",
                 "rationale": "Cyber Essentials expects robust MFA; SIM-swappable methods provide insufficient protection."},
        "soc2": {"id": "CC6.1, CC6.5", "title": "Logical access and MFA enforcement",
                 "desc": "Authentication credentials are protected using methods that resist interception and social engineering.",
                 "rationale": "Weak MFA methods that can be intercepted fail the credential protection requirements of CC6.5."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Authentication mechanisms provide strong identity assurance and resist common attack techniques.",
                 "rationale": "Weak authentication methods (SMS/voice) are known to be interceptable, failing CAF B2's assurance requirements."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Multi-factor authentication methods are phishing-resistant; weak methods like SMS are disallowed at higher maturity levels.",
                 "rationale": "E8 Maturity Level 3 requires phishing-resistant MFA; SMS and voice fail this requirement."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Multi-factor authentication solutions provide effective security and resist known bypass methods.",
                 "rationale": "Interceptable MFA methods undermine the effectiveness that NIS2's MFA mandate requires."},
    },
    "SEC-005": {
        "cis":  {"id": "5.1.5.1", "title": "User consent to apps accessing company data is not allowed", "profile": "E3 L1",
                 "desc": "Users are blocked from granting OAuth application consent to access company data without administrator approval.",
                 "rationale": "Unrestricted user consent directly violates this CIS requirement for admin-controlled OAuth access."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions are managed and applications receive only the permissions they require.",
                 "rationale": "User-granted app permissions bypass centralised access management, violating least privilege control."},
        "iso":  {"id": "A.5.15, A.8.26", "title": "Access control / Application security requirements",
                 "desc": "Application access to data is controlled and applications are required to meet security standards.",
                 "rationale": "Unrestricted user consent bypasses access control and application security requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Applications must only be granted the access they need; admin approval is required for data access.",
                 "rationale": "User-initiated consent can grant apps broad data access — violating CE least-privilege access control."},
        "soc2": {"id": "CC6.3, CC6.6", "title": "Role-based access and boundary protection",
                 "desc": "Application access to data is role-based and boundary controls prevent unauthorised data flows.",
                 "rationale": "Unrestricted consent bypasses role-based access controls and allows uncontrolled external data access."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application access to sensitive data is controlled and requires explicit authorisation.",
                 "rationale": "User-initiated OAuth consent grants data access without the authorisation controls CAF B2 requires."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access control policies govern how applications are granted access to organisational data.",
                 "rationale": "Uncontrolled OAuth consent is an access control failure under NIS2 asset management obligations."},
    },
    "SEC-006": {
        "cis":  None,
        "nist": {"id": "DE.CM-01", "title": "Networks and network services are monitored",
                 "desc": "Networks and services are monitored to detect potentially adverse events.",
                 "rationale": "Without Sentinel, M365 service events are not correlated or centrally monitored for threats."},
        "iso":  {"id": "A.8.15, A.8.16", "title": "Logging / Monitoring activities",
                 "desc": "Security logs are generated and monitoring activities detect and respond to security events.",
                 "rationale": "No SIEM connection means logs are not being actively monitored across M365 services."},
        "ce":   None,
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Tools and processes detect and respond to threats across the environment.",
                 "rationale": "Absence of Sentinel means security incidents across M365 are not detected and correlated in real time."},
        "caf":  {"id": "C1", "title": "Security Monitoring",
                 "desc": "Security monitoring is in place to detect potential security incidents affecting essential services.",
                 "rationale": "Without a connected SIEM, the security monitoring required by CAF C1 is absent for M365 services."},
        "e8":   None,
        "nis2": {"id": "NIS2-b", "title": "Incident handling",
                 "desc": "Incident handling policies require detection capability to identify and respond to cyber incidents.",
                 "rationale": "Without Sentinel, M365 threat events cannot be detected or correlated for effective incident handling."},
    },
    "CA-001": {
        "cis":  {"id": "5.2.2.2", "title": "MFA enabled for all users", "profile": "E3 L1",
                 "desc": "Enable multifactor authentication for all users in the Microsoft 365 tenant.",
                 "rationale": "Conditional Access is the primary enforcement mechanism for MFA — zero policies means MFA cannot be enforced."},
        "nist": {"id": "PR.AA-03, PR.AA-05", "title": "Users authenticated / access permissions managed",
                 "desc": "Users are authenticated and access permissions are managed with contextual controls.",
                 "rationale": "Without any CA policies, authentication and access permission management are effectively absent."},
        "iso":  {"id": "A.5.15, A.8.5", "title": "Access control / Secure Authentication",
                 "desc": "Access control and secure authentication policies are implemented and enforced.",
                 "rationale": "No CA policies means access control and secure authentication requirements cannot be enforced."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "CA policies are the enforcement mechanism for MFA and device compliance in cloud environments.",
                 "rationale": "Zero CA policies means none of the user access controls required by Cyber Essentials are enforced."},
        "soc2": {"id": "CC6.1, CC6.6", "title": "Logical access and boundary protection",
                 "desc": "Logical access is restricted and boundary controls protect the environment.",
                 "rationale": "Without CA policies, neither logical access restriction nor boundary protection can be enforced."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to systems is enforced through identity and access controls.",
                 "rationale": "No CA policies means there is no mechanism for enforced identity and access control in M365."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Multi-factor authentication is enforced for all users accessing systems and services.",
                 "rationale": "CA is required to enforce MFA at scale; zero policies means E8-7 MFA requirements cannot be met."},
        "nis2": {"id": "NIS2-j, NIS2-k", "title": "Access control / Multi-factor authentication",
                 "desc": "Access control and MFA policies are implemented to protect access to systems.",
                 "rationale": "No CA policies means both NIS2 access control and MFA enforcement requirements are unmet."},
    },
    "CA-002": {
        "cis":  {"id": "5.2.2.3", "title": "CA policy to block legacy authentication", "profile": "E3 L1",
                 "desc": "Enable a Conditional Access policy to block all legacy authentication protocols.",
                 "rationale": "This finding directly tests for the CA policy this control requires; its absence is direct non-compliance."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "Authentication methods used meet security requirements; insecure legacy protocols are not permitted.",
                 "rationale": "Legacy authentication protocols bypass MFA, meaning users are not authenticated with required assurance."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Secure authentication controls exclude insecure legacy protocols that bypass modern controls.",
                 "rationale": "Legacy authentication protocols cannot meet ISO secure authentication requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Legacy authentication protocols that bypass MFA must be blocked.",
                 "rationale": "Unblocked legacy auth enables MFA bypass, directly violating Cyber Essentials user access controls."},
        "soc2": {"id": "CC6.1, CC6.6", "title": "Logical access and boundary protection",
                 "desc": "Logical access controls include blocking insecure authentication methods.",
                 "rationale": "Legacy auth bypasses logical access controls, enabling MFA circumvention at the boundary."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Authentication mechanisms that undermine access controls are blocked.",
                 "rationale": "Unblocked legacy auth undermines identity and access control — a CAF B2 failure."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Legacy authentication protocols that enable MFA bypass are blocked.",
                 "rationale": "Legacy auth protocols directly enable MFA bypass — blocking them is essential for E8-7 compliance."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Protocols that circumvent multi-factor authentication are blocked.",
                 "rationale": "Unblocked legacy auth allows MFA to be circumvented, violating NIS2 Article 21(2)(k)."},
    },
    "CA-003": {
        "cis":  {"id": "5.2.2.2", "title": "MFA enabled for all users", "profile": "E3 L1",
                 "desc": "A Conditional Access policy must enforce MFA for all users across all cloud apps.",
                 "rationale": "Having CA policies does not satisfy this control unless at least one explicitly requires MFA for all users."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "All users are required to authenticate with a second factor before accessing systems.",
                 "rationale": "Without a policy enforcing MFA for all users, authentication assurance requirements cannot be met."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Secure authentication is enforced as a policy requirement, not left optional.",
                 "rationale": "Secure authentication for all users requires an enforced policy — optional MFA enrollment is insufficient."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "MFA must be policy-enforced for all accounts accessing cloud services.",
                 "rationale": "CE requires MFA enforcement; a policy gap that leaves users without an MFA requirement is non-compliant."},
        "soc2": {"id": "CC6.1, CC6.5", "title": "Logical access and MFA enforcement",
                 "desc": "MFA is enforced for all user accounts as a logical access control.",
                 "rationale": "MFA must be enforced for all accounts to satisfy CC6.1 logical access and CC6.5 credential protection."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Strong authentication is enforced for all users, not merely made available.",
                 "rationale": "CAF B2 requires enforced strong authentication — available-but-not-required MFA does not satisfy this."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "MFA is enforced for all users through an active policy, not left to user discretion.",
                 "rationale": "E8-7 requires MFA enforcement; a gap where no CA policy targets all users fails this requirement."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "MFA is actively enforced for all users accessing systems.",
                 "rationale": "NIS2 requires active MFA use; a CA policy gap that doesn't enforce MFA for all users is non-compliant."},
    },
    "EXO-001": {
        "cis":  {"id": "6.2.1", "title": "All forms of mail forwarding are blocked and/or disabled", "profile": "E3 L1",
                 "desc": "All forms of automatic mail forwarding to external domains are blocked at the organisational level.",
                 "rationale": "Auto-forwarding allowed to external recipients is a direct violation of this CIS control."},
        "nist": {"id": "PR.DS-02", "title": "Data-in-transit is protected",
                 "desc": "The confidentiality and integrity of data in transit is protected from unauthorised access.",
                 "rationale": "Unblocked auto-forwarding silently exfiltrates email data to external parties in transit."},
        "iso":  {"id": "A.5.14", "title": "Information transfer",
                 "desc": "Rules and controls govern the transfer of information to external parties.",
                 "rationale": "Uncontrolled external mail forwarding violates information transfer controls under ISO A.5.14."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Email routing and forwarding rules are securely configured to prevent unauthorised data transfer.",
                 "rationale": "Unblocked auto-forwarding is a misconfiguration that allows silent data exfiltration via email."},
        "soc2": {"id": "CC6.7", "title": "Restrictions on access to sensitive data",
                 "desc": "Transmission of information is restricted to authorised parties and methods.",
                 "rationale": "Uncontrolled auto-forwarding transmits potentially sensitive data to external parties without restriction."},
        "caf":  {"id": "B3", "title": "Data Security",
                 "desc": "Data is protected against unauthorised transfer or exfiltration.",
                 "rationale": "External mail forwarding is a data exfiltration vector that violates CAF data security requirements."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access to and transfer of data assets is controlled and monitored.",
                 "rationale": "Uncontrolled data exfiltration via email forwarding is an asset management and access control failure."},
    },
    "EXO-002": {
        "cis":  {"id": "6.1.2", "title": "Mailbox audit actions are configured", "profile": "E3 L1",
                 "desc": "Mailbox audit logging is configured to capture all relevant mailbox actions.",
                 "rationale": "Disabled mailbox auditing for a proportion of mailboxes is a direct gap against this control."},
        "nist": {"id": "PR.PS-04", "title": "Logs of events are created",
                 "desc": "Log records of events are created and managed to support security monitoring and investigation.",
                 "rationale": "Mailboxes without audit logging fail to produce the event records this control requires."},
        "iso":  {"id": "A.8.15", "title": "Logging",
                 "desc": "Logs that record security-relevant activities are generated, protected, and retained.",
                 "rationale": "Mailbox audit logs are security-relevant logs required under the ISO logging control."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Audit logging is enabled as part of the secure configuration baseline.",
                 "rationale": "Mailbox audit logging is a secure configuration baseline requirement for Exchange Online."},
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Security monitoring relies on comprehensive audit log coverage from all key systems.",
                 "rationale": "Mailboxes without auditing create blind spots that prevent effective security monitoring."},
        "caf":  {"id": "C1", "title": "Security Monitoring",
                 "desc": "Security monitoring requires audit log data from all key systems including email.",
                 "rationale": "Missing mailbox audit logs undermine security monitoring capability across the email platform."},
        "e8":   None,
        "nis2": {"id": "NIS2-b", "title": "Incident handling",
                 "desc": "Audit logs are essential evidence for incident detection, investigation, and response.",
                 "rationale": "Mailboxes without audit logs cannot support forensic investigation during an incident."},
    },
    "EXO-003": {
        "cis":  {"id": "2.1.7", "title": "An anti-phishing policy has been created", "profile": "E3 L1",
                 "desc": "An anti-phishing policy is configured with mailbox intelligence and impersonation protection.",
                 "rationale": "Disabled mailbox intelligence in the anti-phishing policy is a direct gap in this CIS control."},
        "nist": {"id": "PR.DS-02", "title": "Data-in-transit is protected",
                 "desc": "Email security controls protect against phishing content delivered in transit.",
                 "rationale": "Anti-phishing intelligence protects email-in-transit from targeted social engineering attacks."},
        "iso":  {"id": "A.8.7", "title": "Protection against malware",
                 "desc": "Technical controls protect against malware including phishing-delivered threats.",
                 "rationale": "Anti-phishing policy is part of technical malware and social engineering protection requirements."},
        "ce":   {"pillar": "MP", "title": "Malware Protection",
                 "desc": "Technical controls detect and prevent malware and phishing content delivered via email.",
                 "rationale": "A misconfigured anti-phishing policy is a malware protection gap under Cyber Essentials."},
        "soc2": {"id": "CC6.8", "title": "Change management controls",
                 "desc": "Email security policies are configured and maintained to detect and block threats.",
                 "rationale": "An under-configured anti-phishing policy represents a security control gap."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Email systems are protected through configured anti-phishing and anti-malware controls.",
                 "rationale": "Disabled phishing intelligence weakens the system security controls required by CAF B4."},
        "e8":   {"id": "E8-4", "title": "User Application Hardening",
                 "desc": "User-facing applications including email are hardened against exploitation.",
                 "rationale": "Anti-phishing configuration is part of email application hardening under Essential Eight."},
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Email security policies address phishing risk as part of the information security policy.",
                 "rationale": "Phishing risk must be addressed in security policies — a misconfigured protection is a policy gap."},
    },
    "EXO-004": {
        "cis":  {"id": "2.1.10", "title": "DMARC records published for all Exchange Online domains", "profile": "E3 L1",
                 "desc": "DMARC records are published for all Exchange Online accepted domains.",
                 "rationale": "Missing DMARC is a direct non-compliance with this CIS email authentication control."},
        "nist": {"id": "PR.PS-01, PR.DS-02", "title": "Configuration management / Data-in-transit protected",
                 "desc": "Email domain configuration controls are applied and email in transit is protected from spoofing.",
                 "rationale": "DMARC is a configuration control that protects the email domain from spoofing in transit."},
        "iso":  {"id": "A.8.20, A.8.24", "title": "Network security / Use of cryptography",
                 "desc": "Network communications are secured and cryptographic controls are applied where appropriate.",
                 "rationale": "DMARC uses cryptographic authentication (DKIM) to secure email domain integrity."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Email authentication records (SPF, DKIM, DMARC) are a secure configuration requirement.",
                 "rationale": "DMARC is a required email security configuration under Cyber Essentials Secure Configuration."},
        "soc2": {"id": "CC6.8", "title": "Change management controls",
                 "desc": "Domain configuration changes are controlled; authentication records protect the domain identity.",
                 "rationale": "Missing DMARC allows domain spoofing — an unauthorised representation of the organisation's identity."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Email domain authentication is configured to protect against spoofing attacks.",
                 "rationale": "DMARC is a system security control for the email infrastructure required by CAF B4."},
        "e8":   None,
        "nis2": {"id": "NIS2-i", "title": "Cryptography and encryption",
                 "desc": "Cryptographic controls including email authentication are implemented and maintained.",
                 "rationale": "DMARC relies on cryptographic email signing (DKIM) — its absence is a cryptography control gap."},
    },
    "EXO-005": {
        "cis":  {"id": "2.1.8 / 2.1.9", "title": "SPF records published / DKIM enabled for all domains", "profile": "E3 L1",
                 "desc": "SPF records are published and DKIM signing is enabled for all Exchange Online accepted domains.",
                 "rationale": "Missing SPF or DKIM is a direct gap in this CIS email authentication requirement."},
        "nist": {"id": "PR.PS-01, PR.DS-02", "title": "Configuration management / Data-in-transit protected",
                 "desc": "Email domain authentication records are configured and maintained as part of system configuration.",
                 "rationale": "SPF and DKIM are configuration controls that protect the integrity of email in transit."},
        "iso":  {"id": "A.8.20, A.8.24", "title": "Network security / Use of cryptography",
                 "desc": "Network communications are secured through authentication and cryptographic controls.",
                 "rationale": "DKIM uses cryptographic signing to authenticate email — its absence is a cryptography control gap."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Email authentication records including SPF and DKIM are published as part of secure configuration.",
                 "rationale": "SPF and DKIM are baseline email security configuration requirements under Cyber Essentials."},
        "soc2": {"id": "CC6.8", "title": "Change management controls",
                 "desc": "Email authentication records protect the organisation's domain from spoofing.",
                 "rationale": "Missing SPF or DKIM enables domain spoofing — a gap in protecting the organisation's identity."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Email authentication controls including SPF and DKIM are configured for all domains.",
                 "rationale": "Missing email authentication is a system security gap in the email infrastructure."},
        "e8":   None,
        "nis2": {"id": "NIS2-i", "title": "Cryptography and encryption",
                 "desc": "Cryptographic controls including email signing (DKIM) are implemented and maintained.",
                 "rationale": "DKIM uses cryptographic signing — its absence is a gap in the cryptographic controls NIS2 requires."},
    },
    "EXO-006": {
        "cis":  {"id": "2.1.6 / 2.1.7", "title": "Anti-spam / Anti-phishing policies (ZAP governed by these)", "profile": "E3 L1",
                 "desc": "Anti-spam and anti-phishing policies include Zero-Hour Auto Purge for malware, phishing, and spam.",
                 "rationale": "ZAP configuration sits within the anti-spam and anti-phishing policies this control requires."},
        "nist": {"id": "PR.PS-01", "title": "Configuration management practices are applied",
                 "desc": "Configuration management practices are applied to threat policies including ZAP settings.",
                 "rationale": "Disabled ZAP represents a misconfiguration in threat policy settings that should be managed."},
        "iso":  {"id": "A.8.7", "title": "Protection against malware",
                 "desc": "Technical controls protect against malware including retroactive removal of post-delivery threats.",
                 "rationale": "ZAP provides retroactive malware and phishing protection — its absence is a malware protection gap."},
        "ce":   {"pillar": "MP", "title": "Malware Protection",
                 "desc": "Technical controls detect and remove malicious email content, including retroactively after delivery.",
                 "rationale": "ZAP is a technical malware protection control — disabled ZAP is a CE malware protection gap."},
        "soc2": {"id": "CC6.8", "title": "Change management controls",
                 "desc": "Threat policies are configured and maintained to reduce dwell time of malicious content.",
                 "rationale": "Disabled ZAP allows malicious emails to remain in mailboxes after identification — a configuration gap."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Email threat controls including retroactive purge capabilities are configured and active.",
                 "rationale": "Disabled ZAP is a system security configuration gap in the email threat management capability."},
        "e8":   None,
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Email security policies address retroactive threat removal as part of comprehensive risk management.",
                 "rationale": "Without ZAP, identified threats persist in mailboxes — a gap in the email security risk policy."},
    },
    "TEAMS-001": {
        "cis":  {"id": "8.2.2", "title": "Communication with unmanaged Teams users is disabled", "profile": "E3 L1",
                 "desc": "Communication with unmanaged Teams users from external tenants without domain restriction is disabled.",
                 "rationale": "Unrestricted external federation means communication with any external Teams tenant is permitted."},
        "nist": {"id": "PR.AA-05, PR.IR-01", "title": "Access permissions managed / Networks protected",
                 "desc": "Access permissions are managed and networks are protected from unauthorised communication.",
                 "rationale": "Unrestricted external Teams access violates access permission management and network protection."},
        "iso":  {"id": "A.5.15, A.8.3", "title": "Access control / Information access restriction",
                 "desc": "Access to information systems is controlled and information access is restricted appropriately.",
                 "rationale": "Unrestricted Teams federation bypasses access control and information restriction requirements."},
        "ce":   {"pillar": "FW", "title": "Firewalls",
                 "desc": "Network communications to and from external parties are controlled through firewall and access rules.",
                 "rationale": "Unrestricted external Teams communication bypasses the network access controls CE firewalls require."},
        "soc2": {"id": "CC6.6, CC6.7", "title": "Boundary protection and data access restrictions",
                 "desc": "Boundary controls restrict communications with external parties to authorised channels.",
                 "rationale": "Unrestricted external federation violates boundary protection and data transmission restrictions."},
        "caf":  {"id": "B2, B3", "title": "Identity and Access Control / Data Security",
                 "desc": "External communications are controlled to protect both identity and data security.",
                 "rationale": "Unrestricted Teams federation is an access control and data security failure."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "External access channels are controlled to prevent privilege escalation paths.",
                 "rationale": "Unrestricted external federation can enable uncontrolled access escalation paths."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "External access to systems and communication channels is controlled and restricted.",
                 "rationale": "Unrestricted external communication access violates NIS2 access control requirements."},
    },
    "TEAMS-002": {
        "cis":  {"id": "8.2.3", "title": "External Teams users cannot initiate conversations", "profile": "E3 L1",
                 "desc": "External Teams users (including consumer accounts) cannot initiate conversations with internal users.",
                 "rationale": "Enabled consumer access allows external Teams users to initiate contact, violating this control."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions ensure external parties can only communicate through controlled channels.",
                 "rationale": "Consumer account communications bypass organisational access permission management."},
        "iso":  {"id": "A.5.15, A.5.18", "title": "Access control / Access rights",
                 "desc": "Access rights for external parties are defined and controlled.",
                 "rationale": "Uncontrolled consumer account access violates access control and access rights management."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "External parties must only be granted the access they need; consumer federation must be controlled.",
                 "rationale": "Consumer account federation grants uncontrolled external access, violating CE user access control."},
        "soc2": {"id": "CC6.3, CC6.7", "title": "Role-based access and data access restrictions",
                 "desc": "Communications with external parties are restricted to authorised methods and roles.",
                 "rationale": "Consumer access bypasses role-based controls and data transmission restrictions."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "External access to communication systems is controlled and restricted to authorised parties.",
                 "rationale": "Consumer federation is uncontrolled external access, failing CAF identity and access control."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Unmanaged external access pathways are restricted to prevent uncontrolled privilege escalation.",
                 "rationale": "Unmanaged consumer account access represents an uncontrolled external access pathway."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "External user access is managed and controlled through defined access policies.",
                 "rationale": "Uncontrolled consumer account access fails NIS2 access control and asset management requirements."},
    },
    "TEAMS-003": {
        "cis":  {"id": "8.5.1", "title": "Anonymous users cannot join a meeting", "profile": "E3 L1",
                 "desc": "Anonymous users are prevented from joining Teams meetings without authentication.",
                 "rationale": "Anonymous meeting join being enabled is a direct violation of this CIS control requirement."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "All participants in meetings and system interactions are authenticated before being granted access.",
                 "rationale": "Anonymous join means meeting participants are not authenticated, violating this requirement."},
        "iso":  {"id": "A.5.15, A.8.3", "title": "Access control / Information access restriction",
                 "desc": "Access to meetings and shared information is controlled and restricted to authorised users.",
                 "rationale": "Unauthenticated meeting access violates access control and information restriction controls."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Meetings must require authentication; anonymous participants bypass user access controls.",
                 "rationale": "Anonymous participants bypass identity verification, violating CE user access control requirements."},
        "soc2": {"id": "CC6.6, CC6.7", "title": "Boundary protection and data access restrictions",
                 "desc": "Boundary controls require authentication before access is granted to meeting content.",
                 "rationale": "Anonymous participants cross the boundary without authentication, failing these controls."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Access to meetings and collaborative sessions is limited to authenticated and authorised users.",
                 "rationale": "Unauthenticated meeting access is an identity and access control failure under CAF B2."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Access to systems and sessions requires authentication; anonymous access is not permitted.",
                 "rationale": "Anonymous access completely bypasses authentication requirements, undermining E8-7 controls."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access to collaborative systems is controlled and requires user identity verification.",
                 "rationale": "Anonymous meeting access is an access control failure under NIS2 requirements."},
    },
    "TEAMS-004": {
        "cis":  {"id": "8.4.1", "title": "App permission policies are configured", "profile": "E3 L1",
                 "desc": "Teams app permission policies are configured to restrict which third-party apps users may install.",
                 "rationale": "Unrestricted third-party app access means app permission policies are not configured as required."},
        "nist": {"id": "PR.PS-01", "title": "Configuration management practices are applied",
                 "desc": "Configuration management practices govern which applications are permitted in the environment.",
                 "rationale": "Unrestricted third-party apps represent a configuration management failure for Teams."},
        "iso":  {"id": "A.5.23, A.8.9", "title": "Cloud services / Configuration management",
                 "desc": "Cloud service applications are managed and configuration policies restrict unauthorised apps.",
                 "rationale": "Unrestricted third-party Teams apps violate cloud service and configuration management controls."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Applications are restricted to approved software; unrestricted app stores are not permitted.",
                 "rationale": "Unrestricted Teams app access is a secure configuration failure under Cyber Essentials."},
        "soc2": {"id": "CC6.8", "title": "Change management controls",
                 "desc": "Applications introduced into the environment are authorised and reviewed.",
                 "rationale": "Unrestricted third-party apps introduce unreviewed changes to the system environment."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Only approved applications are permitted to operate within the system environment.",
                 "rationale": "Unrestricted third-party app access is a system security gap under CAF B4."},
        "e8":   {"id": "E8-1", "title": "Application Control",
                 "desc": "Only approved applications are permitted to execute and access data in the environment.",
                 "rationale": "Unrestricted Teams apps violate Essential Eight application control requirements."},
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Risk policies govern which third-party applications are permitted access to systems and data.",
                 "rationale": "Unrestricted third-party app access is a risk not addressed by the security policy."},
    },
    "SPO-001": {
        "cis":  {"id": "7.2.6", "title": "SharePoint external sharing is restricted", "profile": "E3 L1",
                 "desc": "SharePoint external sharing is restricted to authenticated external users only; anonymous links are not permitted.",
                 "rationale": "SharePoint set to 'Anyone' allows unauthenticated link sharing, directly violating this CIS control."},
        "nist": {"id": "PR.AA-05, PR.DS-01", "title": "Access permissions managed / Data-at-rest protected",
                 "desc": "Access permissions are managed and data at rest is protected from unauthorised access.",
                 "rationale": "Anonymous sharing allows unauthenticated data access, violating both access management and data protection."},
        "iso":  {"id": "A.5.15, A.8.3", "title": "Access control / Information access restriction",
                 "desc": "Access to information systems is controlled and information access is appropriately restricted.",
                 "rationale": "Anonymous links bypass access control and information restriction requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "External access to data requires authentication; anonymous sharing links are not permitted.",
                 "rationale": "Anyone links grant data access without identity verification, violating CE user access control."},
        "soc2": {"id": "CC6.7", "title": "Restrictions on access to sensitive data",
                 "desc": "Access to sensitive data is restricted and transmission to external parties requires authorisation.",
                 "rationale": "Anonymous SharePoint links allow unrestricted data access, failing CC6.7 restrictions."},
        "caf":  {"id": "B2, B3", "title": "Identity and Access Control / Data Security",
                 "desc": "External access to data requires authentication and data is protected from unauthorised sharing.",
                 "rationale": "Anonymous sharing violates both access control and data security requirements under CAF."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access to data assets is controlled and external sharing is managed appropriately.",
                 "rationale": "Unrestricted anonymous sharing is an access control and asset management failure under NIS2."},
    },
    "SPO-002": {
        "cis":  {"id": "7.2.1", "title": "Modern authentication for SharePoint applications is required", "profile": "E3 L1",
                 "desc": "Modern authentication is required for all SharePoint Online applications; legacy auth is disabled.",
                 "rationale": "Enabled legacy authentication in SharePoint directly violates this CIS modern auth requirement."},
        "nist": {"id": "PR.AA-03", "title": "Users, services, and hardware are authenticated",
                 "desc": "Authentication to systems meets security requirements; legacy protocols are not permitted.",
                 "rationale": "Legacy authentication does not meet the authentication assurance requirements of this control."},
        "iso":  {"id": "A.8.5", "title": "Secure Authentication",
                 "desc": "Secure authentication is enforced; legacy authentication protocols that bypass controls are disabled.",
                 "rationale": "Legacy authentication protocols do not meet ISO secure authentication requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Modern authentication must be enforced; legacy protocols that bypass MFA are disabled.",
                 "rationale": "Legacy SharePoint auth bypasses modern access controls including MFA."},
        "soc2": {"id": "CC6.1, CC6.6", "title": "Logical access and boundary protection",
                 "desc": "Logical access controls include enforced modern authentication for all services.",
                 "rationale": "Legacy auth enables logical access control bypass and boundary protection failures."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Authentication to systems is enforced using modern, secure protocols.",
                 "rationale": "Legacy auth undermines identity and access control for SharePoint."},
        "e8":   {"id": "E8-7", "title": "Multi-Factor Authentication",
                 "desc": "Modern authentication is required; legacy protocols that enable MFA bypass are blocked.",
                 "rationale": "Legacy auth in SharePoint enables MFA bypass, directly undermining E8-7 requirements."},
        "nis2": {"id": "NIS2-k", "title": "Multi-factor authentication",
                 "desc": "Legacy authentication protocols that circumvent MFA are disabled.",
                 "rationale": "Legacy auth allows MFA circumvention, violating NIS2 Article 21(2)(k) requirements."},
    },
    "SPO-003": {
        "cis":  {"id": "7.2.4", "title": "OneDrive content sharing is restricted", "profile": "E3 L1",
                 "desc": "OneDrive content sharing is restricted; anonymous (Anyone) links are disabled.",
                 "rationale": "OneDrive set to 'Anyone' directly violates this CIS control requiring restricted sharing."},
        "nist": {"id": "PR.DS-01", "title": "Data-at-rest is protected",
                 "desc": "Data at rest in cloud storage is protected from unauthorised access including unauthenticated links.",
                 "rationale": "Anonymous OneDrive links expose files at rest to anyone with the URL, with no authentication."},
        "iso":  {"id": "A.5.15, A.8.3", "title": "Access control / Information access restriction",
                 "desc": "Access to information is controlled; anonymous access to stored files is not permitted.",
                 "rationale": "Anonymous OneDrive links bypass access control and information restriction requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "External access to files requires authentication; anonymous sharing links are not permitted.",
                 "rationale": "Anyone links grant file access without identity verification, violating CE access control."},
        "soc2": {"id": "CC6.7", "title": "Restrictions on access to sensitive data",
                 "desc": "Access to sensitive data in cloud storage is restricted and requires authorisation.",
                 "rationale": "Anonymous file links allow unrestricted data access, failing CC6.7 data access restrictions."},
        "caf":  {"id": "B3", "title": "Data Security",
                 "desc": "Data in cloud storage is protected from unauthorised external access.",
                 "rationale": "Anonymous OneDrive sharing violates data security requirements under CAF B3."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Access to data assets in cloud storage is controlled and managed.",
                 "rationale": "Unrestricted anonymous file sharing is an access control and asset management failure."},
    },
    "SPO-004": {
        "cis":  {"id": "7.2.9", "title": "Guest access to site or OneDrive expires automatically", "profile": "E3 L1",
                 "desc": "Guest access to SharePoint sites and OneDrive expires automatically after a configured period.",
                 "rationale": "No automatic guest expiry means guest access persists indefinitely, violating this CIS control."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions are managed throughout their lifecycle; access is revoked when no longer needed.",
                 "rationale": "Non-expiring guest access violates the access permission lifecycle management this control requires."},
        "iso":  {"id": "A.5.18", "title": "Access rights",
                 "desc": "Access rights are reviewed and revoked when no longer required; temporary access expires automatically.",
                 "rationale": "Guest access without expiry violates the requirement to revoke access rights when no longer needed."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Temporary access grants expire automatically; accounts are not left with perpetual access.",
                 "rationale": "Non-expiring guest access violates the CE principle of granting only the access required."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Access is reviewed and revoked when no longer appropriate; guest access expires automatically.",
                 "rationale": "Guest access without expiry bypasses access lifecycle controls required by CC6.2 and CC6.3."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "External user access is time-limited and revoked when no longer required.",
                 "rationale": "Non-expiring guest accounts fail CAF identity and access control lifecycle requirements."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "External user access is managed with defined lifetimes and appropriate review processes.",
                 "rationale": "Perpetual guest access without expiry is an access control and asset management failure."},
    },
    "APP-001": {
        "cis":  {"id": "5.1.5.1", "title": "User consent to apps accessing company data is not allowed", "profile": "E3 L1",
                 "desc": "Users are blocked from granting OAuth application consent to company data without administrator approval.",
                 "rationale": "High-privilege OAuth apps with broad permissions indicate user or admin consent was granted without restriction."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Applications receive only the permissions they require; least privilege is enforced for service accounts.",
                 "rationale": "High-privilege app permissions violate least privilege for service identities and application access."},
        "iso":  {"id": "A.5.15, A.8.2", "title": "Access control / Privileged access rights",
                 "desc": "Applications with access to organisational data are controlled and granted only necessary permissions.",
                 "rationale": "Apps with high-privilege permissions violate access control and privileged access rights management."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Applications must only be granted the access they need; admin approval is required for sensitive permissions.",
                 "rationale": "Over-permissioned apps have broader access than required, violating CE least-privilege access control."},
        "soc2": {"id": "CC6.3, CC6.6", "title": "Role-based access and boundary protection",
                 "desc": "Application access to data is role-based and boundary controls restrict unauthorised data flows.",
                 "rationale": "High-privilege OAuth apps bypass role-based access and boundary protection requirements."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application access to organisational data requires explicit authorisation and is minimised.",
                 "rationale": "Over-permissioned app registrations are an identity and access control failure under CAF B2."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Applications with administrative Graph permissions represent non-interactive administrative access.",
                 "rationale": "Apps with admin-level Graph permissions are a form of unrestricted administrative privilege."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Application access to organisational data is controlled as part of access and asset management.",
                 "rationale": "Over-permissioned apps are an access control and asset management failure under NIS2."},
    },
    "MON-001": {
        "cis":  {"id": "3.1.1", "title": "Microsoft 365 audit log search is enabled", "profile": "E3 L1",
                 "desc": "Microsoft 365 unified audit log search is enabled to capture activity across all M365 services.",
                 "rationale": "No active Defender alert policies indicate monitoring configuration is not meeting this control."},
        "nist": {"id": "DE.CM-01", "title": "Networks and network services are monitored",
                 "desc": "Networks and services are monitored to detect potentially adverse events.",
                 "rationale": "Without active Defender alert policies, M365 service events are not being monitored for threats."},
        "iso":  {"id": "A.8.16", "title": "Monitoring activities",
                 "desc": "Monitoring activities detect unusual or unauthorised activities and security events.",
                 "rationale": "No active alert policies means security events are not being monitored or flagged."},
        "ce":   {"pillar": "MP", "title": "Malware Protection",
                 "desc": "Activity monitoring is a detection control that identifies malware and suspicious activity.",
                 "rationale": "Without alert policies, malware detections and suspicious events are not surfaced to administrators."},
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Detection tools and processes are in place and active to identify security threats.",
                 "rationale": "No active alert policies means the detection and monitoring required by CC7.1 is absent."},
        "caf":  {"id": "C1", "title": "Security Monitoring",
                 "desc": "Security monitoring is in place to detect potential security incidents in real time.",
                 "rationale": "Without Defender alert policies, real-time security monitoring of M365 is not functioning."},
        "e8":   None,
        "nis2": {"id": "NIS2-b", "title": "Incident handling",
                 "desc": "Incident detection requires active monitoring and alerting to identify security incidents.",
                 "rationale": "No alert policies means security incidents cannot be detected, undermining incident handling capability."},
    },
    "MDM-001": {
        "cis":  {"id": "4.1", "title": "Devices without a compliance policy are marked not compliant", "profile": "E3 L1",
                 "desc": "Devices that do not have a compliance policy assigned are automatically marked non-compliant.",
                 "rationale": "Low device compliance percentage indicates that compliance policies are not being met across the device estate."},
        "nist": {"id": "PR.PS-01, PR.AA-05", "title": "Configuration management / access permissions managed",
                 "desc": "Configuration management practices are applied and access is managed based on device compliance state.",
                 "rationale": "Non-compliant devices indicate configuration management failures; CA can use compliance state for access control."},
        "iso":  {"id": "A.8.1, A.8.9", "title": "User endpoint devices / Configuration management",
                 "desc": "User endpoint devices are managed and configuration controls are applied and verified.",
                 "rationale": "Non-compliant devices fail endpoint device and configuration management controls."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Managed devices must meet secure configuration standards; non-compliant devices are identified.",
                 "rationale": "Non-compliant devices indicate secure configuration requirements are not being met."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions",
                 "desc": "Non-compliant devices can be restricted from accessing systems through Conditional Access.",
                 "rationale": "Low device compliance indicates logical access restrictions on non-compliant devices are insufficient."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Endpoint devices meet security configuration standards as verified by compliance policies.",
                 "rationale": "Low compliance percentage indicates system security requirements are not being met on endpoints."},
        "e8":   None,
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Security policies govern the security configuration required for devices accessing systems.",
                 "rationale": "Non-compliant devices indicate security policy requirements are not being enforced."},
    },
    "MDM-002": {
        "cis":  {"id": "4.1", "title": "Devices without a compliance policy are marked not compliant", "profile": "E3 L1",
                 "desc": "Devices that do not have a compliance policy assigned are automatically marked non-compliant.",
                 "rationale": "Without compliance policies, no device can be evaluated — the control mechanism is entirely absent."},
        "nist": {"id": "PR.PS-01", "title": "Configuration management practices are applied",
                 "desc": "Configuration management practices including device compliance policies are established and applied.",
                 "rationale": "Absence of compliance policies is a fundamental configuration management gap."},
        "iso":  {"id": "A.8.1, A.8.9", "title": "User endpoint devices / Configuration management",
                 "desc": "Endpoint device management and configuration controls are established and enforced.",
                 "rationale": "No compliance policies means endpoint device and configuration management controls are absent."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Compliance policies are the mechanism for enforcing secure device configuration at scale.",
                 "rationale": "Without compliance policies, secure device configuration cannot be verified or enforced."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions",
                 "desc": "Device compliance policies enable logical access restrictions based on device security state.",
                 "rationale": "Without compliance policies, device-based logical access restrictions cannot be applied."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "System security requires device compliance policies to verify endpoint security configuration.",
                 "rationale": "No compliance policies means system security cannot be verified or enforced on endpoints."},
        "e8":   None,
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Security policies include device compliance requirements for accessing organisational systems.",
                 "rationale": "Absence of device compliance policies is a gap in the information security policy framework."},
    },
    "MDM-003": {
        "cis":  None,
        "nist": {"id": "PR.PS-01", "title": "Configuration management practices are applied",
                 "desc": "Configuration management practices govern the deployment of software updates to managed devices.",
                 "rationale": "No Windows Update rings means patch deployment is uncontrolled — a configuration management gap."},
        "iso":  {"id": "A.8.8", "title": "Management of technical vulnerabilities",
                 "desc": "Technical vulnerabilities are managed through timely and systematic patch deployment.",
                 "rationale": "Without update rings, Windows patches are deployed inconsistently, leaving known vulnerabilities unpatched."},
        "ce":   {"pillar": "PM", "title": "Patch Management",
                 "desc": "All software including operating systems must be kept up to date with security patches.",
                 "rationale": "No update rings means there is no controlled mechanism to ensure Cyber Essentials patch management compliance."},
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Patch management monitoring ensures devices are current and vulnerabilities are tracked.",
                 "rationale": "Unmanaged patching increases exploitable vulnerabilities that should be detected and remediated."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Systems are kept up to date through controlled patch management processes.",
                 "rationale": "No update rings is a system security gap in the Windows patch management process."},
        "e8":   {"id": "E8-2, E8-6", "title": "Patch Applications / Patch Operating Systems",
                 "desc": "Applications and operating systems are patched within defined timeframes based on risk.",
                 "rationale": "Windows Update rings are the Intune mechanism for Essential Eight-compliant OS patch management."},
        "nis2": {"id": "NIS2-f", "title": "Vulnerability handling and disclosure",
                 "desc": "Vulnerability handling requires systematic patch deployment within defined timeframes.",
                 "rationale": "No update rings means there is no systematic mechanism for vulnerability handling via OS patching."},
    },
    "MDM-004": {
        "cis":  {"id": "5.1.4.6", "title": "Users are restricted from recovering BitLocker keys (related)", "profile": "E3 L1",
                 "desc": "BitLocker encryption is required by compliance policy and key management is centralised.",
                 "rationale": "BitLocker not enforced by Intune means device encryption is absent or unmanaged."},
        "nist": {"id": "PR.DS-01", "title": "Data-at-rest is protected",
                 "desc": "Data at rest on devices is protected through encryption controls.",
                 "rationale": "Devices without BitLocker expose all data at rest if the device is lost or stolen."},
        "iso":  {"id": "A.8.24", "title": "Use of cryptography",
                 "desc": "Cryptographic controls including full-disk encryption are applied to protect data on devices.",
                 "rationale": "BitLocker is the cryptographic control for data-at-rest protection on Windows devices."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Managed devices must have disk encryption enabled as part of secure configuration.",
                 "rationale": "BitLocker is a secure configuration requirement for Windows devices under Cyber Essentials."},
        "soc2": {"id": "CC6.7", "title": "Restrictions on access to sensitive data",
                 "desc": "Data is protected on devices through encryption to prevent unauthorised physical access.",
                 "rationale": "Unencrypted devices expose data to anyone with physical access, failing CC6.7."},
        "caf":  {"id": "B3", "title": "Data Security",
                 "desc": "Data on endpoint devices is protected by encryption against physical access risks.",
                 "rationale": "BitLocker is a data security control for protecting information on endpoints."},
        "e8":   None,
        "nis2": {"id": "NIS2-i", "title": "Cryptography and encryption",
                 "desc": "Cryptographic controls including device encryption are implemented to protect data.",
                 "rationale": "BitLocker uses encryption to protect data at rest — its absence is a cryptography control gap."},
    },
    "MDM-005": {
        "cis":  {"id": "4.1", "title": "Devices without a compliance policy are marked not compliant", "profile": "E3 L1",
                 "desc": "Compliance policies covering all device platforms including iOS and Android are configured.",
                 "rationale": "No mobile compliance policy means iOS and Android devices have no security baseline requirement."},
        "nist": {"id": "PR.PS-01", "title": "Configuration management practices are applied",
                 "desc": "Configuration management practices extend to all device platforms including mobile.",
                 "rationale": "No mobile compliance policy is a configuration management gap for the mobile device population."},
        "iso":  {"id": "A.8.1", "title": "User endpoint devices",
                 "desc": "All user endpoint devices including mobile are managed with appropriate controls.",
                 "rationale": "Mobile devices are user endpoints that require explicit management controls under ISO A.8.1."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "All devices including mobile must be securely configured to meet compliance requirements.",
                 "rationale": "Mobile devices without compliance policies cannot be verified as meeting secure configuration standards."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions",
                 "desc": "Mobile devices accessing M365 must meet compliance requirements to be granted logical access.",
                 "rationale": "Without mobile compliance policies, non-compliant mobile devices can access M365 without restriction."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "All device types including mobile are covered by security configuration requirements.",
                 "rationale": "No mobile compliance policy is a system security gap for the mobile device population."},
        "e8":   None,
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Security policies address all device types used to access organisational systems.",
                 "rationale": "No mobile compliance policy is a gap in the information system security policy framework."},
    },
    "MDM-006": {
        "cis":  None,
        "nist": {"id": "DE.CM-09", "title": "Computing hardware and software are monitored",
                 "desc": "Computing hardware and software are monitored to detect potentially adverse events.",
                 "rationale": "Without MDE integration, device-level threat signals from Defender are not visible to Intune or CA."},
        "iso":  {"id": "A.8.7, A.8.16", "title": "Protection against malware / Monitoring activities",
                 "desc": "Malware protection and monitoring activities are integrated across endpoint and identity platforms.",
                 "rationale": "MDE integration provides endpoint malware detection signals to Intune's monitoring and compliance framework."},
        "ce":   {"pillar": "MP", "title": "Malware Protection",
                 "desc": "Malware protection covers all managed device types and detection feeds into compliance controls.",
                 "rationale": "Without MDE integration, mobile threat defence signals are not incorporated into device compliance."},
        "soc2": {"id": "CC7.1", "title": "Detection and monitoring",
                 "desc": "Endpoint threat detection signals are integrated with access control and monitoring systems.",
                 "rationale": "Without MDE integration, device threat signals are siloed and not feeding detection and monitoring systems."},
        "caf":  {"id": "C1", "title": "Security Monitoring",
                 "desc": "Security monitoring integrates endpoint threat intelligence to detect potential incidents.",
                 "rationale": "MDE-Intune integration enables security monitoring using real-time device risk signals."},
        "e8":   None,
        "nis2": {"id": "NIS2-b", "title": "Incident handling",
                 "desc": "Endpoint threat signals are integrated with incident detection and response processes.",
                 "rationale": "Without MDE integration, compromised device signals cannot trigger automated incident response."},
    },
    "ENTRA-001": {
        "cis":  {"id": "5.1.5.1", "title": "User consent to apps accessing company data is not allowed", "profile": "E3 L1",
                 "desc": "Users are blocked from granting OAuth application consent to company data without administrator approval.",
                 "rationale": "High-privilege app registrations indicate consent was granted for critical Graph permissions without restriction."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Applications receive only the permissions they require; admin-level permissions are tightly controlled.",
                 "rationale": "App registrations with critical Graph permissions violate least privilege for service identities."},
        "iso":  {"id": "A.5.15, A.8.2", "title": "Access control / Privileged access rights",
                 "desc": "Applications with privileged access to organisational data are controlled and minimised.",
                 "rationale": "High-privilege app registrations violate privileged access rights and access control requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Applications must only be granted the minimum permissions they need for their function.",
                 "rationale": "App registrations with critical permissions have far more access than the least-privilege CE standard requires."},
        "soc2": {"id": "CC6.3, CC6.6", "title": "Role-based access and boundary protection",
                 "desc": "Application permissions are role-based and boundary controls restrict over-privileged data access.",
                 "rationale": "High-privilege app permissions bypass role-based access controls and boundary protection."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application access to sensitive systems is explicitly authorised and minimised.",
                 "rationale": "Over-privileged app registrations are an identity and access control failure under CAF B2."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Applications with administrative-level permissions are treated as privileged access and restricted.",
                 "rationale": "App registrations with admin Graph permissions represent unrestricted administrative privilege."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Application access to organisational data is managed as part of access and asset management policy.",
                 "rationale": "Over-permissioned app registrations are an access control and asset management failure."},
    },
    "ENTRA-002": {
        "cis":  {"id": "5.1.5.4", "title": "App password lifetime does not exceed 180 days", "profile": "E3 L1",
                 "desc": "App registration client secret lifetimes do not exceed 180 days and are actively managed.",
                 "rationale": "Expired credentials on app registrations indicate lifecycle management has failed entirely."},
        "nist": {"id": "PR.AA-01", "title": "Identities and credentials for authorised users are managed",
                 "desc": "Identities and credentials are managed throughout their lifecycle; expired credentials are removed.",
                 "rationale": "Expired credentials should be removed as part of identity and credential lifecycle management."},
        "iso":  {"id": "A.5.17", "title": "Authentication information",
                 "desc": "Authentication information including credentials has defined lifetimes and is actively managed.",
                 "rationale": "Expired credentials violate authentication information management — they should be removed immediately."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Application credentials must be actively managed; expired credentials indicate unmanaged access.",
                 "rationale": "Expired credentials on active apps represent an unmanaged access control gap."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions and credential management",
                 "desc": "Credentials are managed throughout their lifecycle; expired credentials are identified and removed.",
                 "rationale": "Expired credentials represent an unmanaged logical access risk under CC6.1."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application credentials are actively managed; expired credentials are identified and removed.",
                 "rationale": "Unmanaged expired credentials are an identity and access control failure."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Credential lifecycle management is an access control and asset management obligation.",
                 "rationale": "Expired app credentials indicate asset management and access control obligations are not being met."},
    },
    "ENTRA-003": {
        "cis":  {"id": "5.1.5.4", "title": "App password lifetime does not exceed 180 days", "profile": "E3 L1",
                 "desc": "App registration credentials are managed proactively; credentials expiring within 30 days require immediate action.",
                 "rationale": "Credentials expiring within 30 days require urgent rotation to avoid service failure and security gaps."},
        "nist": {"id": "PR.AA-01", "title": "Identities and credentials for authorised users are managed",
                 "desc": "Credentials are proactively managed; imminent expiry is identified and actioned before lapsing.",
                 "rationale": "Near-term credential expiry requires proactive management action to maintain identity integrity."},
        "iso":  {"id": "A.5.17", "title": "Authentication information",
                 "desc": "Authentication credentials are managed with sufficient lead time to prevent unplanned expiry.",
                 "rationale": "Imminent credential expiry indicates authentication information is not being managed proactively."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Application credentials must be renewed before expiry to maintain access control integrity.",
                 "rationale": "Near-expiry credentials require immediate action to avoid access control failures."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions and credential management",
                 "desc": "Credential management includes proactive renewal before expiry to maintain logical access controls.",
                 "rationale": "Imminent credential expiry requires immediate credential management action under CC6.1."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Credential expiry is managed proactively to prevent unplanned access control failures.",
                 "rationale": "Credentials expiring within 30 days represent an imminent identity and access control risk."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Credential lifecycle management requires proactive renewal before expiry.",
                 "rationale": "Near-expiry credentials indicate access control and asset management obligations are not being met proactively."},
    },
    "ENTRA-004": {
        "cis":  {"id": "5.1.5.4 / 5.1.5.6", "title": "App password and certificate lifetime ≤180 days", "profile": "E3 L1",
                 "desc": "App password and certificate lifetimes do not exceed 180 days; rotation is planned in advance.",
                 "rationale": "Credentials expiring within 90 days require planned rotation to avoid last-minute risks."},
        "nist": {"id": "PR.AA-01", "title": "Identities and credentials for authorised users are managed",
                 "desc": "Credential lifecycle is managed with forward planning; rotation is scheduled before expiry.",
                 "rationale": "Credentials expiring in 31–90 days require planned management action within the next month."},
        "iso":  {"id": "A.5.17", "title": "Authentication information",
                 "desc": "Authentication information is managed with planned renewal cycles to prevent lapses.",
                 "rationale": "Credentials expiring in 90 days require forward planning to maintain authentication information integrity."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Planned credential renewal is required to maintain access control integrity.",
                 "rationale": "Credentials expiring within 90 days require planned action to maintain CE access control compliance."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions and credential management",
                 "desc": "Credential lifecycle management includes advance planning for renewal before expiry.",
                 "rationale": "Credential expiry within 90 days requires scheduling renewal to maintain logical access controls."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Credential rotation is planned in advance of expiry to maintain access control continuity.",
                 "rationale": "Credentials expiring in 90 days require scheduled rotation as an identity management obligation."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Credential lifecycle planning is an access control and asset management requirement.",
                 "rationale": "Credentials expiring within 90 days require planned renewal under NIS2 access management obligations."},
    },
    "ENTRA-005": {
        "cis":  {"id": "5.1.5.4 / 5.1.5.6", "title": "App password and certificate lifetime enforcement", "profile": "E3 L1",
                 "desc": "App password and certificate lifetimes are time-limited and do not exceed 180 days.",
                 "rationale": "Never-expiring credentials directly violate the CIS maximum lifetime requirement of 180 days."},
        "nist": {"id": "PR.AA-01", "title": "Identities and credentials for authorised users are managed",
                 "desc": "Credentials have defined lifetimes and are rotated regularly as part of identity lifecycle management.",
                 "rationale": "Non-expiring credentials violate credential lifecycle management — they persist indefinitely without rotation."},
        "iso":  {"id": "A.5.17", "title": "Authentication information",
                 "desc": "Authentication information has defined and enforced expiry periods.",
                 "rationale": "Credentials without expiry violate ISO A.5.17 — authentication information must have defined lifetimes."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Application credentials must have defined expiry; non-expiring credentials are not permitted.",
                 "rationale": "Never-expiring credentials violate the access control principle of periodic review and rotation."},
        "soc2": {"id": "CC6.1", "title": "Logical access restrictions and credential management",
                 "desc": "Credentials are time-limited and rotated regularly; non-expiring credentials are not permitted.",
                 "rationale": "Non-expiring credentials bypass the credential lifecycle controls required by CC6.1."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application credentials are time-limited and subject to regular rotation.",
                 "rationale": "Never-expiring credentials are an identity and access control failure under CAF B2."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Credential management requires defined expiry and rotation as part of access control policy.",
                 "rationale": "Non-expiring credentials violate credential management obligations under NIS2."},
    },
    "ENTRA-006": {
        "cis":  None,
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Access permissions including app registration ownership are managed with accountability.",
                 "rationale": "Unowned apps have no accountable owner to manage permissions, violating access management requirements."},
        "iso":  {"id": "A.5.18, A.5.15", "title": "Access rights / Access control",
                 "desc": "Access rights including application permissions have defined owners responsible for review.",
                 "rationale": "Unowned apps cannot be subject to the access rights reviews ISO A.5.18 requires."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Application access to company data must have an accountable owner for review and management.",
                 "rationale": "Unowned apps cannot be reviewed for least-privilege access, violating CE user access control."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Application access is reviewed and role-based; unowned apps cannot be subject to access reviews.",
                 "rationale": "Unowned apps cannot be subject to the access reviews CC6.2 and CC6.3 require."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application identity and access is managed with accountability and regular review.",
                 "rationale": "Unowned apps represent an accountability gap in identity and access control."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Ownership accountability for application assets is required under access and asset management policy.",
                 "rationale": "Unowned app registrations violate ownership accountability requirements under NIS2."},
    },
    "ENTRA-007": {
        "cis":  {"id": "5.1.2.2", "title": "Users cannot register applications", "profile": "E3 L1",
                 "desc": "Only administrators can register applications; multi-tenant app configuration requires explicit review.",
                 "rationale": "Multi-tenant apps without review expand the attack surface beyond organisational boundaries."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Application access permissions including multi-tenant configuration are explicitly managed.",
                 "rationale": "Unintended multi-tenant access expands permissions beyond organisational boundaries, violating least privilege."},
        "iso":  {"id": "A.5.23", "title": "Information security for use of cloud services",
                 "desc": "Cloud service application configuration is managed and multi-tenant access is explicitly controlled.",
                 "rationale": "Multi-tenant app registrations without review violate cloud service information security requirements."},
        "ce":   {"pillar": "SC", "title": "Secure Configuration",
                 "desc": "Application registration and multi-tenant configuration is reviewed and controlled.",
                 "rationale": "Unreviewed multi-tenant app configuration is a secure configuration failure."},
        "soc2": {"id": "CC6.6, CC6.8", "title": "Boundary protection and change management",
                 "desc": "Multi-tenant applications extend the system boundary and require explicit change management review.",
                 "rationale": "Multi-tenant apps extend the boundary beyond the organisation — requiring boundary protection controls."},
        "caf":  {"id": "B4", "title": "System Security",
                 "desc": "Application configuration including multi-tenant access is explicitly reviewed and controlled.",
                 "rationale": "Multi-tenant configuration without review is a system security risk under CAF B4."},
        "e8":   {"id": "E8-1", "title": "Application Control",
                 "desc": "Application configuration is controlled; multi-tenant apps require explicit approval.",
                 "rationale": "Multi-tenant apps without explicit approval violate application control requirements."},
        "nis2": {"id": "NIS2-a", "title": "Risk analysis and information system security policies",
                 "desc": "Risk policies govern multi-tenant application configuration and external access grants.",
                 "rationale": "Unreviewed multi-tenant app configuration is a risk not addressed by the security policy."},
    },
    "ENTRA-008": {
        "cis":  {"id": "5.1.5.1", "title": "User consent to apps accessing company data is not allowed", "profile": "E3 L1",
                 "desc": "Application authentication flows are configured securely; implicit grant flow is disabled.",
                 "rationale": "Implicit grant flow returns tokens in browser redirects, creating token exposure risks."},
        "nist": {"id": "PR.AA-05", "title": "Access permissions managed, least privilege enforced",
                 "desc": "Application authentication flows are configured to minimise token exposure and access risk.",
                 "rationale": "Implicit flow exposes tokens in URLs and browser history, violating secure permission management."},
        "iso":  {"id": "A.5.15, A.8.26", "title": "Access control / Application security requirements",
                 "desc": "Application security requirements include secure authentication flows that minimise token exposure.",
                 "rationale": "Implicit grant flow is an insecure application design pattern that violates application security requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Application authentication must use secure flows; token-exposing patterns are not permitted.",
                 "rationale": "Implicit flow exposes access tokens in browsers, creating a user access control vulnerability."},
        "soc2": {"id": "CC6.3, CC6.6", "title": "Role-based access and boundary protection",
                 "desc": "Application authentication flows protect tokens at the boundary and prevent uncontrolled exposure.",
                 "rationale": "Implicit flow allows token leakage at the boundary, failing CC6.3 and CC6.6 requirements."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Application authentication flows are configured securely to prevent identity and token compromise.",
                 "rationale": "Token leakage via implicit flow is an identity and access control risk under CAF B2."},
        "e8":   None,
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Application authentication configuration is managed as part of access control policy.",
                 "rationale": "Implicit grant flow token exposure is an access control vulnerability under NIS2."},
    },
    "ENTRA-009": {
        "cis":  {"id": "5.3.1", "title": "Privileged role assignments activated not permanently assigned", "profile": "E5 L1",
                 "desc": "Privileged role assignments are time-bound; service principals with admin roles require JIT controls.",
                 "rationale": "Service principals with permanent admin directory roles violate just-in-time privilege requirements."},
        "nist": {"id": "PR.AA-02, PR.AA-05", "title": "Identities proofed / access permissions managed",
                 "desc": "Service principal identities are managed; their permissions are minimised and validated.",
                 "rationale": "Service principals with high-privilege roles represent unvalidated persistent admin access."},
        "iso":  {"id": "A.8.2, A.5.15", "title": "Privileged access rights / Access control",
                 "desc": "Privileged access rights including those held by service principals are restricted and controlled.",
                 "rationale": "Service principals with admin roles violate privileged access rights and access control requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Service principals with administrative roles must have their access explicitly authorised and minimised.",
                 "rationale": "Privileged service principals represent unrestricted admin access without user interaction."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Service principal role assignments are reviewed; admin-level assignments are explicitly authorised.",
                 "rationale": "Service principal admin role assignments require explicit access reviews under CC6.2 and CC6.3."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Service principal access to systems is managed and privileged access is minimised.",
                 "rationale": "Privileged service principals are an identity and access control risk under CAF B2."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Service principals with administrative privileges are identified, reviewed, and minimised.",
                 "rationale": "Service principals with admin directory roles are a form of unrestricted administrative privilege."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Service principal privilege management is an access control and asset management obligation.",
                 "rationale": "Privileged service principals are an access control failure under NIS2 requirements."},
    },
    "ENTRA-010": {
        "cis":  {"id": "5.3.1", "title": "Privileged role assignments activated not permanently assigned", "profile": "E5 L1",
                 "desc": "Privileged role assignments are time-bound; managed identities with admin roles require explicit authorisation.",
                 "rationale": "Managed identities with permanent admin directory roles violate just-in-time privilege requirements."},
        "nist": {"id": "PR.AA-02, PR.AA-05", "title": "Identities proofed / access permissions managed",
                 "desc": "Managed identity permissions are validated and minimised; admin-level access requires justification.",
                 "rationale": "Managed identities with high-privilege roles represent unvalidated persistent admin access."},
        "iso":  {"id": "A.8.2, A.5.15", "title": "Privileged access rights / Access control",
                 "desc": "Privileged access rights held by managed identities are restricted, monitored, and controlled.",
                 "rationale": "Managed identities with admin roles violate privileged access rights and access control requirements."},
        "ce":   {"pillar": "UAC", "title": "User Access Control",
                 "desc": "Managed identities with administrative roles require explicit authorisation and are minimised.",
                 "rationale": "Managed identity admin roles represent unrestricted privileged access without user interaction."},
        "soc2": {"id": "CC6.2, CC6.3", "title": "Access reviews and role-based access",
                 "desc": "Managed identity role assignments are reviewed; admin-level assignments require explicit authorisation.",
                 "rationale": "Managed identity admin role assignments require access reviews under CC6.2 and CC6.3."},
        "caf":  {"id": "B2", "title": "Identity and Access Control",
                 "desc": "Managed identity access to systems is controlled and privileged access is minimised.",
                 "rationale": "Managed identities with admin roles are an identity and access control risk under CAF B2."},
        "e8":   {"id": "E8-5", "title": "Restrict Administrative Privileges",
                 "desc": "Managed identities with administrative privileges are identified, reviewed, and minimised.",
                 "rationale": "Managed identities with admin directory roles represent unrestricted administrative privileges."},
        "nis2": {"id": "NIS2-j", "title": "Human resources security, access control, asset management",
                 "desc": "Managed identity privilege is managed as part of access control and asset management policy.",
                 "rationale": "Managed identities with admin roles are an access control failure under NIS2 requirements."},
    },
}

# ─────────────────────────────────────────────────────────────
#  FRAMEWORK CONTROL REMEDIATION GUIDANCE
#  Keyed by '{framework}:{control_id}' — injected into enriched
#  findings as fw_rem so the UI and Word report can show
#  framework-specific "how to fix this" guidance.
# ─────────────────────────────────────────────────────────────
FW_CONTROL_REM = {
    # ── CIS Microsoft 365 Foundations Benchmark v7.0 ──────────
    "cis:5.2.2.2": "Deploy a Conditional Access policy (Entra ID > Conditional Access > New policy) targeting All users, All cloud apps, requiring MFA as the grant control. Exclude break-glass accounts only. This directly satisfies CIS M365 Benchmark recommendation 5.2.2.2.",
    "cis:1.1.3": "Reduce Global Administrators to between 2 and 4 accounts. Reassign day-to-day admin tasks to least-privilege roles such as User Administrator or Security Administrator. Audit current assignments via Entra ID > Roles and administrators > Global Administrator.",
    "cis:5.3.1": "Enable Entra Privileged Identity Management (PIM) and convert permanent Global Administrator and other privileged role assignments to Eligible (just-in-time). Configure activation to require approval and business justification. Navigate to Entra ID > Identity Governance > Privileged Identity Management.",
    "cis:5.1.6.2": "Run an Entra ID access review targeting all guest accounts (Entra ID > Identity Governance > Access reviews). Remove guests who no longer require access. Configure a recurring quarterly review policy to maintain ongoing compliance.",
    "cis:5.2.2.6": "Enable Entra ID Identity Protection risk policies: set User Risk policy to require password reset for High risk users, and Sign-in Risk policy to require MFA for Medium and above. Navigate to Entra ID > Protection > Identity Protection > User risk policy.",
    "cis:1.1.2": "Create two break-glass accounts with strong random passwords, no MFA requirement, and explicit exclusion from all Conditional Access policies. Store credentials securely offline. Create a Log Analytics alert for any sign-in activity on these accounts.",
    "cis:5.2.2.3": "Create a CA policy: Users = All users, Cloud apps = All cloud apps, Conditions > Client apps = Legacy authentication clients (Exchange ActiveSync, Other clients), Grant = Block access. Enable in Report-only mode first, validate no legitimate dependencies, then enforce.",
    "cis:6.2.1": "Block external auto-forwarding at the organisation level: Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off. Alternatively, create a transport rule (New-TransportRule) to reject messages where the sender is internal and the ForwardingSmtpAddress is set to an external domain.",
    "cis:6.1.2": "Enable mailbox auditing globally: Set-OrganizationConfig -AuditDisabled $false. Verify with Get-OrganizationConfig | Select-Object AuditDisabled. Modern M365 tenants should have this enabled by default — confirm it has not been disabled.",
    "cis:2.1.7": "Edit the default anti-phishing policy in Microsoft 365 Defender > Email & Collaboration > Policies & Rules > Threat policies > Anti-phishing. Enable: Mailbox intelligence, Mailbox intelligence-based impersonation protection, Spoof intelligence. Consider a custom policy with stricter settings for executive accounts.",
    "cis:2.1.10": "Publish a DMARC TXT record at _dmarc.[yourdomain.com] starting with p=none for initial monitoring. Progress to p=quarantine then p=reject once SPF and DKIM are verified passing. Use a DMARC reporting service to monitor aggregate and forensic reports.",
    "cis:2.1.8 / 2.1.9": "SPF: publish v=spf1 include:spf.protection.outlook.com -all as a TXT record for each domain. DKIM: enable in Exchange Admin Centre > Email authentication > DKIM > Enable for each domain. Both must be passing before enabling DMARC enforcement.",
    "cis:2.1.6 / 2.1.7": "Enable Zero-Hour Auto Purge in Microsoft 365 Defender > Email & Collaboration > Policies: in Anti-malware default policy enable ZAP; in Anti-spam default inbound policy enable both Phishing ZAP and Spam ZAP.",
    "cis:8.2.2": "In Teams Admin Centre > Users > External access: either disable external access entirely or configure an allow list of specific trusted domains. Remove the 'Allow all external domains' setting.",
    "cis:8.2.3": "In Teams Admin Centre > Users > External access: disable 'Allow users in my org to communicate with Teams users whose accounts aren't managed by an organisation' (Teams consumer access).",
    "cis:8.5.1": "In Teams Admin Centre > Meetings > Meeting policies > Global > Participants & guests: set 'Anonymous users can join a meeting' to Off. Apply the policy to all users and validate no custom policies override this setting.",
    "cis:8.4.1": "In Teams Admin Centre > Teams apps > Permission policies > Global: change third-party apps from 'Allow all apps' to 'Block all apps', then create a custom policy or allowlist for approved apps. Implement a formal app approval process.",
    "cis:7.2.6": "In SharePoint Admin Centre > Policies > Sharing: set the SharePoint external sharing level to 'New and existing guests' (ExternalUserSharingOnly) at minimum, or 'Only people in your organisation' to disable external sharing entirely.",
    "cis:7.2.1": "In SharePoint Admin Centre > Access control > Apps that don't use modern authentication: select 'Block access'. This disables legacy authentication protocols (BasicAuth) for SharePoint Online.",
    "cis:7.2.4": "In SharePoint Admin Centre > Policies > Sharing: set the OneDrive sharing level to 'New and existing guests' or more restrictive. Note: this is a separate setting from the SharePoint site sharing level and must be configured independently.",
    "cis:7.2.9": "In SharePoint Admin Centre > Policies > Sharing > More external sharing settings: enable 'Guest access to a site or OneDrive will expire automatically after this many days' and set to 30–90 days. Also configure link expiry for anyone (anonymous) links.",
    "cis:5.1.5.1": "In Entra ID > Enterprise applications > Consent and permissions > User consent settings: set to 'Do not allow user consent'. Enable the admin consent workflow (Entra ID > Enterprise applications > Consent and permissions > Admin consent settings) so users can request access to apps.",
    "cis:3.1.1": "Verify the M365 audit log is enabled in the Microsoft Purview compliance portal > Audit. If disabled, enable it: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $True (requires Exchange Administrator). Confirm Defender for Office 365 alert policies are active.",
    "cis:4.1": "In Intune > Devices > Compliance policies: enable 'Mark devices with no compliance policy assigned as Not compliant' in Compliance policy settings. Create platform-specific policies (Windows, iOS, Android, macOS) and pair with a CA policy blocking non-compliant device access.",
    "cis:5.1.4.6": "In Intune > Endpoint security > Disk encryption: create a BitLocker policy requiring TPM-backed encryption for Windows devices. Add device encryption as a compliance policy condition. Pair with a CA policy blocking non-compliant device access to M365.",
    "cis:5.1.5.4": "In Entra ID > App registrations > [App] > Certificates & secrets: add a new client secret with a maximum 180-day lifetime. Remove all non-expiring and already-expired credentials. Implement a recurring calendar reminder or automated alert for credential expiry.",
    "cis:5.1.5.4 / 5.1.5.6": "Rotate credentials before expiry: Entra ID > App registrations > [App] > Certificates & secrets. Create the replacement credential first, update the dependent application's configuration to use it, verify, then delete the old credential. Do not delete before updating the app.",
    "cis:5.1.2.2": "Review multi-tenant app registrations in Entra ID > App registrations > [App] > Authentication. Change 'Supported account types' to 'Accounts in this organizational directory only' where multi-tenant access is not intentional. For legitimate multi-tenant apps, complete Microsoft Publisher Verification.",
    # ── NIST Cybersecurity Framework 2.0 ──────────────────────
    "nist:PR.AA-01": "Implement a credential lifecycle management process: define issuance, review, rotation, and revocation procedures. Apply to both user and application credentials. Reference NIST SP 800-63 for identity assurance requirements. Document as part of your CSF Implementation Tier.",
    "nist:PR.AA-02": "Implement identity proofing appropriate to the risk level. For admin access, require phishing-resistant credentials (FIDO2 security keys or certificate-based auth). Reference NIST SP 800-63A for identity assurance levels. Document proofing procedures.",
    "nist:PR.AA-03": "Deploy MFA via Conditional Access for all user access to M365. Align with NIST SP 800-63B Authenticator Assurance Level 2 (AAL2) at minimum. Document MFA enforcement as a mitigating control in your NIST CSF implementation profile.",
    "nist:PR.AA-05": "Implement role-based access control with documented role definitions. Conduct quarterly access reviews and remove permissions beyond role requirements. Document access control decisions and reviews as part of your NIST CSF implementation evidence.",
    "nist:PR.DS-01": "Apply encryption-at-rest controls: enable BitLocker on endpoints, apply M365 sensitivity labels to classified data, enable SharePoint at-rest encryption (on by default). Reference NIST SP 800-111 for storage encryption guidance.",
    "nist:PR.DS-02": "Apply TLS/encryption-in-transit for all data flows. Block insecure protocols (legacy auth, BasicAuth). Enable DKIM/DMARC/SPF for email authentication. Reference NIST SP 800-52 Rev 2 for TLS implementation guidance.",
    "nist:PR.PS-01": "Document a configuration management baseline for M365 services, aligned to CIS Benchmarks. Enforce baseline configurations via Intune configuration profiles. Review configurations quarterly and after significant changes.",
    "nist:PR.PS-04": "Enable and retain security logs for all key M365 services. Configure log retention: 90 days minimum (180 days recommended for security investigation). Ingest into Microsoft Sentinel or equivalent SIEM. Reference NIST SP 800-92 for log management guidance.",
    "nist:PR.IR-01": "Apply network boundary controls: configure SharePoint and Teams external access restrictions. Implement CA policies requiring compliant devices or trusted network locations. Reference NIST SP 800-41 for boundary protection guidance.",
    "nist:DE.AE-02": "Establish an event analysis process: connect M365 audit logs to Microsoft Sentinel. Configure detection analytics rules for key threat scenarios (mass file download, impossible travel, suspicious inbox rules). Review alerts on a defined schedule.",
    "nist:DE.CM-01": "Enable security monitoring across all M365 services: connect Microsoft Defender for Office 365 and Microsoft Sentinel. Configure alert policies for high-severity events. Establish a defined alert review cadence (daily recommended).",
    "nist:DE.CM-09": "Deploy Defender for Endpoint across all managed devices. Integrate with Intune via the MDE connector. Monitor device health signals and risk scores via Intune and the Defender portal. Alert on device risk changes.",
    "nist:ID.AM-01": "Maintain an accurate asset inventory: use Entra ID for identities and app registrations, Intune for managed devices, and Microsoft 365 admin centre for licence assignments. Review monthly and after offboarding events.",
    "nist:ID.RA-01": "Implement vulnerability management for M365 configurations: review Microsoft Secure Score monthly, subscribe to Microsoft Security Response Centre advisories, track identified gaps through to remediation. Document in a vulnerability register.",
    # ── ISO 27001:2022 Annex A ─────────────────────────────────
    "iso:A.5.9": "Maintain a current software asset register including M365 licences, app registrations, and connected applications. Review quarterly. Include in your ISMS asset inventory and reference in your Statement of Applicability (SoA) against A.5.9.",
    "iso:A.5.14": "Define and implement an information transfer policy. Block unauthorised email auto-forwarding. Apply data classification and transfer controls appropriate to each classification level. Document transfer controls in your SoA against A.5.14.",
    "iso:A.5.15": "Document an access control policy defining access principles (least privilege, need-to-know). Implement RBAC and CA policies. Conduct annual access reviews (quarterly for privileged accounts). Include CA policies as A.5.15 mitigating controls in your SoA.",
    "iso:A.5.17": "Define an authentication information management procedure covering creation, use, rotation, and revocation of credentials (user passwords and application secrets). Enforce expiry and complexity. Reference in your SoA against A.5.17.",
    "iso:A.5.18": "Conduct formal access rights reviews at defined intervals (minimum annually, quarterly for privileged access). Document review outcomes. Remove access rights promptly on role change or departure. Record evidence for ISO audit.",
    "iso:A.5.23": "Define a cloud service security policy covering M365. Document security responsibilities, SLA requirements, and monitoring arrangements. Include in your SoA against A.5.23. Review annually or after significant service changes.",
    "iso:A.5.25": "Establish a security event assessment procedure: define criteria for classifying events, escalation thresholds, and response timelines. Document how M365 Defender alerts are triaged and escalated. Include in your incident management procedure.",
    "iso:A.5.35": "Conduct periodic independent reviews of M365 security controls (at least annually). Use this assessment output as documented review evidence. Record findings and corrective actions for ISO audit. Include review scope and frequency in your SoA.",
    "iso:A.8.1": "Document an endpoint device management policy covering all device types including mobile. Apply Intune compliance and configuration policies for each platform. Include device management as an A.8.1 control in your SoA.",
    "iso:A.8.2": "Document a privileged access management procedure. Implement Entra PIM for just-in-time privilege. Conduct quarterly privileged account reviews. Include PIM configuration as an A.8.2 mitigating control in your SoA.",
    "iso:A.8.3": "Define information access restriction controls: implement SharePoint sensitivity labels, site-level access permissions, and sharing restrictions. Document access restriction measures in your SoA against A.8.3.",
    "iso:A.8.5": "Document an authentication policy requiring MFA for all users accessing information systems. Implement MFA enforcement via Conditional Access. Record the CA policy configuration as an A.8.5 mitigating control in your SoA.",
    "iso:A.8.7": "Implement anti-malware controls at the email gateway, endpoint, and cloud layers. Configure Defender for Office 365 threat policies and Defender for Endpoint. Document the multi-layer protection in your SoA against A.8.7.",
    "iso:A.8.8": "Establish a patch management procedure with defined timeframes (critical: 48 hours, high: 14 days, medium: 30 days). Use Intune Update Rings for OS patching. Document the procedure and evidence of compliance in your SoA against A.8.8.",
    "iso:A.8.9": "Document a configuration management process. Apply and enforce secure configurations via Intune profiles. Baseline against CIS M365 Benchmarks. Reference configuration policies in your SoA against A.8.9.",
    "iso:A.8.15": "Enable comprehensive logging for all M365 services. Retain logs for a minimum of 12 months. Define a log review procedure. Include logging controls in your SoA against A.8.15 and provide log samples as ISO audit evidence.",
    "iso:A.8.16": "Establish a monitoring procedure for M365 activity. Review security alerts daily. Integrate with Microsoft Sentinel or equivalent SIEM. Include monitoring controls in your SoA against A.8.16.",
    "iso:A.8.20": "Document a network security policy including M365 access boundaries. Apply SharePoint, Teams, and Exchange external access controls as network boundary controls. Reference in your SoA against A.8.20.",
    "iso:A.8.24": "Define a cryptography policy: mandate TLS for data in transit, BitLocker for device storage, DKIM for email signing, and sensitivity label encryption for classified data. Document and reference in your SoA against A.8.24.",
    "iso:A.8.26": "Define application security requirements for all apps connecting to M365. Assess and document OAuth app permissions. Include app security requirements in your secure development/procurement policy and SoA against A.8.26.",
    # ── Cyber Essentials v3.3 ──────────────────────────────────
    "ce:UAC": "Ensure MFA is enabled for all user accounts accessing cloud services. Remove admin rights from accounts that don't require them. Separate admin accounts from day-to-day user accounts. Certify compliance via the Cyber Essentials self-assessment questionnaire or Cyber Essentials Plus technical audit.",
    "ce:SC": "Configure M365 services following the Cyber Essentials Secure Configuration requirement: disable unnecessary services, apply CIS Benchmark Level 1 settings, remove default or unnecessary accounts. Certify configurations during the Cyber Essentials assessment.",
    "ce:MP": "Ensure Defender for Office 365 is enabled with anti-malware, anti-phishing (with intelligence), and ZAP configured. Enable Defender for Endpoint on all managed devices. Malware protection must cover all boundary firewalls and internet-connected devices.",
    "ce:FW": "Configure SharePoint and Teams external access controls to restrict inbound communications to approved domains, or disable external access where not required. Treat M365 external access restrictions as boundary firewall controls for the purposes of Cyber Essentials.",
    "ce:PM": "Apply the Cyber Essentials patch management requirement: all software must be updated with vendor-supported patches within 14 days of release (critical/high vulnerabilities) or removed if patches are unavailable. Enforce via Intune Update Rings for OS and app patching.",
    # ── SOC 2 Trust Services Criteria ─────────────────────────
    "soc2:CC6.1": "Implement logical access controls: enforce MFA via CA policy, apply device compliance as an access condition, document access restriction mechanisms. Evidence for audit: CA policy screenshots, sign-in log exports, and Intune compliance reports.",
    "soc2:CC6.2": "Document and implement access authorisation procedures. Conduct periodic access reviews with documented approval records. Evidence for audit: access review records, approval tickets, and Entra ID role assignment reports.",
    "soc2:CC6.3": "Implement role-based access control with documented role definitions. Remove access beyond role requirements at role changes. Evidence for audit: RBAC policy, Entra ID group membership reports, and access review records.",
    "soc2:CC6.5": "Protect user credentials using MFA. Disable weak authentication methods (SMS, voice, email OTP where possible). Evidence for audit: authentication method policy settings and MFA registration reports.",
    "soc2:CC6.6": "Apply network boundary controls: configure CA policies requiring compliant devices or named locations. Restrict external access to M365 services. Evidence for audit: CA policy configuration, conditional access named locations.",
    "soc2:CC6.7": "Apply data transfer restrictions: block auto-forwarding, restrict external sharing, apply sensitivity labels. Evidence for audit: transport rules, SharePoint sharing policy settings, DLP policy reports.",
    "soc2:CC6.8": "Apply change management controls: restrict app consent, review OAuth permissions, document approved configuration changes. Evidence for audit: change log, app permission audit report, consent policy settings.",
    "soc2:CC7.1": "Implement security monitoring: configure Defender alert policies, integrate Microsoft Sentinel, establish a defined alert review procedure. Evidence for audit: alert policy configuration, SIEM integration records, and alert review log.",
    "soc2:CC7.2": "Enable anomaly detection: configure Entra ID Identity Protection risk policies, review risky users and sign-ins weekly. Evidence for audit: Identity Protection policy settings, risk event reports.",
    "soc2:CC7.3": "Document and test incident response procedures. Define escalation paths for Defender alerts. Review and close incidents within defined SLAs. Evidence for audit: incident response plan, incident tickets, test records.",
    # ── NCSC Cyber Assessment Framework v4.0 ──────────────────
    "caf:A2": "Conduct a documented M365 risk assessment identifying key threats, vulnerabilities, and controls. Review annually and after significant changes. Record risk treatment decisions in a risk register. Provide the risk register as CAF assessment evidence.",
    "caf:B2": "Implement enforced MFA via CA policies, PIM for privileged access, and RBAC for all users. Conduct quarterly access reviews. Document controls and provide CA policy exports, PIM configurations, and access review records as CAF B2 evidence.",
    "caf:B3": "Classify organisational data in M365 using sensitivity labels. Apply label-based access controls and sharing restrictions to high-value data. Monitor data access via Microsoft Defender. Document data security controls as CAF B3 evidence.",
    "caf:B4": "Harden M365 configurations against CIS Benchmark. Apply Intune compliance and configuration policies. Patch operating systems within 14 days. Enable Defender for Endpoint. Provide configuration audit reports and patch compliance data as CAF B4 evidence.",
    "caf:C1": "Enable Microsoft Sentinel and connect the Microsoft 365 Defender data connector. Configure analytics rules for high-priority scenarios (impossible travel, mass file download, suspicious inbox rules). Establish a defined alert review and escalation process. Provide SIEM configuration and alert logs as CAF C1 evidence.",
    "caf:C2": "Implement proactive security discovery: track Microsoft Secure Score monthly, review Entra ID Protection risk reports weekly, conduct periodic configuration audits against CIS Benchmark. Document findings and remediation as CAF C2 evidence.",
    # ── Australian Essential Eight (ASD 2024) ─────────────────
    "e8:E8-1": "Configure Teams app permission policies to permit only approved applications (allow-list). Maintain a formal approved app register. Route all new app requests through a defined approval process before allowlisting.",
    "e8:E8-2": "Configure Intune Update Rings for application patching. Set critical patch deployment to within 48 hours and other security patches to within two weeks. Monitor compliance via Intune patch compliance reports.",
    "e8:E8-4": "Enable Microsoft Defender for Office 365: configure Safe Links and Safe Attachments. Apply Intune configuration profiles to disable macros from internet-sourced files. Configure Office protected view settings to prevent auto-execution of untrusted content.",
    "e8:E8-5": "Remove unnecessary admin role assignments. Implement Entra PIM for just-in-time privilege. Restrict admin account use to admin tasks only. Audit privileged access monthly and remove unused assignments. Implement dedicated admin accounts separate from user accounts.",
    "e8:E8-6": "Configure Intune Update Rings for Windows OS patching. Apply critical OS patches within 48 hours and other security patches within two weeks. Monitor via Intune patch compliance reports. Automate reporting to identify non-compliant devices.",
    "e8:E8-7": "Enforce MFA for all users via Conditional Access. Implement phishing-resistant methods: Microsoft Authenticator with number matching and additional context (Maturity Level 2), or FIDO2 security keys (Maturity Level 3). Disable SMS/voice MFA for highest maturity.",
    # ── EU NIS2 Article 21 ────────────────────────────────────
    "nis2:NIS2-a": "Develop and maintain an information security risk management policy for M365, aligned to Article 21(2)(a). Document the risk assessment methodology, risk register, and treatment decisions. Review annually and submit to the relevant NIS2 competent authority if required.",
    "nis2:NIS2-b": "Establish an incident detection and response procedure for M365 security events, meeting NIS2 notification timelines: initial notification within 24 hours, detailed report within 72 hours, final report within one month. Test annually. Designate a responsible contact for authority reporting.",
    "nis2:NIS2-f": "Implement a vulnerability management procedure meeting Article 21(2)(f): subscribe to Microsoft Security Response Centre advisories, apply patches within defined timeframes, and maintain a vulnerability register. Disclose significant vulnerabilities to the competent authority as required.",
    "nis2:NIS2-i": "Define a cryptography and encryption policy aligned to Article 21(2)(i): mandate TLS for data in transit, BitLocker/device encryption for data at rest, DKIM for email signing. Document the policy and provide evidence for competent authority review.",
    "nis2:NIS2-j": "Implement and document access control policies covering all user types (employees, contractors, guests, service accounts), satisfying Article 21(2)(j). Enforce MFA, PIM for privileged access, and quarterly access reviews. Maintain evidence for competent authority review.",
    "nis2:NIS2-k": "Deploy MFA enforcement via Conditional Access for all users, satisfying Article 21(2)(k). Implement phishing-resistant methods where possible. Document MFA coverage, any approved exclusions, and the rationale for those exclusions. Maintain evidence for competent authority review.",
}

def _inject_fw_rem(fw_map):
    """Inject fw_rem (framework-specific remediation) into each framework entry."""
    if not fw_map:
        return fw_map
    result = {}
    for fw_key, fw_entry in fw_map.items():
        if fw_entry is None:
            result[fw_key] = None
            continue
        entry = dict(fw_entry)
        # Look up remediation by framework + control ID (or pillar for CE)
        control_id = entry.get("id") or entry.get("pillar", "")
        rem_key = f"{fw_key}:{control_id}"
        rem = FW_CONTROL_REM.get(rem_key)
        if rem:
            entry["fw_rem"] = rem
        result[fw_key] = entry
    return result


# ─────────────────────────────────────────────────────────────
#  FINDINGS LIBRARY
# ─────────────────────────────────────────────────────────────
def build_findings_library():
    findings = [
        # Identity
        {"id":"ID-001","title":"Low MFA Coverage","module":"identity","metric":"mfa_percentage","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 95,
         "description":"Fewer than 95% of licensed users have MFA registered. This significantly increases account compromise risk.",
         "recommendation":"Enable MFA for all users via Conditional Access. Consider enabling Security Defaults if no CA policies exist.",
         "severity_reason":"Critical because credential-only access at scale is the single highest-exploited attack vector — even a 5% gap exposes hundreds of accounts to password spray and phishing.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 16},

        {"id":"ID-002","title":"Excessive Global Administrators","module":"identity","metric":"global_admin_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 3,
         "description":"More than 3 Global Administrators detected. Global Admin is the highest-privilege role and should be minimised.",
         "recommendation":"Reduce Global Admins to 2–3 break-glass accounts. Use least-privilege roles for day-to-day admin tasks.",
         "severity_reason":"High because each additional permanent Global Admin multiplies the blast radius of a single compromised account, but the risk requires active targeting of an admin account to materialise.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 5},

        {"id":"ID-003","title":"No Privileged Identity Management","module":"identity","metric":"pim_enabled","severity":"high",
         "threshold": lambda v: v is False,
         "description":"PIM is not in use. Permanent role assignments expand the attack surface unnecessarily.",
         "recommendation":"Enable Entra PIM and convert permanent admin role assignments to eligible (just-in-time) assignments.",
         "severity_reason":"High because permanent admin roles grant standing privileges that attackers can exploit immediately after credential compromise, removing the time-window defence of just-in-time access.",
         "effort":"Medium","effort_hours":8,
         "secure_score_impact": 10},

        {"id":"ID-004","title":"High Guest User Count","module":"identity","metric":"guest_user_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 50,
         "description":"A large number of guest accounts exist in the tenant. Unreviewed guests represent a data exposure risk.",
         "recommendation":"Implement an access review policy for guest accounts. Remove guests who no longer require access.",
         "severity_reason":"Medium because unreviewed guests are a latent risk, not an active gap — the exposure depends on what data those guests can reach and whether their accounts remain active.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 3},

        {"id":"ID-005","title":"Unused Licences","module":"identity","metric":"unassigned_licence_percentage","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 20,
         "description":"More than 20% of purchased licences are unassigned, representing unnecessary cost.",
         "recommendation":"Audit unassigned licences and remove from the subscription where no longer required.",
         "severity_reason":"Medium for financial and governance risk — unassigned licences carry no direct security impact but indicate poor access lifecycle management and unnecessary spend.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 0},

        # Security & CA
        {"id":"SEC-001","title":"Low Secure Score","module":"security","metric":"secure_score_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 50,
         "description":"Microsoft Secure Score is below 50%, indicating significant security controls are missing.",
         "recommendation":"Review the Secure Score dashboard in Defender portal. Prioritise high-impact, low-effort recommendations first.",
         "severity_reason":"High because a sub-50% Secure Score indicates a broad range of baseline controls are absent across multiple attack surfaces — it is a symptom of systemic under-configuration.",
         "effort":"High","effort_hours":40,
         "secure_score_impact": 0},

        {"id":"SEC-002","title":"Security Defaults Disabled — No CA Policies","module":"security","metric":"security_defaults_enabled","severity":"critical",
         "threshold": lambda v, m: v is False and m.get("ca_enabled_policy_count", 0) == 0,
         "description":"Security Defaults are disabled and no compensating Conditional Access policies may be in place.",
         "recommendation":"Either re-enable Security Defaults or implement an equivalent baseline CA policy set covering MFA and legacy auth blocking.",
         "severity_reason":"Critical because with neither Security Defaults nor Conditional Access, the tenant has zero enforced authentication controls — any credential gives full access.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 12},

        {"id":"CA-001","title":"No Conditional Access Policies Enabled","module":"security","metric":"ca_enabled_policy_count","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No enabled Conditional Access policies found. Access to M365 is not context-aware.",
         "recommendation":"Deploy baseline CA policies: MFA for all users, MFA for admins, block legacy auth, require compliant devices.",
         "severity_reason":"Critical because Conditional Access is the primary enforcement layer for M365 access — its complete absence means all users authenticate with no context-aware checks whatsoever.",
         "effort":"Medium","effort_hours":8,
         "secure_score_impact": 15},

        {"id":"CA-002","title":"Legacy Authentication Not Blocked","module":"security","metric":"legacy_auth_blocked","severity":"critical",
         "threshold": lambda v: v is False,
         "description":"Legacy authentication protocols are not blocked. These bypass MFA and are heavily exploited.",
         "recommendation":"Create a CA policy to block all legacy authentication. Audit dependencies before enforcing.",
         "severity_reason":"Critical because legacy protocols bypass MFA entirely, providing attackers a direct path to credential-only authentication regardless of how many CA policies are in place.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 10},

        {"id":"CA-003","title":"No CA Policy Enforcing MFA for All Users","module":"security","metric":"mfa_all_users_ca_policy","severity":"critical",
         "threshold": lambda v: v is False,
         "description":"There is no Conditional Access policy that enforces multi-factor authentication for all users. Even with CA policies in place, if none of them target all users with an MFA requirement, entire user populations can authenticate with just a password. Credential stuffing, phishing and password spray attacks succeed instantly against accounts with no MFA enforcement.",
         "recommendation":"Create a CA policy targeting all users (excluding break-glass accounts), all cloud apps, and requiring MFA as the grant control. This is the single most impactful CA control you can deploy. Test with a pilot group first, then broaden to all users.",
         "severity_reason":"Critical because without a policy explicitly requiring MFA for all users, any unprotected account is a viable attack path — one uncovered user is enough for a successful credential compromise.",
         "effort":"Low","effort_hours":3,
         "secure_score_impact": 10},

        # Exchange
        {"id":"EXO-001","title":"Auto-Forwarding Allowed to External","module":"exchange","metric":"external_forwarding_blocked","severity":"high",
         "threshold": lambda v: v is False,
         "description":"Automatic email forwarding to external recipients is not blocked. This is a common data exfiltration vector.",
         "recommendation":"Set AutoForwardingMode to 'Automatic' block in the outbound spam filter policy, or create a transport rule to block external auto-forwarding.",
         "severity_reason":"High because silent external forwarding is a confirmed BEC indicator — once configured by an attacker, email intelligence leaks indefinitely with no user awareness.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        {"id":"EXO-002","title":"Mailbox Auditing Disabled","module":"exchange","metric":"mailbox_audit_enabled_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 90,
         "description":"Mailbox auditing is not enabled for all mailboxes. Audit logs are essential for forensic investigation.",
         "recommendation":"Enable mailbox auditing organisation-wide using Set-OrganizationConfig -AuditDisabled $false.",
         "severity_reason":"High because without mailbox audit logs, forensic investigation of email-based incidents is impossible — you cannot determine what was read, deleted, or forwarded after a compromise.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        {"id":"EXO-003","title":"Anti-Phishing Intelligence Disabled","module":"exchange","metric":"antiphish_intelligence_enabled","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Mailbox intelligence in anti-phishing policies is not enabled, reducing protection against targeted attacks.",
         "recommendation":"Enable mailbox intelligence and impersonation protection in the anti-phishing policy.",
         "severity_reason":"Medium because mailbox intelligence adds targeted-attack protection, but the baseline anti-phishing policy still operates — the gap is meaningful but not a complete absence of email filtering.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        # Teams
        {"id":"TEAMS-001","title":"Unrestricted External Access","module":"teams","metric":"teams_external_access_restricted","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Teams external access (federation) is not restricted. Users can communicate with any external Teams tenant.",
         "recommendation":"Restrict Teams external access to approved domains only, or disable it if not required.",
         "severity_reason":"Medium because unrestricted federation expands the social engineering surface, but requires an active attacker with a Teams tenant — it is not a passive vulnerability.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 3},

        {"id":"TEAMS-002","title":"Teams Consumer Access Enabled","module":"teams","metric":"teams_consumer_access_blocked","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Users can communicate with Teams personal/consumer accounts, increasing data leakage risk.",
         "recommendation":"Disable Teams consumer access unless there is a specific business requirement.",
         "severity_reason":"Medium because personal Teams accounts have weaker identity assurance, but exploitation requires user-initiated contact — the risk is behavioural rather than a direct technical exposure.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 3},

        {"id":"TEAMS-003","title":"Anonymous Users Can Join Meetings","module":"teams","metric":"teams_anon_meeting_join_enabled","severity":"medium",
         "threshold": lambda v: v is True,
         "description":"The global Teams meeting policy allows anonymous users to join meetings without authentication. Anyone with a meeting link can join as a guest with no identity verification. This enables uninvited participants to join internal calls, access shared content, and potentially record sensitive discussions.",
         "recommendation":"In the Teams Admin Centre, go to Meetings > Meeting policies > Global > Participants & guests. Set 'Anonymous users can join a meeting' to Off. Create an exception policy for specific users or groups with a legitimate need.",
         "severity_reason":"Medium because meeting infiltration requires possession of a valid meeting link — the risk is meaningful for sensitive discussions but does not expose underlying tenant data or enable further access.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 3},

        {"id":"TEAMS-004","title":"Third-Party Teams Apps Unrestricted","module":"teams","metric":"teams_third_party_apps_allowed","severity":"medium",
         "threshold": lambda v: v is True,
         "description":"The global Teams app permission policy allows all third-party apps from the Teams store without restriction. Users can install apps that have permissions to read messages, files, and meeting content. Malicious or compromised third-party apps are a growing attack surface in Teams environments.",
         "recommendation":"In Teams Admin Centre, go to Teams apps > Permission policies > Global. Change third-party apps from Allow all to either Block all or allow specific approved apps only. Review and approve a whitelist of business-critical third-party apps.",
         "severity_reason":"Medium because broad app permissions create ongoing data access risk, but exploitation depends on app behaviour and requires a user to install the app — not an immediate passive attack path.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 2},

        # SharePoint
        {"id":"SPO-001","title":"SharePoint Sharing Set to Anyone","module":"sharepoint","metric":"spo_sharing_level","severity":"critical",
         "threshold": lambda v: v == "ExternalUserAndGuestSharing",
         "description":"SharePoint/OneDrive external sharing is set to Anyone, allowing unauthenticated link sharing.",
         "recommendation":"Restrict sharing to 'New and existing guests' (ExternalUserSharingOnly) at minimum. Review per site collection.",
         "severity_reason":"Critical because Anyone links expose data to the entire internet with no authentication — a single forwarded link makes the content accessible to anyone, with no audit trail or access control.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 8},

        {"id":"SPO-002","title":"Legacy Authentication Enabled in SharePoint","module":"sharepoint","metric":"spo_legacy_auth","severity":"high",
         "threshold": lambda v: v is True,
         "description":"Legacy authentication protocols are enabled in SharePoint, bypassing modern auth controls.",
         "recommendation":"Disable LegacyAuthProtocolsEnabled in SharePoint tenant settings.",
         "severity_reason":"High because legacy auth in SharePoint bypasses modern CA controls, providing a SharePoint-specific authentication bypass path even if legacy auth is blocked elsewhere.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        {"id":"SPO-003","title":"OneDrive External Sharing Unrestricted","module":"sharepoint","metric":"onedrive_sharing_level","severity":"high",
         "threshold": lambda v: v == "ExternalUserAndGuestSharing",
         "description":"OneDrive for Business external sharing is set to Anyone, allowing users to create unauthenticated sharing links. SharePoint and OneDrive have separate sharing settings — a tenant can restrict SharePoint while leaving OneDrive open. Files shared via anonymous links are accessible to anyone with the URL, with no authentication or audit trail.",
         "recommendation":"In SharePoint Admin Centre, go to Policies > Sharing and set the OneDrive sharing level to 'New and existing guests' or more restrictive. This setting is separate from the SharePoint sharing level.",
         "severity_reason":"High because OneDrive sharing is a separate setting — a restricted SharePoint policy does not protect it, leaving personal file storage fully open for anonymous link sharing.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        {"id":"SPO-004","title":"Guest Access Expiry Not Configured","module":"sharepoint","metric":"guest_access_expiry_configured","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"External user (guest) access expiry is not configured. Shared links and guest accounts granted to contractors, partners, or clients do not automatically expire. Former employees of partner organisations, ex-contractors, and deprecated service accounts retain access indefinitely unless manually removed.",
         "recommendation":"In SharePoint Admin Centre, go to Policies > Sharing > More external sharing settings. Enable 'Guest access to a site or OneDrive will expire automatically after this many days' and set a value appropriate for your business (30–90 days is typical). Also enable link expiry for anonymous sharing links.",
         "severity_reason":"Medium because indefinite guest access is a governance gap that accumulates over time — each departing contractor retains data access until manually removed, which rarely happens in practice.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 3},

        # Over-Permissioned Apps
        {"id":"APP-001","title":"High-Privilege OAuth Apps Detected","module":"security","metric":"high_privilege_app_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more third-party OAuth applications have been granted high-privilege permissions across the tenant. These apps have persistent access to data even after users log out, and are a common persistence mechanism used by attackers following account compromise.",
         "recommendation":"Review all OAuth app permissions in Entra ID under Enterprise Applications. Remove or restrict apps that have unnecessary Graph permissions such as Mail.ReadWrite, Files.ReadWrite.All, or Directory.ReadWrite.All. Enable admin consent workflow to prevent users granting app permissions without approval.",
         "severity_reason":"High because applications with tenant-wide permissions create persistent access that survives password resets — a compromised app credential grants attacker-level data access across the entire organisation.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 5},

        # Alerting and Monitoring
        {"id":"MON-001","title":"No Active Defender Alert Policies","module":"security","metric":"defender_alert_policy_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Microsoft Defender alert policies are active. Without alerting, security incidents such as mass file downloads, impossible travel sign-ins, or malware detections will not be flagged to administrators in real time.",
         "recommendation":"Enable Microsoft Defender for Office 365 and configure alert policies for high-severity events including suspicious inbox rules, mass file deletion, impossible travel, and malware detected. Ensure alerts are routed to a monitored mailbox or SIEM.",
         "severity_reason":"High because without alerting, security incidents remain invisible to administrators — all other controls become less effective when breaches go undetected for days or weeks.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 5},

        {"id":"SEC-003","title":"MFA Fatigue Protection Not Enabled","module":"security","metric":"mfa_number_matching_enabled","severity":"high",
         "threshold": lambda v: v is False,
         "description":"Microsoft Authenticator number matching and additional context (sign-in location and app name) are not enabled. Without these, users are vulnerable to MFA fatigue attacks where an attacker repeatedly sends push notifications until the user approves one.",
         "recommendation":"Enable number matching and additional context in the Authenticator app settings under Entra ID Authentication Methods. This ensures users see the number displayed on screen before approving, making accidental approvals impossible.",
         "severity_reason":"High because number matching blocks the most common MFA bypass technique in current threat campaigns — a free, single-toggle fix that removes a well-documented, actively exploited attack path.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},

        {"id":"SEC-004","title":"Weak MFA Methods Enabled","module":"security","metric":"weak_auth_methods_enabled","severity":"medium",
         "threshold": lambda v: v is True,
         "description":"One or more weak authentication methods (SMS text, voice call, or email OTP) are enabled in the tenant. These methods can be intercepted via SIM swapping, call forwarding, or phishing, and are significantly less secure than the Microsoft Authenticator app or FIDO2 keys.",
         "recommendation":"Disable SMS, voice call, and email OTP authentication methods in Entra ID under Authentication Methods policies. Migrate users to Microsoft Authenticator app with number matching, or FIDO2 security keys for highest assurance.",
         "severity_reason":"Medium because SMS and voice MFA still provide meaningful friction compared to no MFA — the elevated risk requires a targeted SIM-swap or SS7 attack, not a mass credential spray.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 8},

        {"id":"SEC-005","title":"Users Can Consent to Apps Without Admin Approval","module":"security","metric":"user_consent_unrestricted","severity":"high",
         "threshold": lambda v: v is True,
         "description":"Users are permitted to grant OAuth application permissions to access company data without administrator approval. This allows malicious or over-permissioned apps to gain access to email, files, and other sensitive data simply by convincing a user to click Accept.",
         "recommendation":"Restrict user consent to apps in Entra ID under Enterprise Applications > Consent and Permissions. Set to admin consent required, and enable the admin consent workflow so users can request access through an approved process.",
         "severity_reason":"High because unrestricted user consent is the primary delivery mechanism for OAuth phishing — a single user clicking Accept grants an attacker persistent data access that survives password resets.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 5},
        # Intune
        {"id":"MDM-001","title":"Low Device Compliance","module":"intune","metric":"intune_compliance_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 80,
         "description":"Fewer than 80% of managed devices are compliant. Non-compliant devices may lack encryption or current patches.",
         "recommendation":"Review non-compliant devices in Intune portal. Identify common failures and remediate. Consider blocking non-compliant device access to M365.",
         "severity_reason":"High because non-compliant devices accessing M365 may lack encryption, patches, or antivirus — they are potential entry points that cannot be trusted with corporate data.",
         "effort":"Medium","effort_hours":8,
         "secure_score_impact": 5},

        {"id":"MDM-002","title":"No Compliance Policies Configured","module":"intune","metric":"intune_compliance_policy_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Intune device compliance policies are in place. Devices cannot be evaluated for compliance.",
         "recommendation":"Create compliance policies for each device platform (Windows, iOS, Android) covering OS version, encryption, and antivirus requirements.",
         "severity_reason":"High because without any compliance policies, device trust is undefined — CA policies requiring compliant devices cannot function, making device-based access controls entirely inoperable.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 8},

        # New v1.2 findings
        {"id":"ID-006","title":"Risky Users Not Reviewed","module":"identity","metric":"risky_users_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more users are flagged as high or medium risk by Entra ID Identity Protection and have not been remediated or dismissed. Risky users indicate potential compromised accounts.",
         "recommendation":"Review risky users in Entra ID > Protection > Risky users. Require password reset or MFA re-registration for at-risk accounts. Investigate the risk events behind each flagged user.",
         "severity_reason":"High because unreviewed risky users are flagged by Identity Protection as likely compromised — ignoring them means accepting an active threat within the tenant.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 5},

        {"id":"ID-007","title":"No Emergency Access Account Detected","module":"identity","metric":"emergency_access_exists","severity":"high",
         "threshold": lambda v: v is False,
         "description":"No break-glass (emergency access) account was detected. Without an emergency access account, a misconfigured Conditional Access policy or MFA outage could lock administrators out of the tenant.",
         "recommendation":"Create at least two emergency access accounts. Exclude them from all CA policies. Store credentials securely offline. Monitor for any sign-in activity on these accounts as an indicator of compromise.",
         "severity_reason":"High because a misconfigured CA policy without a break-glass account can result in a complete, irreversible admin lockout — recovery requires engaging Microsoft Support, which takes days.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"SEC-006","title":"No Microsoft Sentinel Connected","module":"security","metric":"sentinel_connected","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Microsoft Sentinel does not appear to be connected or generating security alerts. Without a SIEM, threats across M365 services may not be correlated or retained for investigation.",
         "recommendation":"Deploy Microsoft Sentinel and connect the Microsoft 365 Defender data connector. Configure analytics rules for high-priority scenarios and set up a regular alert review process.",
         "severity_reason":"Medium because without a SIEM, threat correlation and long-term log retention are absent — but in-product Defender alerting partially compensates and Sentinel requires significant investment to deploy.",
         "effort":"High","effort_hours":16,
         "secure_score_impact": 3},

        {"id":"EXO-004","title":"DMARC Not Configured","module":"exchange","metric":"dmarc_configured","severity":"high",
         "threshold": lambda v: v is False,
         "description":"DMARC is not configured on the primary domain. Without DMARC, attackers can spoof your domain in phishing emails, impersonating your organisation to external recipients.",
         "recommendation":"Publish a DMARC TXT record at _dmarc.yourdomain.com. Start with p=none for monitoring, then progress to p=quarantine and p=reject once SPF and DKIM are confirmed working.",
         "severity_reason":"High because without DMARC, your domain can be spoofed in external phishing campaigns — attackers can impersonate your organisation to clients and partners with no technical barrier.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 5},

        {"id":"EXO-005","title":"SPF or DKIM Not Configured","module":"exchange","metric":"spf_dkim_configured","severity":"high",
         "threshold": lambda v: v is False,
         "description":"SPF or DKIM email authentication is not fully configured on the primary domain. Without both controls, outbound emails may be rejected by recipients and the domain can be spoofed.",
         "recommendation":"Ensure an SPF TXT record exists for your domain. Enable DKIM signing in Exchange Online Admin > Email authentication. Both must pass before DMARC enforcement is safe to enable.",
         "severity_reason":"High because SPF and DKIM are prerequisites for DMARC and email deliverability — their absence means outbound mail authenticity cannot be verified, and domain spoofing has no cryptographic barrier.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 5},

        {"id":"EXO-006","title":"Zero-Hour Auto Purge (ZAP) Not Fully Enabled","module":"exchange","metric":"zap_fully_enabled","severity":"high",
         "threshold": lambda v: v is False,
         "description":"Zero-Hour Auto Purge (ZAP) is not fully enabled for malware, phishing, or spam. ZAP retroactively removes emails already delivered to mailboxes when they are later identified as malicious. Without ZAP, emails that bypass initial filters remain in user mailboxes permanently — giving attackers a lasting foothold for credential theft, business email compromise, and malware delivery.",
         "recommendation":"In the Microsoft 365 Defender portal, go to Email & Collaboration > Policies & Rules > Threat policies. Under Anti-malware, edit the default policy and ensure ZAP is enabled. Under Anti-spam, edit the default inbound policy and ensure both Phishing ZAP and Spam ZAP are enabled.",
         "severity_reason":"High because ZAP is the last line of defence against emails that evade initial filtering — without it, delivered malicious emails remain in mailboxes permanently as persistent attack vectors.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 4,
         "tags": ["email", "defender", "zap", "malware", "phishing"]},

        {"id":"MDM-003","title":"No Windows Update Ring Configured","module":"intune","metric":"update_ring_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Windows Update for Business rings are configured in Intune. Without update rings, Windows devices may receive patches inconsistently or too late, leaving known vulnerabilities unpatched.",
         "recommendation":"Create at least one Windows Update ring in Intune targeting Windows devices. Consider a Pilot ring and a Production ring with a deferral period to catch problematic updates before broad rollout.",
         "severity_reason":"Medium because inconsistent patching creates exploitable vulnerabilities over time, but M365 cloud services are not directly affected — endpoint risk compounds when combined with weak CA controls.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"MDM-004","title":"BitLocker Not Enforced","module":"intune","metric":"bitlocker_enforced","severity":"high",
         "threshold": lambda v: v is False,
         "description":"BitLocker disk encryption does not appear to be required by Intune compliance or configuration policies. Devices without encryption expose all data if lost or stolen.",
         "recommendation":"Create an Intune device configuration profile enabling BitLocker on Windows devices. Add a compliance policy condition requiring device encryption, and block non-compliant devices from accessing M365.",
         "severity_reason":"High because an unencrypted device that is lost or stolen exposes all locally cached M365 data — email, files, and authentication tokens — with no access barrier whatsoever.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 8},

        {"id":"MDM-005","title":"No Mobile Device Compliance Policy","module":"intune","metric":"mobile_compliance_policy_exists","severity":"high",
         "threshold": lambda v: v is False,
         "description":"No Intune compliance policy exists for iOS or Android devices. Mobile devices connecting to Microsoft 365 — including Exchange, Teams and SharePoint — are doing so with no compliance requirement. Compromised, jailbroken, or unmanaged personal devices can access the same data as fully managed corporate endpoints.",
         "recommendation":"Create Intune compliance policies for iOS and Android covering minimum OS version, screen lock, device encryption, and jailbreak/root detection. Pair with a Conditional Access policy requiring compliant devices for mobile access to M365.",
         "severity_reason":"High because mobile devices are the most common unmanaged endpoint accessing M365 — without a compliance policy, jailbroken or compromised phones access the same data as corporate laptops.",
         "effort":"Low","effort_hours":3,
         "secure_score_impact": 5},

        {"id":"MDM-006","title":"Defender for Endpoint Not Integrated with Intune","module":"intune","metric":"defender_mde_integration_enabled","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Microsoft Defender for Endpoint is not integrated with Intune via a Mobile Threat Defence connector. Without this integration, device risk signals from Defender — such as active malware, suspicious activity, or network attacks — are not available to Conditional Access. A compromised device can continue to access M365 resources even while Defender has flagged it.",
         "recommendation":"In Intune, go to Endpoint security > Microsoft Defender for Endpoint and enable the connector. Set up device risk score conditions in your compliance policies. This routes Defender's real-time risk signals into CA so compromised devices are automatically blocked.",
         "severity_reason":"Medium because without Defender risk signals in CA, a compromised device stays authorised to access M365 until manually blocked — removing a key automated response capability.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 4},

        # Entra ID Deep Findings
        {"id":"ENTRA-001","title":"High-Privilege App Registrations","module":"identity","metric":"high_priv_app_reg_count","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have been granted Critical or High risk Microsoft Graph application permissions. An attacker who compromises the application's credentials gains persistent, tenant-wide access that survives user password resets and MFA changes. These permissions are a common target for OAuth consent phishing and credential theft attacks.",
         "recommendation":"Review all app registrations under Entra ID > App registrations. Remove or reduce permissions that are broader than required. Rotate credentials on any high-privilege app immediately. Enable admin consent workflow to prevent future over-privileged consent grants.",
         "severity_reason":"Critical because app-level permissions are broader than user permissions and bypass all user-based controls — credential compromise grants silent, persistent tenant-wide access that survives MFA resets.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 5},

        {"id":"ENTRA-002","title":"Expired App Registration Credentials","module":"identity","metric":"expired_cred_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have credentials (client secrets or certificates) that have already expired. Expired credentials on high-privilege apps suggest the app may be unmanaged or abandoned — a common persistence mechanism left behind by former staff or attackers.",
         "recommendation":"Go to Entra ID > App registrations and review all apps with expired credentials. Remove expired credentials immediately. If the app is no longer needed, delete the registration entirely. If still in use, rotate credentials and implement a credential rotation process.",
         "severity_reason":"High because expired credentials on high-privilege apps indicate abandoned, unmanaged applications — prime targets for attackers using leaked historical secrets found in code repositories.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"ENTRA-003","title":"App Registration Credentials Expiring Within 30 Days","module":"identity","metric":"expiring_cred_30d_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have credentials expiring within 30 days. If not renewed, dependent services will fail to authenticate, potentially causing outages. Rushed credential rotation under time pressure increases the risk of errors.",
         "recommendation":"Review and rotate expiring credentials immediately in Entra ID > App registrations > Certificates & secrets. Implement automated credential rotation or calendar reminders to avoid last-minute renewals.",
         "severity_reason":"High because the 30-day window forces urgent action — rushed credential rotation under time pressure increases error risk and may cause service outages if not handled carefully.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"ENTRA-004","title":"App Registration Credentials Expiring Within 90 Days","module":"identity","metric":"expiring_cred_90d_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have credentials expiring within 31–90 days. Plan credential rotation now to avoid service disruption and rushed changes.",
         "recommendation":"Schedule credential rotation for affected app registrations within the next 30 days. Review Entra ID > App registrations > Certificates & secrets and create replacement credentials before the current ones expire.",
         "severity_reason":"Medium because 31–90 days provides adequate planning time for rotation — the risk is future disruption, not current exposure, if actioned promptly.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 2},

        {"id":"ENTRA-005","title":"App Registration Credentials Set to Never Expire","module":"identity","metric":"never_expire_cred_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have credentials with no expiry date configured. Non-expiring credentials remain valid indefinitely, meaning a leaked secret provides persistent access with no natural rotation forcing function.",
         "recommendation":"Replace never-expiring credentials with time-limited ones. Set expiry to 6–12 months and implement a rotation process. Go to Entra ID > App registrations > Certificates & secrets, add a new credential with an expiry, and remove the non-expiring one.",
         "severity_reason":"Medium because non-expiring credentials are a long-term governance risk — a leaked secret remains valid indefinitely, but this is a policy gap rather than a confirmed active exposure.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"ENTRA-006","title":"Unowned App Registrations","module":"identity","metric":"unowned_app_reg_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have no owner assigned. Without an owner, there is no accountable person to review permissions, rotate credentials, or respond if the app is compromised. Unowned apps are frequently abandoned and left with stale high-privilege permissions.",
         "recommendation":"Assign an owner to every app registration in Entra ID > App registrations > [App] > Owners. Where no owner can be identified, review whether the app is still in use and delete it if not.",
         "severity_reason":"Medium because unowned apps lack an accountable reviewer, causing credential and permission hygiene to decay over time — the direct risk depends on what permissions those apps hold.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 2},

        {"id":"ENTRA-007","title":"Multi-Tenant App Registrations","module":"identity","metric":"multitenant_app_reg_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations are configured as multi-tenant, meaning users from any external Entra ID tenant can sign in or consent to the app. If this is not intentional, it expands the attack surface beyond your organisation.",
         "recommendation":"Review multi-tenant app registrations in Entra ID > App registrations. If multi-tenant access is not required, change Supported account types to 'Accounts in this organizational directory only'. For legitimate multi-tenant apps, ensure publisher verification is complete.",
         "severity_reason":"Medium because multi-tenant configuration is frequently left in place unintentionally — opening consent to external tenants without vetting, but requiring an attacker from an external tenant to exploit.",
         "effort":"Low","effort_hours":1,
         "secure_score_impact": 2},

        {"id":"ENTRA-008","title":"Implicit Grant Flow Enabled on App Registrations","module":"identity","metric":"implicit_grant_app_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more app registrations have implicit grant flow enabled (ID token or access token issuance). Implicit flow returns tokens in browser redirect URLs, making them susceptible to leakage via browser history, referrer headers, and cross-site scripting attacks. Microsoft recommends disabling implicit flow for all applications.",
         "recommendation":"Go to Entra ID > App registrations > [App] > Authentication and uncheck both 'ID tokens' and 'Access tokens' under Implicit grant and hybrid flows. Migrate to the Authorization Code flow with PKCE for public clients.",
         "severity_reason":"Medium because implicit flow is a deprecated security pattern that exposes tokens via redirect URLs — the risk materialises primarily if an XSS vulnerability exists in the application itself.",
         "effort":"Low","effort_hours":2,
         "secure_score_impact": 3},

        {"id":"ENTRA-009","title":"Service Principals with High-Privilege Directory Roles","module":"identity","metric":"priv_service_principal_count","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more service principals (enterprise applications) have been assigned high-privilege Entra ID directory roles such as Global Administrator or Application Administrator. A service principal with admin roles is a non-interactive backdoor — an attacker who obtains its credentials gains admin-level access without triggering user sign-in alerts or MFA prompts.",
         "recommendation":"Go to Entra ID > Roles and administrators and review all high-privilege role assignments. Remove service principals from privileged roles unless there is a documented, audited business requirement. Use least-privilege roles (e.g., Application.ReadWrite.OwnedBy) where possible.",
         "severity_reason":"Critical because a service principal with Global Admin equivalent is a non-interactive admin backdoor — credential compromise grants full tenant control with no MFA, no CA policy, and no user-based detection.",
         "effort":"Medium","effort_hours":4,
         "secure_score_impact": 5},

        {"id":"ENTRA-010","title":"Managed Identities with High-Privilege Directory Roles","module":"identity","metric":"priv_managed_identity_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more managed identities have been assigned high-privilege Entra ID directory roles. Managed identities granted admin roles can be exploited by any workload running under that identity — a compromised Azure VM or Function App with a privileged managed identity can take administrative actions across the tenant.",
         "recommendation":"Go to Entra ID > Roles and administrators and review managed identity role assignments. Remove high-privilege roles from managed identities and assign only the minimum permissions required for each workload.",
         "severity_reason":"High because any compromised Azure workload running under a privileged managed identity inherits admin-level tenant access — the attack surface extends beyond M365 into Azure compute and services.",
         "effort":"Medium","effort_hours":3,
         "secure_score_impact": 3},
    ]
    # Apply framework mappings to all findings
    for f in findings:
        f["frameworks"] = _inject_fw_rem(FRAMEWORK_MAPPING.get(f["id"], {}))
    return findings

FINDINGS_LIBRARY = build_findings_library()

METRIC_DISPLAY = {
    "mfa_percentage":                  {"label":"MFA Coverage",                    "format":"{}%",   "desc":"Percentage of users with MFA registered"},
    "global_admin_count":              {"label":"Global Administrators",           "format":"{}",    "desc":"Number of users with Global Admin role"},
    "pim_enabled":                     {"label":"Just-in-Time Admin Access (PIM)", "format":"{}",    "desc":"Whether Privileged Identity Management is active"},
    "guest_user_count":                {"label":"Guest Accounts",                  "format":"{}",    "desc":"Number of external guest users in the tenant"},
    "unassigned_licence_percentage":   {"label":"Unused Licences",                 "format":"{}%",   "desc":"Percentage of purchased licences not assigned"},
    "secure_score_percentage":         {"label":"Microsoft Secure Score",          "format":"{}%",   "desc":"Microsofts own security configuration score"},
    "security_defaults_enabled":       {"label":"Security Defaults Enabled",       "format":"{}",    "desc":"Whether Microsoft baseline security defaults are on"},
    "ca_enabled_policy_count":         {"label":"Conditional Access Policies",     "format":"{}",    "desc":"Number of active Conditional Access policies"},
    "legacy_auth_blocked":             {"label":"Legacy Authentication Blocked",   "format":"{}",    "desc":"Whether old-style auth protocols are blocked"},
    "external_forwarding_blocked":     {"label":"External Email Forwarding Blocked","format":"{}",   "desc":"Whether auto-forwarding to external addresses is blocked"},
    "mailbox_audit_enabled_percentage":{"label":"Mailbox Audit Coverage",          "format":"{}%",   "desc":"Percentage of mailboxes with audit logging enabled"},
    "antiphish_intelligence_enabled":  {"label":"Anti-Phishing Intelligence",      "format":"{}",    "desc":"Whether mailbox intelligence protects against impersonation"},
    "teams_external_access_restricted":{"label":"Teams External Access Restricted","format":"{}",    "desc":"Whether Teams federation is restricted to approved domains"},
    "teams_consumer_access_blocked":   {"label":"Teams Consumer Access Blocked",   "format":"{}",    "desc":"Whether personal Teams accounts are blocked"},
    "teams_anon_meeting_join_enabled": {"label":"Anonymous Meeting Join",          "format":"{}",    "desc":"Whether unauthenticated users can join Teams meetings"},
    "teams_third_party_apps_allowed":  {"label":"Third-Party Apps Unrestricted",   "format":"{}",    "desc":"Whether all third-party Teams store apps are allowed"},
    "spo_sharing_level":               {"label":"SharePoint External Sharing",     "format":"{}",    "desc":"External sharing setting for SharePoint and OneDrive"},
    "spo_legacy_auth":                 {"label":"SharePoint Legacy Auth Enabled",  "format":"{}",    "desc":"Whether old authentication is enabled in SharePoint"},
    "onedrive_sharing_level":          {"label":"OneDrive External Sharing",       "format":"{}",    "desc":"External sharing setting for OneDrive for Business"},
    "guest_access_expiry_configured":  {"label":"Guest Access Expiry",             "format":"{}",    "desc":"Whether external user access expires automatically"},
    "intune_compliance_percentage":    {"label":"Device Compliance Rate",          "format":"{}%",   "desc":"Percentage of managed devices meeting compliance policy"},
    "intune_compliance_policy_count":  {"label":"Device Compliance Policies",      "format":"{}",    "desc":"Number of Intune compliance policies configured"},
    "intune_config_policy_count":      {"label":"Device Config Policies",          "format":"{}",    "desc":"Number of Intune device configuration profiles"},
    "high_privilege_app_count":        {"label":"High-Privilege OAuth Apps",       "format":"{}",    "desc":"Apps with dangerous tenant-wide permissions"},
    "defender_alert_policy_count":     {"label":"Defender Alert Policies",         "format":"{}",    "desc":"Number of active Microsoft Defender alert policies"},
    "mfa_number_matching_enabled":     {"label":"MFA Fatigue Protection",          "format":"{}",    "desc":"Whether Authenticator number matching is enabled"},
    "weak_auth_methods_enabled":       {"label":"Weak MFA Methods Active",         "format":"{}",    "desc":"Whether SMS, voice, or email OTP auth is enabled"},
    "user_consent_unrestricted":       {"label":"Users Can Consent to Apps",       "format":"{}",    "desc":"Whether users can grant app permissions without admin approval"},
    "teams_email_into_channel":        {"label":"Teams Email-to-Channel",          "format":"{}",    "desc":"Whether external emails can be sent into Teams channels"},
    "risky_users_count":               {"label":"Risky Users (High/Medium)",       "format":"{}",    "desc":"Users flagged as high or medium risk by Identity Protection"},
    "emergency_access_exists":         {"label":"Emergency Access Account",        "format":"{}",    "desc":"Whether a break-glass account is detectable in the tenant"},
    "sentinel_connected":              {"label":"Microsoft Sentinel Connected",    "format":"{}",    "desc":"Whether Sentinel appears to be active and generating alerts"},
    "dmarc_configured":                {"label":"DMARC Configured",               "format":"{}",    "desc":"Whether a DMARC record exists for the primary domain"},
    "spf_dkim_configured":             {"label":"SPF and DKIM Configured",        "format":"{}",    "desc":"Whether SPF and DKIM are both set up for the primary domain"},
    "zap_fully_enabled":               {"label":"Zero-Hour Auto Purge (ZAP)",     "format":"{}",    "desc":"Whether ZAP is enabled for malware, phishing and spam"},
    "zap_malware_enabled":             {"label":"ZAP — Malware",                  "format":"{}",    "desc":"Whether ZAP is enabled in the malware filter policy"},
    "zap_phish_enabled":               {"label":"ZAP — Phishing",                 "format":"{}",    "desc":"Whether ZAP is enabled for phishing in the content filter"},
    "zap_spam_enabled":                {"label":"ZAP — Spam",                     "format":"{}",    "desc":"Whether ZAP is enabled for spam in the content filter"},
    "update_ring_count":               {"label":"Windows Update Rings",            "format":"{}",    "desc":"Number of Windows Update for Business rings in Intune"},
    "bitlocker_enforced":              {"label":"BitLocker Enforced",              "format":"{}",    "desc":"Whether BitLocker is required by Intune policies"},
    "mobile_compliance_policy_exists": {"label":"Mobile Compliance Policy",        "format":"{}",    "desc":"Whether an iOS or Android compliance policy exists in Intune"},
    "defender_mde_integration_enabled":{"label":"Defender MDE Integration",        "format":"{}",    "desc":"Whether Defender for Endpoint is connected to Intune"},
    "mfa_all_users_ca_policy":         {"label":"MFA for All Users (CA)",          "format":"{}",    "desc":"Whether a CA policy enforces MFA broadly for all users"},
    "high_priv_app_reg_count":         {"label":"High-Privilege App Registrations", "format":"{}",   "desc":"Apps with Critical or High risk Graph permissions"},
    "expired_cred_count":              {"label":"Expired App Credentials",          "format":"{}",   "desc":"App registrations with expired credentials"},
    "expiring_cred_30d_count":         {"label":"Credentials Expiring (≤30 days)",  "format":"{}",   "desc":"App registrations with credentials expiring within 30 days"},
    "expiring_cred_90d_count":         {"label":"Credentials Expiring (31–90 days)","format":"{}",   "desc":"App registrations with credentials expiring within 31–90 days"},
    "never_expire_cred_count":         {"label":"Never-Expiring Credentials",       "format":"{}",   "desc":"App registrations with credentials set to never expire"},
    "unowned_app_reg_count":           {"label":"Unowned App Registrations",        "format":"{}",   "desc":"App registrations with no owner assigned"},
    "multitenant_app_reg_count":       {"label":"Multi-Tenant App Registrations",   "format":"{}",   "desc":"App registrations accessible from any Entra tenant"},
    "implicit_grant_app_count":        {"label":"Implicit Grant Apps",              "format":"{}",   "desc":"Apps with implicit ID/access token issuance enabled"},
    "priv_service_principal_count":    {"label":"Privileged Service Principals",    "format":"{}",   "desc":"Service principals with high-privilege directory roles"},
    "priv_managed_identity_count":     {"label":"Privileged Managed Identities",    "format":"{}",   "desc":"Managed identities with high-privilege directory roles"},
}


# ─────────────────────────────────────────────────────────────
#  SCRIPT RUNNER
# ─────────────────────────────────────────────────────────────

# Map module names → script filenames
MODULE_SCRIPTS = {
    "identity":   "Get-IdentityMetrics.ps1",
    "security":   "Get-SecurityMetrics.ps1",
    "exchange":   "Get-ExchangeMetrics.ps1",
    "teams":      "Get-TeamsMetrics.ps1",
    "sharepoint": "Get-SharePointMetrics.ps1",
    "intune":     "Get-IntuneMetrics.ps1",
}

# Modules that ALWAYS use interactive login (no app-only support)
INTERACTIVE_ONLY_MODULES = {"exchange", "teams", "sharepoint"}


def build_ps_args(module, auth):
    """Build the PowerShell parameter list for a given module and auth config."""
    auth_method = auth.get("authMethod", "interactive")
    environment = auth.get("environment", "commercial").lower()
    args = []

    # Government cloud endpoint overrides
    # GCC uses the same endpoints as Commercial — no change needed
    # GCCH uses graph.microsoft.us / login.microsoftonline.us
    # DoD uses dod-graph.microsoft.us / login.microsoftonline.us
    if environment == "gcch":
        graph_endpoint = "https://graph.microsoft.us"
        login_endpoint = "https://login.microsoftonline.us"
    elif environment == "dod":
        graph_endpoint = "https://dod-graph.microsoft.us"
        login_endpoint = "https://login.microsoftonline.us"
    else:
        # Commercial and GCC both use standard endpoints
        graph_endpoint = "https://graph.microsoft.com"
        login_endpoint = "https://login.microsoftonline.com"

    if auth_method == "appreg" and module not in INTERACTIVE_ONLY_MODULES:
        args += ["-AuthMethod", "AppReg"]
        args += ["-TenantId", auth.get("tenantId", "")]
        args += ["-ClientId", auth.get("clientId", "")]
        args += ["-ClientSecret", auth.get("clientSecret", "")]
        args += ["-GraphEndpoint", graph_endpoint]
        args += ["-LoginEndpoint", login_endpoint]
    elif auth_method == "certificate" and module not in INTERACTIVE_ONLY_MODULES:
        args += ["-AuthMethod", "Certificate"]
        args += ["-TenantId", auth.get("tenantId", "")]
        args += ["-ClientId", auth.get("clientId", "")]
        args += ["-CertThumbprint", auth.get("certThumbprint", "")]
        args += ["-GraphEndpoint", graph_endpoint]
        args += ["-LoginEndpoint", login_endpoint]
    else:
        # Interactive auth (also fallback for cert/appreg on interactive-only modules)
        args += ["-AuthMethod", "Interactive"]
        tenant_id = auth.get("tenantId", "")
        if tenant_id:
            args += ["-TenantId", tenant_id]

    # Pass environment to all modules so Exchange/Teams/SPO can switch endpoints
    args += ["-Environment", environment]

    # SharePoint admin URL for SPO module
    if module == "sharepoint":
        args += ["-SpAdminUrl", auth.get("spAdminUrl", "")]

    return args


# Per-module timeouts (seconds) — Security and Identity need more time for CA/Graph enumeration
MODULE_TIMEOUTS = {
    "security":   600,   # CA policy enumeration + Defender checks can be slow
    "identity":   600,   # Entra ID deep checks — large tenants need extra time
    "exchange":   300,
    "teams":      300,
    "sharepoint": 300,
    "intune":     300,
}
DEFAULT_TIMEOUT = 300

def run_script(script_name, ps_args, module=None):
    """
    Execute a PowerShell script and return parsed JSON output.
    App Registration: runs silently, captures stdout directly.
    Interactive: runs allowing popup windows, filters WARNING lines before JSON parsing.
    """
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        return None, f"Script not found: {script_name}"

    timeout = MODULE_TIMEOUTS.get(module, DEFAULT_TIMEOUT) if module else DEFAULT_TIMEOUT

    # Do NOT use -NonInteractive - it blocks login popups for interactive auth
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", script_path
    ] + ps_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        stdout = result.stdout.strip()

        # Filter WARNING and INFO lines - find the JSON output line
        json_line = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break

        # If script failed and no JSON found, return error
        if result.returncode != 0 and not json_line:
            err = result.stderr.strip() or stdout[:300] or f"Script exited with code {result.returncode}"
            return None, err

        if not json_line:
            err = result.stderr.strip() or "Script produced no JSON output"
            return None, err

        data = json.loads(json_line)
        return data, None

    except subprocess.TimeoutExpired:
        return None, f"Script timed out after {timeout} seconds"
    except json.JSONDecodeError as e:
        stderr = result.stderr.strip() if result else ""
        return None, f"Invalid JSON from script: {e}. stderr: {stderr[:300]}"
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────
#  EVALUATION & SCORING
# ─────────────────────────────────────────────────────────────

def evaluate_findings(all_metrics):
    triggered = []
    for f in FINDINGS_LIBRARY:
        metric = f["metric"]
        if metric not in all_metrics:
            continue
        value = all_metrics[metric]
        try:
            try:
                triggered_flag = f["threshold"](value, all_metrics)
            except TypeError:
                triggered_flag = f["threshold"](value)
            if triggered_flag:
                triggered.append({
                    "id": f["id"], "title": f["title"], "module": f["module"],
                    "metric": metric, "severity": f["severity"],
                    "description": f["description"], "recommendation": f["recommendation"],
                    "observed_value": value,
                    "secure_score_impact": f.get("secure_score_impact", 0),
                    "frameworks": f.get("frameworks", {})
                })
        except Exception:
            pass
    return triggered


def calculate_score(findings):
    """
    Score out of 100. Deductions per finding with caps per severity band
    so a tenant with many findings still gets a meaningful score.
      Critical: -8 each, max -32  (4+ critical = worst band)
      High:     -5 each, max -20
      Medium:   -3 each, max -12
      Low:      -1 each, max -4
    Floor: 10 (even the worst tenant shows a number)
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    penalty = (
        min(counts["critical"] * 8, 32) +
        min(counts["high"]     * 5, 20) +
        min(counts["medium"]   * 3, 12) +
        min(counts["low"]      * 1,  4)
    )
    return max(10, 100 - penalty)


def format_metric(key, value):
    config = METRIC_DISPLAY.get(key, {"label": key, "format": "{}"})
    try:
        display = config["format"].format(value)
    except Exception:
        display = str(value)

    status = "good"
    if isinstance(value, bool):
        # For flags where True = good
        good_when_true = {"pim_enabled", "security_defaults_enabled", "legacy_auth_blocked",
                          "external_forwarding_blocked", "antiphish_intelligence_enabled",
                          "teams_external_access_restricted", "teams_consumer_access_blocked",
                          "mfa_number_matching_enabled",
                          "zap_fully_enabled", "zap_malware_enabled", "zap_phish_enabled", "zap_spam_enabled",
                          "guest_access_expiry_configured", "mobile_compliance_policy_exists",
                          "defender_mde_integration_enabled", "mfa_all_users_ca_policy"}
        # Flags where True = bad
        bad_when_true_extra = {"weak_auth_methods_enabled", "user_consent_unrestricted", "teams_email_into_channel",
                               "teams_anon_meeting_join_enabled", "teams_third_party_apps_allowed"}
        # For flags where False = good
        bad_when_true = {"spo_legacy_auth"}
        if key in bad_when_true or key in bad_when_true_extra:
            status = "bad" if value else "good"
        else:
            status = "good" if value else "bad"
    elif isinstance(value, (int, float)):
        percentage_good_high = {"mfa_percentage", "secure_score_percentage",
                                 "mailbox_audit_enabled_percentage", "intune_compliance_percentage"}
        percentage_good_low  = {"unassigned_licence_percentage"}
        count_good_low       = {"global_admin_count", "guest_user_count"}
        count_good_high      = {"ca_enabled_policy_count", "intune_compliance_policy_count", "defender_alert_policy_count", "intune_config_policy_count"}
        count_good_zero      = {"high_privilege_app_count", "risky_users_count",
                               "high_priv_app_reg_count", "expired_cred_count",
                               "expiring_cred_30d_count", "expiring_cred_90d_count",
                               "never_expire_cred_count", "unowned_app_reg_count",
                               "multitenant_app_reg_count", "implicit_grant_app_count",
                               "priv_service_principal_count", "priv_managed_identity_count"}
        count_good_nonzero   = {"update_ring_count"}

        if key in percentage_good_high:
            status = "good" if value >= 90 else ("warn" if value >= 70 else "bad")
        elif key in percentage_good_low:
            status = "good" if value <= 10 else ("warn" if value <= 20 else "bad")
        elif key in count_good_low:
            status = "good" if value <= 2 else ("warn" if value <= 4 else "bad")
        elif key in count_good_high:
            status = "good" if value >= 3 else ("warn" if value >= 1 else "bad")
        elif key in count_good_zero:
            status = "good" if value == 0 else ("warn" if value <= 2 else "bad")
        elif key in count_good_nonzero:
            status = "good" if value >= 1 else "bad"
    elif isinstance(value, str):
        bad_values = {"ExternalUserAndGuestSharing", "anyone"}
        warn_values = {"ExternalUserSharingOnly", "new_and_existing"}
        if value in bad_values: status = "bad"
        elif value in warn_values: status = "warn"

    # Convert True/False to friendly labels
    if isinstance(value, bool):
        friendly_map = {
            "pim_enabled": ("Active", "Not Active"),
            "security_defaults_enabled": ("Enabled", "Disabled"),
            "legacy_auth_blocked": ("Blocked", "Not Blocked"),
            "external_forwarding_blocked": ("Blocked", "Not Blocked"),
            "antiphish_intelligence_enabled": ("Enabled", "Disabled"),
            "teams_external_access_restricted": ("Restricted", "Open"),
            "teams_consumer_access_blocked": ("Blocked", "Allowed"),
            "spo_legacy_auth": ("Enabled", "Disabled"),
            "mfa_number_matching_enabled": ("Enabled", "Disabled"),
            "weak_auth_methods_enabled": ("Yes - Review", "No"),
            "user_consent_unrestricted": ("Yes - Review", "Restricted"),
            "teams_email_into_channel": ("Allowed", "Blocked"),
            "emergency_access_exists": ("Detected", "Not Detected"),
            "sentinel_connected": ("Connected", "Not Connected"),
            "dmarc_configured": ("Configured", "Not Configured"),
            "spf_dkim_configured": ("Configured", "Not Configured"),
            "bitlocker_enforced": ("Enforced", "Not Enforced"),
            "zap_fully_enabled": ("Enabled", "Not Fully Enabled"),
            "zap_malware_enabled": ("Enabled", "Disabled"),
            "zap_phish_enabled": ("Enabled", "Disabled"),
            "zap_spam_enabled": ("Enabled", "Disabled"),
            "teams_anon_meeting_join_enabled": ("Allowed", "Blocked"),
            "teams_third_party_apps_allowed": ("Allowed", "Restricted"),
            "guest_access_expiry_configured": ("Configured", "Not Configured"),
            "mobile_compliance_policy_exists": ("Exists", "Not Found"),
            "defender_mde_integration_enabled": ("Connected", "Not Connected"),
            "mfa_all_users_ca_policy": ("Policy Exists", "No Policy Found"),
        }
        if key in friendly_map:
            display = friendly_map[key][0] if value else friendly_map[key][1]

    # SharePoint sharing level friendly labels
    spo_labels = {
        "ExternalUserAndGuestSharing": "Anyone (Unrestricted)",
        "ExternalUserSharingOnly": "New and Existing Guests",
        "ExistingExternalUserSharingOnly": "Existing Guests Only",
        "Disabled": "No External Sharing",
        "Unknown": "Could not retrieve",
    }
    if key == "spo_sharing_level":
        display = spo_labels.get(str(value), str(value))

    desc = config.get("desc", "")
    return {"label": config["label"], "value": display, "status": status, "sub": desc}


def save_csvs(client_name, all_metrics, findings):
    date_str = datetime.date.today().strftime("%Y%m%d")
    safe = client_name.replace(" ", "_")
    with open(os.path.join(OUTPUT_DIR, f"TenantMetrics_{safe}_{date_str}.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["Metric","Value"])
        for k, v in all_metrics.items(): w.writerow([k, v])
    fields = ["id","title","module","metric","severity","observed_value","recommendation"]
    with open(os.path.join(OUTPUT_DIR, f"TriggeredFindings_{safe}_{date_str}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for fi in findings: w.writerow({k: fi.get(k,"") for k in fields})


def save_session(session_data):
    """Save full assessment session as JSON for later reload."""
    client_name = session_data.get("orgName", session_data.get("clientName", "Unknown"))
    assess_date = session_data.get("assessDate", datetime.date.today().isoformat())
    safe = client_name.replace(" ", "_").replace("/", "-")
    date_str = assess_date.replace("-", "")
    # Add timestamp to avoid overwriting same-day runs
    timestamp = datetime.datetime.now().strftime("%H%M%S")
    filename = f"Session_{safe}_{date_str}_{timestamp}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(session_data, f, ensure_ascii=False, indent=2)
    return filename


# ─────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────

# Read version from VERSION file — never hardcode so updates always reflect correctly
_ver_file = os.path.join(BASE_DIR, "VERSION")
CURRENT_VERSION       = open(_ver_file).read().strip() if os.path.exists(_ver_file) else "1.4.0"
FINDINGS_LAST_UPDATED = "2026-06-07"   # Update whenever FINDINGS list is modified
VERSION_URL     = "https://raw.githubusercontent.com/malcolmmcdonald1982/M365-Assessment-Toolkit/main/VERSION"
RELEASES_URL    = "https://github.com/malcolmmcdonald1982/M365-Assessment-Toolkit/releases"


@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "online", "version": CURRENT_VERSION,
                    "findings_loaded": len(FINDINGS_LIBRARY), "scripts_dir": SCRIPTS_DIR})


@app.route("/check-update", methods=["GET"])
def check_update():
    """Check GitHub for a newer version."""
    try:
        req = urllib.request.Request(VERSION_URL,
              headers={"User-Agent": "M365-Assessment-Toolkit"})
        with urllib.request.urlopen(req, timeout=5) as r:
            latest = r.read().decode().strip()
        def _ver(v):
            try: return tuple(int(x) for x in v.strip().split("."))
            except: return (0,)
        update_available = _ver(latest) > _ver(CURRENT_VERSION)
        return jsonify({
            "current":          CURRENT_VERSION,
            "latest":           latest,
            "update_available": update_available,
            "releases_url":     RELEASES_URL
        })
    except Exception as e:
        return jsonify({
            "current":          CURRENT_VERSION,
            "latest":           CURRENT_VERSION,
            "update_available": False,
            "error":            str(e)
        })


@app.route("/apply-update", methods=["POST"])
def apply_update():
    """Run the local update.ps1 script to pull latest files from GitHub."""
    update_script = os.path.join(BASE_DIR, "update.ps1")
    if not os.path.exists(update_script):
        return jsonify({"success": False, "error": "update.ps1 not found"}), 500
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", update_script, "-Force"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return jsonify({"success": False, "error": result.stderr.strip() or result.stdout.strip()})
        return jsonify({"success": True, "output": result.stdout.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Update timed out after 120 seconds"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


ALL_FRAMEWORKS = ["cis", "nist", "iso", "caf"]  # CE, SOC2, E8, NIS2 removed — no stable reference links

# ── Scan progress tracker ────────────────────────────────────
import threading
_scan_progress = {"status": "idle", "module": "", "step": 0, "total": 0, "label": ""}
_scan_lock     = threading.Lock()

def _set_progress(status, module="", step=0, total=0, label=""):
    with _scan_lock:
        _scan_progress.update({"status": status, "module": module,
                                "step": step, "total": total, "label": label})

@app.route("/progress", methods=["GET"])
def get_progress():
    with _scan_lock:
        return jsonify(dict(_scan_progress))

# ── Heartbeat / shutdown ─────────────────────────────────────
import time as _time
_last_heartbeat = _time.time()
_shutdown_enabled = False

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    global _last_heartbeat
    _last_heartbeat = _time.time()
    return jsonify({"ok": True})

@app.route("/shutdown", methods=["POST"])
def shutdown():
    """Clean shutdown triggered by Stop button or heartbeat timeout."""
    func = request.environ.get("werkzeug.server.shutdown")
    if func:
        func()
    else:
        import os, signal
        os.kill(os.getpid(), signal.SIGTERM)
    return jsonify({"ok": True})

def _heartbeat_watchdog():
    """Auto-shutdown if no heartbeat received for 90 seconds."""
    import time
    time.sleep(30)  # grace period on startup
    while True:
        time.sleep(15)
        if _shutdown_enabled and (_time.time() - _last_heartbeat) > 90:
            print("[INFO] No heartbeat for 90s — shutting down.", flush=True)
            import os, signal
            os.kill(os.getpid(), signal.SIGTERM)

_wd = threading.Thread(target=_heartbeat_watchdog, daemon=True)
_wd.start()

@app.route("/run", methods=["POST"])
def run_assessment():
    global _shutdown_enabled
    _shutdown_enabled = True          # enable watchdog once a real session starts
    body          = request.get_json()
    client_name   = body.get("orgName", body.get("clientName", "Unknown"))
    modules       = body.get("modules", [])
    active_frameworks = body.get("activeFrameworks", ALL_FRAMEWORKS)
    auth          = {k: body.get(k,"") for k in
                     ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment"]}

    log = []
    all_metrics = {}

    def L(msg, t="info"):
        log.append({"message": msg, "type": t})
        print(f"[{t.upper()}] {msg}", flush=True)

    L(f"Assessment started — {client_name}")
    L(f"Auth method: {auth['authMethod']}")

    total_modules = len(modules)
    _set_progress("running", step=0, total=total_modules, label="Starting...")

    for idx, module in enumerate(modules, 1):
        script = MODULE_SCRIPTS.get(module)
        if not script:
            L(f"Unknown module: {module}", "warn"); continue

        is_interactive_only = module in INTERACTIVE_ONLY_MODULES
        if auth["authMethod"] == "interactive" or is_interactive_only:
            effective_auth = "interactive"
        elif auth["authMethod"] == "certificate":
            effective_auth = "certificate"
        else:
            effective_auth = "appreg"

        if is_interactive_only and auth["authMethod"] == "appreg":
            L(f"{module}: App Reg not supported for this workload — using interactive login", "warn")

        module_label = module.replace("sharepoint","SharePoint").replace("exchange","Exchange").replace("identity","Identity").replace("security","Security").replace("teams","Teams").replace("intune","Intune")
        _set_progress("running", module=module, step=idx, total=total_modules,
                      label=f"Running {module_label}... ({idx} of {total_modules})")
        L(f"Running: {script} [{effective_auth}]")
        ps_args = build_ps_args(module, auth)
        metrics, error = run_script(script, ps_args, module=module)

        if error:
            L(f"{module} failed: {error}", "error")
        elif metrics:
            all_metrics.update(metrics)
            L(f"{module} complete — {len(metrics)} metrics collected", "success")
        else:
            L(f"{module} returned no data", "warn")

    _set_progress("complete", step=total_modules, total=total_modules, label="Complete")

    # Derive composite metrics from raw values
    if any(k in all_metrics for k in ("zap_malware_enabled", "zap_phish_enabled", "zap_spam_enabled")):
        all_metrics["zap_fully_enabled"] = bool(
            all_metrics.get("zap_malware_enabled", False) and
            all_metrics.get("zap_phish_enabled", False) and
            all_metrics.get("zap_spam_enabled", False)
        )

    findings = evaluate_findings(all_metrics)
    score    = calculate_score(findings)
    display_metrics = [format_metric(k, v) for k, v in all_metrics.items()]

    L(f"Findings: {len(findings)} triggered")
    L(f"Score: {score}/100")

    try:
        save_csvs(client_name, all_metrics, findings)
        L("CSVs saved to /output", "success")
    except Exception as e:
        L(f"CSV save failed: {e}", "warn")

    assess_date = datetime.date.today().isoformat()
    # Check if a remediation log exists for this client
    safe_client = client_name.replace(" ", "_").replace("/", "-")
    rem_log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe_client}.json")
    rem_log = []
    if os.path.exists(rem_log_path):
        try:
            with open(rem_log_path, "r", encoding="utf-8") as f:
                rem_log = json.load(f)
        except Exception:
            pass

    session = {
        "orgName": client_name, "clientName": client_name,
        "authMethod": auth["authMethod"],
        "assessDate": assess_date,
        "score": score,
        "metrics": display_metrics,
        "findings": findings,
        "rawMetrics": all_metrics,
        "modulesRun": len(modules),
        "log": log,
        "savedAt": datetime.datetime.now().isoformat(),
        "toolVersion": CURRENT_VERSION,
        "findingsLastUpdated": FINDINGS_LAST_UPDATED,
        "activeFrameworks": active_frameworks,
        "remediationLog": rem_log,
    }

    try:
        saved_file = save_session(session)
        L(f"Session saved: {saved_file}", "success")
        session["savedFile"] = saved_file
    except Exception as e:
        L(f"Session save failed: {e}", "warn")

    return jsonify(session)


@app.route("/report", methods=["POST"])
def report_meta():
    body = request.get_json()
    return jsonify({"status":"ready","modulesRun": body.get("modulesRun",0),
                    "findingsCount": len(body.get("findings",[]))})


@app.route("/download", methods=["POST"])
def download_report():
    """
    Generate a professional colour-coded .docx report using the Node.js generator.
    Requires Node.js and: npm install docx  (run once in the tool folder)
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    filename    = f"M365_Assessment_{safe_name}_{assess_date.replace('-', '')}.docx"
    report_path = os.path.join(REPORTS_DIR, filename)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found. Place it in the same folder as backend.py."}), 500

    # Compute framework totals dynamically from FRAMEWORK_MAPPING so
    # generate-report.js never uses stale hardcoded numbers.
    fw_totals = {}
    for fw_id in body.get("activeFrameworks", ALL_FRAMEWORKS):
        fw_totals[fw_id] = sum(
            1 for mapping in FRAMEWORK_MAPPING.values()
            if mapping.get(fw_id)
        )
    body["fwTotals"] = fw_totals

    # Write assessment data to a temp JSON file for the Node script
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, report_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            error_detail = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": f"Report generator failed: {error_detail}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found. Install from https://nodejs.org"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(report_path):
        return jsonify({"error": "Report file was not created — check Node.js and docx module are installed."}), 500

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )






@app.route("/generate-exec-report", methods=["POST"])
def generate_exec_report():
    """
    Generate a board-ready Executive Summary .docx report.
    Calls generate-report.js with reportType='executive'.
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    filename    = f"M365_ExecSummary_{safe_name}_{assess_date.replace('-', '')}.docx"
    report_path = os.path.join(REPORTS_DIR, filename)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_exec_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found. Place it in the same folder as backend.py."}), 500

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, report_path, "executive"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            error_detail = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": f"Exec report generator failed: {error_detail}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found. Install from https://nodejs.org"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(report_path):
        return jsonify({"error": "Exec report file was not created."}), 500

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )


@app.route("/download-remediation", methods=["POST"])
def download_remediation_report():
    """
    Generate a separate Remediation Report document.
    Only available when a remediation log exists for the client.
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))
    rem_date    = datetime.date.today().isoformat()

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    filename    = f"M365_RemediationReport_{safe_name}_{rem_date.replace('-','')}.docx"
    report_path = os.path.join(REPORTS_DIR, filename)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_rem_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    print(f"[REMEDIATION REPORT] Organisation: {client_name}, Safe: {safe_name}", flush=True)
    print(f"[REMEDIATION REPORT] Generator: {generator} exists={os.path.exists(generator)}", flush=True)

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    # Always load from file — file is source of truth and includes rollbacks
    # that may have happened after the frontend cached the session data
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe_name}.json")
    print(f"[REMEDIATION REPORT] Log path: {log_path} exists={os.path.exists(log_path)}", flush=True)
    rem_log = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                rem_log = json.load(f)
        except Exception as e:
            print(f"[REMEDIATION REPORT] Log read error: {e}", flush=True)
    # Fall back to body if file missing
    if not rem_log:
        rem_log = body.get("remediationLog", [])

    print(f"[REMEDIATION REPORT] Log entries: {len(rem_log)}", flush=True)

    if not rem_log:
        return jsonify({"error": "No remediation log found for this client. Complete at least one remediation before generating this report."}), 400

    # Calculate after-remediation score
    remediatedIds = {e["findingId"] for e in rem_log if e.get("action") == "remediate" and e.get("success")}
    rolledBackIds = {e["findingId"] for e in rem_log if e.get("action") == "rollback" and e.get("success")}
    netFixed      = remediatedIds - rolledBackIds
    openFindings  = [f for f in body.get("findings", []) if f["id"] not in netFixed]
    score_after   = calculate_score(openFindings)

    # Build data payload for remediation report
    report_data = {
        **body,
        "remediationLog": rem_log,
        "remediationDate": rem_date,
        "scoreAfter": score_after,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, report_path, "remediation"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report generator failed: {result.stderr.strip()}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(report_path):
        return jsonify({"error": "Report file was not created"}), 500

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )

@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    """
    Generate a PDF report by first creating the .docx then converting via LibreOffice.
    Falls back to generating a clean HTML-based PDF using weasyprint if available.
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    docx_name   = f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.docx"
    pdf_name    = f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.pdf"
    docx_path   = os.path.join(REPORTS_DIR, docx_name)
    pdf_path    = os.path.join(REPORTS_DIR, pdf_name)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False)

    try:
        # Step 1: Generate the docx
        result = subprocess.run(
            ["node", generator, json_path, docx_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report generator failed: {result.stderr.strip()}"}), 500

        # Step 2: Try LibreOffice conversion
        lo_paths = [
            r"C:\Program Files\LibreOffice\program\soffice.exe",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
            "soffice",
        ]
        lo_exe = None
        for p in lo_paths:
            if os.path.exists(p) or p == "soffice":
                try:
                    subprocess.run([p, "--version"], capture_output=True, timeout=5)
                    lo_exe = p
                    break
                except Exception:
                    continue

        if lo_exe:
            conv = subprocess.run(
                [lo_exe, "--headless", "--convert-to", "pdf", "--outdir", REPORTS_DIR, docx_path],
                capture_output=True, text=True, timeout=120
            )
            if conv.returncode == 0 and os.path.exists(pdf_path):
                return send_file(pdf_path, mimetype="application/pdf",
                                 as_attachment=True, download_name=pdf_name)

        # Step 3: Fallback - generate HTML-based PDF report
        html_pdf = generate_html_pdf(body, assess_date)
        return send_file(
            io.BytesIO(html_pdf.encode("utf-8")),
            mimetype="text/html",
            as_attachment=True,
            download_name=f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.html"
        )

    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)


def generate_html_pdf(data, assess_date):
    """Generate a clean, print-ready HTML report as PDF fallback."""
    findings  = data.get("findings", [])
    score     = data.get("score", 0)
    client          = data.get("orgName", data.get("clientName", "Organisation"))
    consultant_name  = data.get("consultantName", "[Consultant Name]")
    consultant_role  = data.get("consultantRole",  "[Role]")
    consultant_email = data.get("consultantEmail", "[Email]")
    metrics   = data.get("metrics", [])

    sev_colours = {"critical":"#C0392B","high":"#D35400","medium":"#D4AC0D","low":"#27AE60"}
    score_colour = "#27AE60" if score >= 70 else "#D4AC0D" if score >= 50 else "#C0392B"

    counts = {s: len([f for f in findings if f["severity"]==s]) for s in ["critical","high","medium","low"]}

    order = {"critical":0,"high":1,"medium":2,"low":3}
    sorted_findings = sorted(findings, key=lambda x: order.get(x["severity"],9))

    findings_html = ""
    for f in sorted_findings:
        col = sev_colours.get(f["severity"], "#666")
        findings_html += f"""
        <div class="finding">
          <div class="finding-header" style="border-left: 6px solid {col}; padding-left: 12px;">
            <span class="badge" style="background:{col}">{f["severity"].upper()}</span>
            <span class="finding-id">{f["id"]}</span>
            <strong>{f["title"]}</strong>
          </div>
          <table class="finding-table">
            <tr><td class="ft-label">What this means</td><td>{f["description"]}</td></tr>
            <tr><td class="ft-label">Recommendation</td><td>{f["recommendation"]}</td></tr>
            <tr><td class="ft-label">Observed value</td><td>{f.get("observed_value","")}</td></tr>
          </table>
        </div>"""

    metrics_html = ""
    for m in metrics:
        col = "#27AE60" if m["status"]=="good" else "#D4AC0D" if m["status"]=="warn" else "#C0392B"
        metrics_html += f'<tr><td>{m["label"]}</td><td style="font-weight:bold;color:{col}">{m["value"]}</td></tr>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>M365 Assessment - {client}</title>
<style>
  @media print {{ @page {{ margin: 2cm; }} .no-print {{ display:none; }} }}
  body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #212529; margin: 0; padding: 20px; }}
  h1 {{ color: #1B2A4A; font-size: 22pt; border-bottom: 3px solid #1B2A4A; padding-bottom: 8px; }}
  h2 {{ color: #2E4A7A; font-size: 15pt; border-bottom: 1px solid #DEE2E6; padding-bottom: 4px; margin-top: 30px; }}
  .cover {{ text-align:center; padding: 60px 0; border-bottom: 2px solid #1B2A4A; margin-bottom: 30px; }}
  .cover h1 {{ font-size: 28pt; border: none; }}
  .cover p {{ color: #6c757d; font-size: 12pt; }}
  .score-box {{ background: {score_colour}22; border: 3px solid {score_colour}; border-radius: 10px;
                text-align: center; padding: 20px; margin: 20px 0; }}
  .score-num {{ font-size: 48pt; font-weight: bold; color: {score_colour}; }}
  .counts {{ display: flex; gap: 10px; margin: 20px 0; }}
  .count-box {{ flex: 1; text-align: center; padding: 15px; border-radius: 6px; }}
  .count-num {{ font-size: 28pt; font-weight: bold; }}
  .finding {{ margin-bottom: 20px; border: 1px solid #DEE2E6; border-radius: 6px; overflow: hidden; }}
  .finding-header {{ padding: 10px 12px; background: #f8f9fa; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 3px; font-size: 9pt; font-weight: bold; }}
  .finding-id {{ font-size: 9pt; color: #6c757d; font-family: monospace; }}
  .finding-table {{ width: 100%; border-collapse: collapse; }}
  .finding-table td {{ padding: 8px 12px; border-top: 1px solid #DEE2E6; vertical-align: top; font-size: 10pt; }}
  .ft-label {{ width: 140px; color: #495057; font-weight: bold; background: #f8f9fa; }}
  .metrics-table {{ width: 100%; border-collapse: collapse; }}
  .metrics-table th {{ background: #1B2A4A; color: white; padding: 8px 12px; text-align: left; }}
  .metrics-table td {{ padding: 7px 12px; border-bottom: 1px solid #DEE2E6; font-size: 10pt; }}
  .metrics-table tr:nth-child(even) td {{ background: #f8f9fa; }}
  .notice {{ background: #EBF5FB; border-left: 5px solid #2E4A7A; padding: 12px 16px; margin: 20px 0; font-size: 10pt; line-height: 1.6; }}
  footer {{ margin-top: 40px; padding-top: 10px; border-top: 1px solid #DEE2E6; color: #6c757d; font-size: 9pt; text-align: center; }}
  .no-print {{ text-align:center; margin-bottom: 20px; }}
  .print-btn {{ background: #1B2A4A; color: white; border: none; padding: 10px 24px; border-radius: 6px; font-size: 12pt; cursor: pointer; }}
</style>
</head><body>
<div class="no-print"><button class="print-btn" onclick="window.print()">Print / Save as PDF</button></div>
<div class="cover">
  <h1>Microsoft 365 Health Assessment</h1>
  <p style="font-size:18pt;font-weight:bold;color:#2E4A7A">{client}</p>
  <p>Assessment Date: {assess_date}</p>
  <p>Prepared by {consultant_name} &nbsp;|&nbsp; {consultant_role}</p>
  <p style="color:#C0392B;font-weight:bold">CONFIDENTIAL</p>
</div>

<h2>1. Executive Summary</h2>
<div class="score-box">
  <div class="score-num">{score}/100</div>
  <div>Overall Security Score</div>
</div>
<div class="counts">
  <div class="count-box" style="background:#FDECEA;border:2px solid #C0392B"><div class="count-num" style="color:#C0392B">{counts["critical"]}</div><div>Critical</div></div>
  <div class="count-box" style="background:#FEF0E7;border:2px solid #D35400"><div class="count-num" style="color:#D35400">{counts["high"]}</div><div>High</div></div>
  <div class="count-box" style="background:#FEFAE7;border:2px solid #D4AC0D"><div class="count-num" style="color:#D4AC0D">{counts["medium"]}</div><div>Medium</div></div>
  <div class="count-box" style="background:#EAF7EE;border:2px solid #27AE60"><div class="count-num" style="color:#27AE60">{counts["low"]}</div><div>Low</div></div>
</div>
<div class="notice">
  <strong>Beyond Microsoft Secure Score:</strong> Microsoft Secure Score measures configuration compliance - whether recommended settings are turned on.
  This assessment evaluates real attack paths. A tenant can achieve a high Secure Score and still be vulnerable to business email compromise, OAuth app abuse, and lateral movement.
  Each finding below represents a genuine risk that an attacker could exploit.
</div>

<h2>2. Findings</h2>
{findings_html}

<h2>3. Metrics Summary</h2>
<table class="metrics-table">
  <tr><th>Metric</th><th>Value</th></tr>
  {metrics_html}
</table>

<footer>{consultant_name} &nbsp;|&nbsp; {consultant_role} &nbsp;|&nbsp; {consultant_email}</footer>
</body></html>"""




# =================================================================
#  APP REGISTRATION PERMISSION CHECKER
# =================================================================

# Required permissions per module (Graph Application permissions)
MODULE_REQUIRED_PERMISSIONS = {
    "identity": [
        "User.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "AuditLog.Read.All",
        "Organization.Read.All",
        "Policy.Read.All",
    ],
    "security": [
        "Policy.Read.All",
        "SecurityEvents.Read.All",
        "Organization.Read.All",
        "Application.Read.All",
    ],
    "intune": [
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
    ],
    # Exchange, Teams, SharePoint always use interactive - no app reg check needed
    "exchange":   [],
    "teams":      [],
    "sharepoint": [],
}

INTERACTIVE_ONLY_MODULES_SET = {"exchange", "teams", "sharepoint"}




@app.route("/test-connection", methods=["POST"])
def test_connection():
    """Quick connection test - validates credentials without running a full assessment."""
    body          = request.get_json()
    auth_method   = body.get("authMethod", "interactive").strip().lower()
    tenant_id     = body.get("tenantId", "").strip()
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()

    if auth_method == "appreg":
        if not all([tenant_id, client_id, client_secret]):
            return jsonify({"connected": False, "error": "Tenant ID, Client ID and Client Secret are all required"})

        try:
            token_url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_data = urllib.parse.urlencode({
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default",
            }).encode("utf-8")
            req = urllib.request.Request(token_url, data=token_data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=10) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))
            access_token = token_resp.get("access_token")
            if not access_token:
                return jsonify({"connected": False, "error": "No access token returned. Check credentials."})
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_desc = err_body.get("error_description", str(e))[:120]
            except Exception:
                err_desc = str(e)
            return jsonify({"connected": False, "error": f"Authentication failed: {err_desc}"})
        except Exception as e:
            return jsonify({"connected": False, "error": f"Connection failed: {str(e)[:120]}"})

        # Get org info to confirm access
        try:
            org_req = urllib.request.Request("https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains")
            org_req.add_header("Authorization", f"Bearer {access_token}")
            with urllib.request.urlopen(org_req, timeout=10) as resp:
                org_data = json.loads(resp.read().decode("utf-8"))
            org    = org_data.get("value", [{}])[0]
            name   = org.get("displayName", "Unknown")
            domain = next((d.get("name","") for d in org.get("verifiedDomains",[]) if d.get("isInitial")), "")
            return jsonify({"connected": True, "tenantName": name, "domain": domain,
                            "authMode": "App Registration", "message": f"Connected to {name} ({domain})"})
        except Exception:
            return jsonify({"connected": True, "message": "Connected - token obtained successfully", "authMode": "App Registration"})
    else:
        return jsonify({"connected": True, "message": "Interactive login will be prompted when assessment runs", "authMode": "Interactive"})

@app.route("/check-permissions", methods=["POST"])
def check_permissions():
    """
    Verify an App Registration has the required Graph permissions
    for the selected assessment modules.
    Calls the Graph API to get the service principal's app roles
    and compares against required permissions.
    """
    body          = request.get_json()
    tenant_id     = body.get("tenantId", "").strip()
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    modules       = body.get("modules", list(MODULE_REQUIRED_PERMISSIONS.keys()))

    if not tenant_id or not client_id or not client_secret:
        return jsonify({"error": "Tenant ID, Client ID and Client Secret are required"}), 400

    # Get an access token using client credentials
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = urllib.parse.urlencode({
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(token_url, data=token_data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_resp = json.loads(resp.read().decode("utf-8"))
        access_token = token_resp.get("access_token")
        if not access_token:
            return jsonify({"error": "Could not obtain access token. Check Tenant ID, Client ID and Secret."}), 401
    except urllib.error.HTTPError as e:
        err_body = json.loads(e.read().decode("utf-8"))
        err_desc = err_body.get("error_description", str(e))
        return jsonify({"error": f"Authentication failed: {err_desc[:200]}"}), 401
    except Exception as e:
        return jsonify({"error": f"Token request failed: {str(e)}"}), 500

    # Get the service principal for this app registration
    try:
        sp_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{client_id}'&$select=id,displayName,appRoles"
        req2   = urllib.request.Request(sp_url)
        req2.add_header("Authorization", f"Bearer {access_token}")
        req2.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req2, timeout=15) as resp:
            sp_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return jsonify({"error": f"Could not query service principal: {str(e)}"}), 500

    # Get granted app role assignments (what permissions have been granted + consented)
    granted_permissions = set()
    try:
        sp_list = sp_data.get("value", [])
        if sp_list:
            sp_id = sp_list[0]["id"]
            # Get app role assignments for this SP
            roles_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
            req3 = urllib.request.Request(roles_url)
            req3.add_header("Authorization", f"Bearer {access_token}")
            with urllib.request.urlopen(req3, timeout=15) as resp:
                roles_data = json.loads(resp.read().decode("utf-8"))

            # For each role assignment, get the permission name from the resource SP
            resource_sps = {}
            for assignment in roles_data.get("value", []):
                resource_id   = assignment.get("resourceId")
                app_role_id   = assignment.get("appRoleId")
                if not resource_id or not app_role_id:
                    continue
                # Cache resource SP lookups
                if resource_id not in resource_sps:
                    try:
                        rsp_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{resource_id}?$select=appRoles,displayName"
                        req4 = urllib.request.Request(rsp_url)
                        req4.add_header("Authorization", f"Bearer {access_token}")
                        with urllib.request.urlopen(req4, timeout=15) as resp:
                            resource_sps[resource_id] = json.loads(resp.read().decode("utf-8"))
                    except Exception:
                        resource_sps[resource_id] = {}

                rsp     = resource_sps.get(resource_id, {})
                sp_name = rsp.get("displayName", "")
                if sp_name == "Microsoft Graph":
                    for role in rsp.get("appRoles", []):
                        if role.get("id") == app_role_id:
                            granted_permissions.add(role.get("value", ""))
                            break
    except Exception as e:
        return jsonify({"error": f"Could not retrieve permissions: {str(e)}"}), 500

    # Check each module
    results = {}
    all_ok  = True

    for module in modules:
        if module in INTERACTIVE_ONLY_MODULES_SET:
            results[module] = {
                "status":  "interactive",
                "message": "This module always uses interactive login — App Registration not required.",
                "missing": [],
                "granted": [],
            }
            continue

        required = MODULE_REQUIRED_PERMISSIONS.get(module, [])
        missing  = [p for p in required if p not in granted_permissions]
        present  = [p for p in required if p in granted_permissions]

        if missing:
            all_ok = False
            results[module] = {
                "status":  "missing",
                "message": f"{len(missing)} permission(s) missing. Grant them in Entra ID and re-run admin consent.",
                "missing": missing,
                "granted": present,
            }
        else:
            results[module] = {
                "status":  "ok",
                "message": "All required permissions granted.",
                "missing": [],
                "granted": present,
            }

    # Build missing list and fix instructions
    all_missing = []
    for mod_result in results.values():
        all_missing.extend(mod_result.get("missing", []))
    all_missing = list(set(all_missing))

    fix_instructions = []
    if all_missing:
        fix_instructions.append(f"Go to Entra ID > App registrations > {client_id} > API permissions")
        fix_instructions.append("Click: Add a permission > Microsoft Graph > Application permissions")
        for perm in sorted(all_missing):
            fix_instructions.append(f"Add: {perm}")
        fix_instructions.append("Click: Grant admin consent for your organisation")

    # Normalise module results for frontend compatibility
    norm_modules = {}
    for mod, res in results.items():
        norm_modules[mod] = {
            "status":   res.get("status", "ok"),
            "present":  res.get("granted", []),
            "missing":  res.get("missing", []),
            "authMode": "Interactive" if res.get("status") == "interactive" else "AppRegistration",
            "note":     res.get("message", ""),
        }

    return jsonify({
        "success":         True,
        "allGranted":      all_ok,
        "allOk":           all_ok,
        "grantedCount":    len(granted_permissions),
        "grantedPerms":    sorted(list(granted_permissions)),
        "modules":         norm_modules,
        "missingAll":      all_missing,
        "fixInstructions": fix_instructions,
        "tenantId":        tenant_id,
        "clientId":        client_id,
    })






@app.route("/sessions/<filename>", methods=["GET"])
def load_session(filename):
    """
    Load a specific saved assessment session.
    Also scans the output folder for any snapshot files for this client
    and returns remediation state so rollback works after reload.
    """
    if not filename.startswith("Session_") or not filename.endswith(".json"):
        return jsonify({"error": "Invalid session file"}), 400
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Session file not found"}), 404
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Upgrade legacy sessions — inject framework data into findings that predate v1.5
        for finding in data.get("findings", []):
            if not finding.get("frameworks"):
                finding["frameworks"] = _inject_fw_rem(FRAMEWORK_MAPPING.get(finding.get("id", ""), {}))

        client_name = data.get("clientName", "")
        safe        = client_name.replace(" ", "_").replace("/", "-")

        # Scan for snapshot files for this client and restore remediation state
        remediation_state = {}
        try:
            for fname in os.listdir(OUTPUT_DIR):
                if fname.startswith(f"Snapshot_{safe}_") and fname.endswith(".json"):
                    snap_path = os.path.join(OUTPUT_DIR, fname)
                    try:
                        with open(snap_path, "r", encoding="utf-8") as sf:
                            snap = json.load(sf)
                        finding_id = snap.get("findingId")
                        if finding_id:
                            # Most recent snapshot wins
                            existing = remediation_state.get(finding_id, {})
                            if snap.get("timestamp", "") >= existing.get("timestamp", ""):
                                remediation_state[finding_id] = {
                                    "status": "done",
                                    "snapshotFile": fname,
                                    "timestamp": snap.get("timestamp", ""),
                                    "previousState": snap.get("previousState", {}),
                                }
                    except Exception:
                        pass
        except Exception:
            pass

        # Also load remediation log to mark any rolled-back items
        log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as lf:
                    log = json.load(lf)
                # Process log entries in order - last action wins per finding
                for entry in log:
                    fid = entry.get("findingId")
                    if not fid: continue
                    action = entry.get("action")
                    if action == "rollback" and entry.get("success"):
                        if fid in remediation_state:
                            remediation_state[fid]["status"] = "rolled"
                    elif action == "remediate" and entry.get("success"):
                        snap_file = entry.get("snapshotFile")
                        if fid not in remediation_state and snap_file:
                            remediation_state[fid] = {
                                "status": "done",
                                "snapshotFile": snap_file,
                                "timestamp": entry.get("timestamp", ""),
                            }
                data["remediationLog"] = log
            except Exception:
                pass

        data["remediationState"] = remediation_state
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions/<filename>", methods=["PATCH"])
def patch_session(filename):
    """
    Merge finding annotations (status, reason, notes) into a saved session
    without overwriting the full session. Accepts:
      { "annotations": { "CA-003": { "status": "accepted_risk", "reason": "...", "notes": "..." } } }
    """
    if not filename.startswith("Session_") or not filename.endswith(".json"):
        return jsonify({"error": "Invalid session file"}), 400
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Session not found"}), 404
    try:
        payload = request.get_json(force=True) or {}
        with open(filepath, "r", encoding="utf-8") as f:
            session_data = json.load(f)
        # Merge annotations
        if "annotations" in payload:
            existing = session_data.get("annotations", {})
            existing.update(payload["annotations"])
            session_data["annotations"] = existing
        # Merge any other top-level keys explicitly passed
        for key in ("adjustedScore",):
            if key in payload:
                session_data[key] = payload[key]
        session_data["annotatedAt"] = datetime.datetime.now().isoformat()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2)
        return jsonify({"ok": True, "filename": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions/<filename>", methods=["DELETE"])
def delete_session(filename):
    """Delete a saved session file."""
    if not filename.startswith("Session_") or not filename.endswith(".json"):
        return jsonify({"error": "Invalid session file"}), 400
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Session not found"}), 404
    try:
        os.remove(filepath)
        return jsonify({"deleted": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions", methods=["GET"])
def list_sessions():
    """List all saved assessment sessions, newest first."""
    sessions = []
    try:
        files = sorted(
            [f for f in os.listdir(OUTPUT_DIR) if f.startswith("Session_") and f.endswith(".json")],
            reverse=True
        )
        for fname in files:
            filepath = os.path.join(OUTPUT_DIR, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sessions.append({
                    "filename":     fname,
                    "clientName":   data.get("clientName", data.get("orgName", "Unknown")),
                    "assessDate":   data.get("assessDate", ""),
                    "score":        data.get("score", 0),
                    "findingsCount": len(data.get("findings", [])),
                    "modulesRun":   data.get("modulesRun", 0),
                    "savedAt":      data.get("savedAt", ""),
                    "toolVersion":  data.get("toolVersion", ""),
                })
            except Exception:
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"sessions": sessions})








# =================================================================
#  PHASE 4 - MULTI-ASSESSMENT COMPARISON
# =================================================================

@app.route("/compare", methods=["POST"])
def compare_assessments():
    """
    Compare two saved assessment sessions.
    Returns a structured comparison including score delta,
    resolved findings, new findings, still open, and trend data.
    """
    body    = request.get_json()
    file_a  = body.get("sessionA", "")
    file_b  = body.get("sessionB", "")

    if not file_a or not file_b:
        return jsonify({"error": "Two session files required"}), 400

    # Load both sessions
    def load_sess(filename):
        if not filename.startswith("Session_") or not filename.endswith(".json"):
            return None, "Invalid session file"
        path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(path):
            return None, f"Session not found: {filename}"
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), None
        except Exception as e:
            return None, str(e)

    sess_a, err_a = load_sess(file_a)
    sess_b, err_b = load_sess(file_b)

    if err_a: return jsonify({"error": f"Session A: {err_a}"}), 400
    if err_b: return jsonify({"error": f"Session B: {err_b}"}), 400

    # Ensure A is the earlier session
    date_a = sess_a.get("assessDate", "")
    date_b = sess_b.get("assessDate", "")
    if date_a > date_b:
        sess_a, sess_b = sess_b, sess_a
        file_a, file_b = file_b, file_a

    findings_a = {f["id"]: f for f in sess_a.get("findings", [])}
    findings_b = {f["id"]: f for f in sess_b.get("findings", [])}

    ids_a = set(findings_a.keys())
    ids_b = set(findings_b.keys())

    # Resolved: was in A, not in B
    resolved = [findings_a[fid] for fid in (ids_a - ids_b)]
    # New: in B but not in A
    new_findings = [findings_b[fid] for fid in (ids_b - ids_a)]
    # Still open: in both
    still_open = [findings_b[fid] for fid in (ids_a & ids_b)]
    # Improved severity: same finding but lower severity in B
    improved = []
    for fid in (ids_a & ids_b):
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sev_a = sev_order.get(findings_a[fid].get("severity", "low"), 3)
        sev_b = sev_order.get(findings_b[fid].get("severity", "low"), 3)
        if sev_b < sev_a:
            improved.append({
                **findings_b[fid],
                "previousSeverity": findings_a[fid].get("severity"),
            })

    score_a = sess_a.get("score", 0)
    score_b = sess_b.get("score", 0)
    score_delta = score_b - score_a

    # Metric comparison
    metrics_a = {m["sub"]: m for m in sess_a.get("metrics", [])}
    metrics_b = {m["sub"]: m for m in sess_b.get("metrics", [])}
    metric_changes = []
    for key in set(list(metrics_a.keys()) + list(metrics_b.keys())):
        ma = metrics_a.get(key)
        mb = metrics_b.get(key)
        if ma and mb and ma.get("value") != mb.get("value"):
            metric_changes.append({
                "label":    mb.get("label", key),
                "before":   ma.get("value", "-"),
                "after":    mb.get("value", "-"),
                "statusA":  ma.get("status", ""),
                "statusB":  mb.get("status", ""),
            })

    # Severity counts for both
    def sev_counts(findings_dict):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings_dict.values():
            s = f.get("severity", "low")
            if s in counts: counts[s] += 1
        return counts

    def enrich_findings(findings_dict):
        """Apply FRAMEWORK_MAPPING (with fw_rem) to findings for compare framework delta."""
        result = []
        for f in findings_dict.values():
            fc = dict(f)
            if not fc.get("frameworks"):
                fc["frameworks"] = _inject_fw_rem(FRAMEWORK_MAPPING.get(fc.get("id", ""), {}))
            result.append(fc)
        return result

    return jsonify({
        "sessionA": {
            "filename":        file_a,
            "orgName":         sess_a.get("orgName", sess_a.get("clientName", "Unknown")),
            "assessDate":      sess_a.get("assessDate", ""),
            "score":           score_a,
            "findingCount":    len(ids_a),
            "sevCounts":       sev_counts(findings_a),
            "activeFrameworks": sess_a.get("activeFrameworks", []),
            "findings":        enrich_findings(findings_a),
        },
        "sessionB": {
            "filename":        file_b,
            "orgName":         sess_b.get("orgName", sess_b.get("clientName", "Unknown")),
            "assessDate":      sess_b.get("assessDate", ""),
            "score":           score_b,
            "findingCount":    len(ids_b),
            "sevCounts":       sev_counts(findings_b),
            "activeFrameworks": sess_b.get("activeFrameworks", []),
            "findings":        enrich_findings(findings_b),
        },
        "scoreDelta":    score_delta,
        "resolved":      resolved,
        "newFindings":   new_findings,
        "stillOpen":     still_open,
        "improved":      improved,
        "metricChanges": metric_changes,
        "summary": {
            "resolvedCount": len(resolved),
            "newCount":      len(new_findings),
            "stillOpenCount": len(still_open),
            "improvedCount": len(improved),
            "overallTrend":  "improved" if score_delta > 0 else "declined" if score_delta < 0 else "unchanged",
        }
    })


@app.route("/compare/report", methods=["POST"])
def comparison_report():
    """Generate a Word comparison report from two sessions."""
    body      = request.get_json()
    comp_data = body.get("comparisonData", {})
    generator = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    org_name  = comp_data.get("sessionA", {}).get("orgName", "Organisation")
    safe_name = org_name.replace(" ", "_").replace("/", "-")
    date_str  = datetime.date.today().strftime("%Y%m%d")
    filename  = f"M365_Comparison_{safe_name}_{date_str}.docx"
    rep_path  = os.path.join(REPORTS_DIR, filename)
    json_path = os.path.join(REPORTS_DIR, f"_tmp_compare_{safe_name}.json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(comp_data, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, rep_path, "comparison"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report failed: {result.stderr.strip()}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(rep_path):
        return jsonify({"error": "Report file not created"}), 500

    return send_file(rep_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True, download_name=filename)

# =================================================================
#  SIMULATOR - Attack Chain Engine
# =================================================================

ATTACK_CHAINS = [
    {
        "id": "BEC",
        "name": "Business Email Compromise",
        "description": "Attacker bypasses MFA via SIM swapping, authenticates using legacy protocols, then silently forwards emails to an external address to intercept financial communications.",
        "requires": ["SEC-004", "CA-002", "EXO-001"],
        "severity": "critical",
        "steps": [
            "Attacker identifies a target user with SMS-based MFA",
            "SIM swap attack transfers the victim's phone number to attacker",
            "Attacker authenticates via legacy protocol (bypasses Conditional Access)",
            "Silent forwarding rule created — all emails copied to attacker",
            "Financial emails, invoices, and credentials intercepted indefinitely"
        ],
        "impact": "Invoice fraud, credential theft, financial loss. Average BEC loss: $125,000 per incident.",
        "broken_by": "Fixing any one of: SEC-004 (remove weak MFA), CA-002 (block legacy auth), EXO-001 (block forwarding)"
    },
    {
        "id": "ATO",
        "name": "Account Takeover",
        "description": "Without MFA enforcement or Conditional Access policies, a phishing attack or credential stuffing can result in full account compromise with no controls to detect or prevent it.",
        "requires": ["ID-001", "CA-001", "SEC-002"],
        "severity": "critical",
        "steps": [
            "Attacker sends phishing email to obtain credentials",
            "No MFA enforced — attacker signs in with username and password only",
            "No Conditional Access — sign-in from unknown location not challenged",
            "Full access to email, files, Teams, and SharePoint",
            "Attacker moves laterally to other accounts using harvested credentials"
        ],
        "impact": "Full account compromise, data breach, lateral movement to other systems.",
        "broken_by": "Fixing any one of: ID-001 (enforce MFA), CA-001 (deploy CA policies), SEC-002 (enable security defaults)"
    },
    {
        "id": "PRIV",
        "name": "Privilege Escalation",
        "description": "With too many permanent Global Administrators and no just-in-time access controls, compromising any one admin account gives an attacker unrestricted tenant-wide control.",
        "requires": ["ID-002", "ID-003"],
        "severity": "critical",
        "steps": [
            "Attacker targets one of the many permanent Global Admin accounts",
            "Account compromised via phishing, credential stuffing, or password spray",
            "No PIM in place — attacker has immediate permanent Global Admin access",
            "Attacker creates backdoor admin accounts and disables security controls",
            "Full tenant control established — MFA disabled, audit logs cleared"
        ],
        "impact": "Complete tenant takeover. Attacker can access all data, disable security, create persistent backdoors.",
        "broken_by": "Both required: ID-002 (reduce Global Admins) AND ID-003 (enable PIM for just-in-time access)"
    },
    {
        "id": "OAUTH",
        "name": "OAuth App Abuse",
        "description": "Users can be tricked into granting a malicious third-party app access to their email, files, and directory data. The app retains access permanently, even after the user's password is reset.",
        "requires": ["SEC-005", "APP-001"],
        "severity": "high",
        "steps": [
            "Attacker creates a convincing OAuth app requesting Mail.Read and Files.ReadWrite permissions",
            "Phishing email directs user to consent page — user clicks Accept",
            "App has persistent access to mailbox and files — survives password resets",
            "Attacker exfiltrates emails and documents continuously via Graph API",
            "Access persists until app is manually revoked by an administrator"
        ],
        "impact": "Persistent data exfiltration. Access survives MFA resets and password changes.",
        "broken_by": "Both help: SEC-005 (restrict user consent) AND APP-001 (review existing high-privilege apps)"
    },
    {
        "id": "EXFIL",
        "name": "Data Exfiltration",
        "description": "A combination of open SharePoint sharing, unblocked email forwarding, and no alerting creates multiple unmonitored channels for data to leave the organisation without detection.",
        "requires": ["SPO-001", "EXO-001", "MON-001"],
        "severity": "high",
        "steps": [
            "Attacker or malicious insider identifies sensitive SharePoint sites",
            "Files shared via Anyone links — no authentication required to access",
            "Email forwarding configured to send copies to external address",
            "No Defender alerts configured — exfiltration goes undetected",
            "Data leaves the organisation through multiple channels simultaneously"
        ],
        "impact": "Undetected bulk data theft. Regulatory breach risk (GDPR). No forensic trail.",
        "broken_by": "Fixing any one significantly reduces risk: SPO-001 (restrict sharing), EXO-001 (block forwarding), MON-001 (enable alerting)"
    },
    {
        "id": "RANSOM",
        "name": "Ransomware Deployment",
        "description": "Legacy authentication bypasses MFA, allowing access from an unmanaged and unpatched device. Once inside, ransomware is deployed across SharePoint, OneDrive, and connected file shares.",
        "requires": ["CA-002", "MDM-001", "MDM-002"],
        "severity": "critical",
        "steps": [
            "Attacker authenticates via legacy protocol — bypasses MFA and Conditional Access",
            "Access granted from unmanaged device with no compliance check",
            "No compliance policies to detect missing patches or disabled antivirus",
            "Ransomware payload deployed to OneDrive — version sync spreads to SharePoint",
            "Files encrypted across the tenant — backups potentially compromised"
        ],
        "impact": "Full file encryption across M365. Average ransomware recovery cost: $1.85M. Operational shutdown.",
        "broken_by": "CA-002 is critical (block legacy auth). MDM-001 and MDM-002 add defence in depth."
    },
    {
        "id": "APP-TAKEOVER",
        "name": "App Registration Credential Theft",
        "description": "An attacker targets a high-privilege app registration with an expired or leaked credential. Using the credential, they authenticate as the application identity and gain persistent tenant-wide access that survives all user-based controls including MFA resets and password changes.",
        "requires": ["ENTRA-001", "ENTRA-002"],
        "severity": "critical",
        "steps": [
            "Attacker identifies high-privilege app registrations via public reconnaissance or leaked configs",
            "Expired or leaked client secret discovered in code repository, deployment pipeline, or dark web",
            "Attacker authenticates as the application — no user interaction, no MFA prompt",
            "Application-level access grants tenant-wide permissions (e.g., Mail.ReadWrite, Directory.ReadWrite.All)",
            "Persistent access maintained silently — survives user password resets and MFA changes"
        ],
        "impact": "Full tenant-wide data access at application permission level. Credential theft survives all user-based remediation.",
        "broken_by": "Both required: ENTRA-001 (remove high-privilege permissions) AND ENTRA-002 (rotate or remove expired credentials)"
    },
    {
        "id": "SP-PERSIST",
        "name": "Service Principal Backdoor",
        "description": "A service principal with a high-privilege directory role acts as a persistent, non-interactive backdoor. An attacker who compromises the associated application gains admin-level tenant access without triggering user-based sign-in alerts, MFA prompts, or Conditional Access controls.",
        "requires": ["ENTRA-009"],
        "severity": "high",
        "steps": [
            "Attacker identifies a service principal assigned to Global Administrator or Application Administrator role",
            "Application credentials (secret or certificate) obtained via code repo, config leak, or phishing",
            "Attacker authenticates as the service principal — bypasses all user Conditional Access policies",
            "Admin-level directory access obtained: create users, assign roles, modify CA policies",
            "Backdoor account created under attacker control — persistent access even after initial credential revoked"
        ],
        "impact": "Complete tenant administrative access without any user-based detection or MFA controls.",
        "broken_by": "ENTRA-009: Remove high-privilege directory role assignments from all service principals"
    },
    {
        "id": "PERSIST",
        "name": "Invisible Persistence",
        "description": "An attacker who gains access establishes multiple persistence mechanisms — rogue apps, email forwarding rules, and backdoor accounts — while generating no alerts. The compromise can go undetected for months.",
        "requires": ["APP-001", "MON-001", "EXO-001"],
        "severity": "high",
        "steps": [
            "Initial access gained via any vector (phishing, legacy auth, weak MFA)",
            "Rogue OAuth app registered with high-privilege permissions as backdoor",
            "Silent email forwarding rules created on key mailboxes",
            "No alert policies — no notifications sent to administrators",
            "Attacker maintains persistent access and intelligence for months undetected"
        ],
        "impact": "Long-term undetected compromise. Average dwell time without alerting: 197 days.",
        "broken_by": "MON-001 is most critical (enable alerting). APP-001 and EXO-001 remove persistence mechanisms."
    },
]


@app.route("/simulator/chains", methods=["POST"])
def simulate_chains():
    """
    Evaluate attack chains against a set of open finding IDs.
    Returns which chains are active, broken, and partially mitigated.
    """
    body            = request.get_json()
    open_finding_ids = set(body.get("openFindings", []))
    all_finding_ids  = set(body.get("allFindings", []))

    results = []
    for chain in ATTACK_CHAINS:
        required     = set(chain["requires"])
        active_reqs  = required & open_finding_ids
        fixed_reqs   = required - open_finding_ids

        if len(active_reqs) == len(required):
            status = "active"      # All requirements open - chain fully active
        elif len(active_reqs) == 0:
            status = "broken"      # All requirements fixed - chain broken
        else:
            status = "partial"     # Some fixed, some still open - partially mitigated

        # Score contribution - how much does fixing this chain improve security
        score_impact = len(active_reqs) * {"critical": 15, "high": 10}.get(chain["severity"], 5)

        results.append({
            "id":           chain["id"],
            "name":         chain["name"],
            "description":  chain["description"],
            "severity":     chain["severity"],
            "status":       status,
            "requires":     chain["requires"],
            "activeReqs":   list(active_reqs),
            "fixedReqs":    list(fixed_reqs),
            "steps":        chain["steps"],
            "impact":       chain["impact"],
            "broken_by":    chain["broken_by"],
            "scoreImpact":  score_impact,
        })

    # Calculate simulated score
    open_findings_list = body.get("openFindingsData", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings_list:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    sim_score = max(10, 100 - (
        min(counts["critical"] * 8, 32) +
        min(counts["high"]     * 5, 20) +
        min(counts["medium"]   * 3, 12) +
        min(counts["low"]      * 1,  4)
    ))

    active_chains  = [r for r in results if r["status"] == "active"]
    broken_chains  = [r for r in results if r["status"] == "broken"]
    partial_chains = [r for r in results if r["status"] == "partial"]

    return jsonify({
        "chains":        results,
        "simScore":      sim_score,
        "activeCount":   len(active_chains),
        "brokenCount":   len(broken_chains),
        "partialCount":  len(partial_chains),
        "criticalChains": len([c for c in active_chains if c["severity"] == "critical"]),
    })

# =================================================================
#  REMEDIATION ROUTES
# =================================================================

REMEDIATION_DIR = os.path.join(BASE_DIR, "remediation")

# Maps finding ID to its remediation and rollback scripts
REMEDIATION_MAP = {
    "CA-002": {
        "script": "Remediate-LegacyAuth.ps1", "rollback": "Rollback-LegacyAuth.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess\n# Create CA policy blocking legacy auth in Entra ID:\n# Entra ID > Protection > Conditional Access > New Policy\n# Conditions: Client apps = Exchange ActiveSync + Other clients\n# Grant: Block access",
        "manual_rollback": "# Go to Entra ID > Protection > Conditional Access\n# Find policy named: MM-Assessment - Block Legacy Authentication\n# Delete or disable the policy",
    },
    "CA-003": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["graph"],
        "manual_fix": "# Entra ID > Protection > Conditional Access > New Policy\n# Name: Require MFA for All Users\n# Assignments: Users — All users (exclude break-glass accounts)\n# Target resources: All cloud apps\n# Grant: Require multi-factor authentication\n# Enable policy: On",
        "manual_rollback": "# Entra ID > Protection > Conditional Access\n# Find the MFA policy and disable or delete it",
    },
    "EXO-001": {
        "script": "Remediate-ExternalForwarding.ps1", "rollback": "Rollback-ExternalForwarding.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\nSet-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\nSet-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Automatic\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "EXO-002": {
        "script": "Remediate-MailboxAudit.ps1", "rollback": "Rollback-MailboxAudit.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\nSet-OrganizationConfig -AuditDisabled $false\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\nSet-OrganizationConfig -AuditDisabled $true\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "EXO-003": {
        "script": "Remediate-AntiPhish.ps1", "rollback": "Rollback-AntiPhish.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\n$Policy = Get-AntiPhishPolicy | Select-Object -First 1\nSet-AntiPhishPolicy -Identity $Policy.Name -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\n$Policy = Get-AntiPhishPolicy | Select-Object -First 1\nSet-AntiPhishPolicy -Identity $Policy.Name -EnableMailboxIntelligence $false\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "SEC-003": {
        "script": "Remediate-MFAFatigue.ps1", "rollback": "Rollback-MFAFatigue.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Protection > Authentication Methods > Microsoft Authenticator\n# Enable: Require number matching\n# Enable: Show additional context in notifications",
        "manual_rollback": "# Entra ID > Protection > Authentication Methods > Microsoft Authenticator\n# Disable: Require number matching\n# Disable: Show additional context in notifications",
    },
    "SEC-004": {
        "script": "Remediate-WeakAuth.ps1", "rollback": "Rollback-WeakAuth.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Protection > Authentication Methods\n# Select SMS > Disable\n# Select Voice call > Disable\n# Select Email OTP > Disable",
        "manual_rollback": "# Entra ID > Protection > Authentication Methods\n# Re-enable SMS, Voice call, or Email OTP as required",
    },
    "SEC-005": {
        "script": "Remediate-UserConsent.ps1", "rollback": "Rollback-UserConsent.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Enterprise Applications > Consent and Permissions > User consent settings\n# Set: Do not allow user consent\n# Enable: Admin consent request workflow",
        "manual_rollback": "# Entra ID > Enterprise Applications > Consent and Permissions > User consent settings\n# Restore to: Allow user consent for apps from verified publishers",
    },
    "TEAMS-002": {
        "script": "Remediate-TeamsConsumer.ps1", "rollback": "Rollback-TeamsConsumer.ps1",
        "tier": 1, "auth": ["teams"],
        "manual_fix": "Connect-MicrosoftTeams\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $false\nDisconnect-MicrosoftTeams",
        "manual_rollback": "Connect-MicrosoftTeams\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $true\nDisconnect-MicrosoftTeams",
    },
    "TEAMS-003": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["teams"],
        "manual_fix": "Connect-MicrosoftTeams\nSet-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $false\nDisconnect-MicrosoftTeams",
        "manual_rollback": "Connect-MicrosoftTeams\nSet-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $true\nDisconnect-MicrosoftTeams",
    },
    "TEAMS-004": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["teams"],
        "manual_fix": "# Teams Admin Centre > Teams apps > Permission policies > Global\n# Change Third-party apps from 'Allow all' to 'Block all' or add an approved app list\n# Portal: https://admin.teams.microsoft.com/policies/app-permission",
        "manual_rollback": "# Teams Admin Centre > Teams apps > Permission policies > Global\n# Change Third-party apps back to 'Allow all'",
    },
    "SPO-002": {
        "script": "Remediate-SPOLegacyAuth.ps1", "rollback": "Rollback-SPOLegacyAuth.ps1",
        "tier": 1, "auth": ["sharepoint"],
        "manual_fix": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -LegacyAuthProtocolsEnabled $false\nDisconnect-SPOService",
        "manual_rollback": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -LegacyAuthProtocolsEnabled $true\nDisconnect-SPOService",
    },
    "SPO-003": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["sharepoint"],
        "manual_fix": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -ODBSharingCapability ExistingExternalUserSharingOnly\nDisconnect-SPOService",
        "manual_rollback": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -ODBSharingCapability ExternalUserAndGuestSharing\nDisconnect-SPOService",
    },
    "SPO-004": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["sharepoint"],
        "manual_fix": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 60\nDisconnect-SPOService",
        "manual_rollback": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -ExternalUserExpirationRequired $false\nDisconnect-SPOService",
    },
    "MDM-005": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["graph"],
        "manual_fix": "# Intune > Devices > Compliance policies > Create policy\n# Platform: iOS/iPadOS or Android device administrator / Android Enterprise\n# Settings: Minimum OS version, Require device encryption, Require screen lock, Jailbreak detection\n# Actions: Mark non-compliant, then block access after grace period",
        "manual_rollback": "# Delete the compliance policy created for iOS/Android in Intune",
    },
    "MDM-006": {
        "script": None, "rollback": None,
        "tier": 2, "auth": ["graph"],
        "manual_fix": "# Intune > Endpoint security > Microsoft Defender for Endpoint\n# Enable: Connect Windows devices to Microsoft Defender for Endpoint\n# Enable: Connect Android/iOS devices\n# Then in compliance policies: add Device Threat Level condition\n# Portal: https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/mdeConnector",
        "manual_rollback": "# Intune > Endpoint security > Microsoft Defender for Endpoint\n# Toggle off the platform connectors that were enabled",
    },
}

# Tier 2 findings - guided only, no auto-fix script
TIER2_GUIDANCE = {
    "ID-001":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods", "steps": ["Go to Entra ID > Protection > Authentication Methods", "Enable Microsoft Authenticator for all users", "Set registration campaign to nudge users without MFA to register", "Set a deadline of 14 days for registration"]},
    "ID-002":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles", "steps": ["Go to Entra ID > Roles and administrators > Global Administrator", "Review each Global Admin account", "Remove the Global Admin role from accounts that do not need it", "Assign least-privilege roles instead (e.g. Exchange Admin, Intune Admin)", "Keep a maximum of 2-3 break-glass accounts with Global Admin"]},
    "ID-003":  {"portal": "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart", "steps": ["Go to Entra ID > Identity Governance > Privileged Identity Management", "Click Entra roles", "Add eligible assignments for admin roles", "Remove permanent assignments and convert to eligible", "Configure approval workflow and MFA on activation"]},
    "CA-001":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies", "steps": ["Go to Entra ID > Protection > Conditional Access", "Create policy: Require MFA for all users", "Create policy: Require MFA for admin roles", "Create policy: Block legacy authentication", "Create policy: Require compliant device for M365 apps", "Set all policies to Report-only first, then Enabled after review"]},
    "ID-004":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UsersManagementMenuBlade/~/AllUsers", "steps": ["Go to Entra ID > Users > All Users", "Filter by User type = Guest", "Review each guest account", "Remove guests who no longer need access", "Set up Access Reviews under Identity Governance to automate this going forward"]},
    "SPO-001": {"portal": "https://admin.microsoft.com/sharepoint", "steps": ["Go to SharePoint Admin Centre > Policies > Sharing", "Change the top-level sharing setting from Anyone to New and existing guests", "Review site-level sharing settings for sensitive sites", "Enable expiry on Anyone links (recommended: 30 days)"]},
    "APP-001": {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview", "steps": ["Go to Entra ID > Enterprise Applications > All Applications", "Filter by Application type = Enterprise Applications", "Review each app's permissions under Permissions", "Remove or restrict apps with Directory.ReadWrite.All or Mail.ReadWrite.All", "Enable admin consent workflow under User settings > Admin consent requests"]},
    "MON-001": {"portal": "https://security.microsoft.com/alertpolicies", "steps": ["Go to Microsoft Defender > Policies > Alert Policies", "Enable high-severity alert policies: Malware detected, Suspicious email forwarding, Mass file download", "Set alert notification email to a monitored mailbox", "Review existing alerts under Incidents and Alerts"]},
    "MDM-001": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview", "steps": ["Go to Intune > Devices > Monitor > Device compliance", "Review non-compliant devices", "Identify common compliance failures (BitLocker, OS version, antivirus)", "Remediate devices or create exceptions where appropriate", "Consider blocking non-compliant devices via Conditional Access"]},
    "MDM-002": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies", "steps": ["Go to Intune > Devices > Compliance policies", "Create a Windows compliance policy requiring: BitLocker enabled, Minimum OS version, Antivirus enabled, Defender enabled", "Create equivalent policies for iOS and Android if managed", "Assign policies to All Users or All Devices"]},
    "SEC-001": {"portal": "https://security.microsoft.com/securescore", "steps": ["Go to Microsoft Defender > Secure Score", "Review improvement actions sorted by Points available", "Prioritise actions with High impact and Low implementation effort", "Assign actions to responsible team members", "Review score weekly"]},
    "SEC-002": {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantPropertiesBlade", "steps": ["Go to Entra ID > Properties > Manage security defaults", "If not using Conditional Access: enable Security Defaults", "If using Conditional Access: ensure CA policies cover all scenarios Security Defaults would cover (MFA for all, block legacy auth)", "Do not enable Security Defaults if you have existing CA policies - they conflict"]},
    "TEAMS-001": {"portal": "https://admin.teams.microsoft.com/company-wide-settings/external-communications", "steps": ["Go to Teams Admin Centre > Users > External access", "Change from Open federation to Allowed domains only", "Add any approved partner domains to the allowed list", "Remove unknown or unused domains"]},
    "ID-006":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RiskyUsersV2Blade", "steps": ["Go to Entra ID > Protection > Risky users", "Filter by Risk level: High, then Medium", "For high risk: select user > Block sign-in > Require password reset", "For medium risk: select user > Require users to re-register MFA", "Investigate the risk events behind each flagged user under Risk history", "Dismiss false positives after investigation"]},
    "ID-007":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UsersManagementMenuBlade/~/AllUsers", "steps": ["Create two dedicated emergency access accounts with long random passwords", "Exclude both accounts from all Conditional Access policies", "Store credentials in a physically secure location (e.g. safe, sealed envelope)", "Do NOT register MFA on break-glass accounts — if MFA fails, you cannot use them", "Set up an alert for any sign-in on these accounts", "Test the accounts annually to verify they work", "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"]},
    "SEC-006": {"portal": "https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/MainMenuBlade", "steps": ["Go to Azure Portal > Microsoft Sentinel", "If not deployed: Create a Sentinel workspace in your subscription", "Add the Microsoft 365 Defender data connector", "Add the Azure Active Directory data connector", "Enable the Microsoft Sentinel analytics rules relevant to your environment", "Configure a daily review process for Sentinel incidents"]},
    "EXO-004": {"portal": "https://admin.microsoft.com/Adminportal/Home#/Domains", "steps": ["Identify your primary domain in Microsoft 365 Admin > Settings > Domains", "Log into your DNS provider and add a TXT record", "Name: _dmarc.yourdomain.com", "Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com", "Wait for DNS propagation (up to 48 hours)", "Monitor reports for 2-4 weeks, then change p=none to p=quarantine", "Once confident, move to p=reject for full enforcement"]},
    "EXO-005": {"portal": "https://admin.exchange.microsoft.com/#/dkim", "steps": ["Go to Exchange Admin Centre > Email authentication > DKIM", "Select your domain and click Enable", "If not yet set up: follow the DNS record instructions provided", "For SPF: ensure your domain has a TXT record starting with v=spf1 include:spf.protection.outlook.com", "Add any other authorised senders (e.g. marketing platforms) to the SPF record", "Verify both records with MXToolbox before enabling DMARC enforcement"]},
    "EXO-006": {"portal": "https://security.microsoft.com/antimalwarev2", "steps": ["Go to Microsoft 365 Defender > Email & Collaboration > Policies & Rules > Threat policies", "Under Protection policies, click Anti-malware", "Open the Default policy and click Edit protection settings", "Ensure 'Enable zero-hour auto purge (ZAP)' is turned on", "Click Save", "Go back to Threat policies and click Anti-spam", "Open the Default inbound policy and click Edit actions", "Ensure 'Enable zero-hour auto purge (ZAP) for phishing messages' is on", "Ensure 'Enable zero-hour auto purge (ZAP) for spam messages' is on", "Click Save"]},
    "MDM-003": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/PatchManagementBlade/~/overview", "steps": ["Go to Intune > Devices > Windows > Update rings for Windows 10 and later", "Click Create profile", "Name it e.g. Pilot Ring — set quality update deferral to 3 days", "Create a second Production Ring with quality deferral of 7 days, feature deferral of 30 days", "Assign Pilot Ring to a test group, Production Ring to all Windows devices", "Monitor Windows Update compliance under Reports > Windows Updates"]},
    "MDM-004": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies", "steps": ["Go to Intune > Devices > Compliance policies > Create policy > Windows 10+", "Enable: Require BitLocker", "Also go to Intune > Devices > Configuration > Create > Windows > Templates > Endpoint Protection", "Configure BitLocker Drive Encryption settings", "Assign both policies to All Devices or Windows device groups", "Monitor encryption status under Intune > Devices > Monitor > Encryption report"]},
    "CA-003":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies", "steps": ["Go to Entra ID > Protection > Conditional Access", "Click New policy", "Name: Require MFA — All Users", "Assignments > Users: All users. Exclude your break-glass accounts by object ID", "Target resources: All cloud apps", "Grant: Require multi-factor authentication", "Set to Report-only first and review the sign-in log impact for 1-2 days", "Set to Enabled once confident"]},
    "TEAMS-003": {"portal": "https://admin.teams.microsoft.com/meetings/meeting-policies", "steps": ["Go to Teams Admin Centre > Meetings > Meeting policies", "Select the Global (Org-wide default) policy", "Under Participants and guests, find 'Anonymous users can join a meeting'", "Set to Off", "Click Save", "If specific users need anonymous join capability, create a custom policy and assign it to those users only"]},
    "TEAMS-004": {"portal": "https://admin.teams.microsoft.com/policies/app-permission", "steps": ["Go to Teams Admin Centre > Teams apps > Permission policies", "Select the Global (Org-wide default) policy", "Under Third-party apps, change from 'Allow all apps' to 'Block all apps' or 'Allow specific apps'", "If choosing specific apps: add each approved app individually", "Click Save", "Review any custom app permission policies that may override the global setting"]},
    "SPO-003":  {"portal": "https://admin.microsoft.com/sharepoint#/sharing", "steps": ["Go to SharePoint Admin Centre > Policies > Sharing", "Scroll to OneDrive — this is separate from the SharePoint sharing setting", "Change OneDrive external sharing from 'Anyone' to 'New and existing guests' at minimum", "Optionally restrict further to 'Existing guests only' or 'Only people in your organisation'", "Click Save", "Note: this does not affect existing shared links — audit and expire those separately"]},
    "SPO-004":  {"portal": "https://admin.microsoft.com/sharepoint#/sharing", "steps": ["Go to SharePoint Admin Centre > Policies > Sharing", "Expand 'More external sharing settings'", "Check 'Guest access to a site or OneDrive will expire automatically after this many days'", "Set a value — 60 days is a reasonable default for most organisations", "Also enable 'People who use a verification code must reauthenticate after this many days'", "Click Save", "Consider also enabling expiry on anonymous (Anyone) sharing links"]},
    "MDM-005":  {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies", "steps": ["Go to Intune > Devices > Compliance policies > Create policy", "Create an iOS/iPadOS policy: Minimum OS version, Require screen lock passcode, Require device not to be jailbroken", "Create an Android policy: Require device encryption, Minimum OS version, Require screen lock, Block rooted devices", "Assign both policies to All Users or a device group", "Set non-compliant action to Mark as non-compliant immediately, then block access after 1-day grace period", "Pair with a Conditional Access policy requiring compliant device for M365 apps"]},
    "MDM-006":  {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/mdeConnector", "steps": ["Go to Intune > Endpoint security > Microsoft Defender for Endpoint", "Click Connect under Microsoft Defender for Endpoint connector", "Enable the toggle for Windows devices", "Enable the toggle for Android devices (if managed)", "Enable the toggle for iOS/iPadOS devices (if managed)", "Click Save", "Go to Compliance policies and add a device threat level condition (e.g. Low or Medium)", "This passes device risk signals from Defender into Conditional Access"]},
}


def run_remediation_script(script_name, ps_args, timeout=180):
    """Run a remediation PowerShell script and return parsed JSON output."""
    script_path = os.path.join(REMEDIATION_DIR, script_name)
    if not os.path.exists(script_path):
        return None, f"Script not found: {script_name}"
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", script_path] + ps_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None, (result.stderr.strip() or f"Script exited with code {result.returncode}")
        if not result.stdout.strip():
            return None, "Script produced no output"
        data = json.loads(result.stdout.strip())
        return data, None
    except subprocess.TimeoutExpired:
        return None, f"Script timed out after {timeout} seconds"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON output: {e}. Output: {result.stdout[:300]}"
    except Exception as e:
        return None, str(e)


def save_remediation_log(client_name, finding_id, action, result, snapshot_file=None):
    """Append an entry to the remediation log for this client."""
    safe = client_name.replace(" ", "_").replace("/", "-")
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
    
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "findingId": finding_id,
        "action": action,  # "remediate", "rollback", "check"
        "success": result.get("success", False),
        "details": result.get("details", ""),
        "warning": result.get("warning", None),
        "snapshotFile": snapshot_file,
    }
    
    log = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                log = json.load(f)
        except Exception:
            log = []
    
    log.append(entry)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
    return log_path


@app.route("/remediate/check/<finding_id>", methods=["POST"])
def remediate_check(finding_id):
    """Run pre-remediation safety check for a finding without making changes."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No remediation available for {finding_id}", "tier": 2,
                        "guidance": TIER2_GUIDANCE.get(finding_id, {})}), 200
    
    body    = request.get_json()
    auth    = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment",
                                             "writeAuthSame","writeAuthMethod","writeTenantId","writeClientId","writeClientSecret","writeCertThumbprint"]}
    auth["writeAuthSame"] = body.get("writeAuthSame", True)
    mapping = REMEDIATION_MAP[finding_id]

    ps_args = build_ps_args_remediation(auth) + ["-CheckOnly"]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["script"], ps_args)
    if error:
        return jsonify({"error": error}), 500
    
    return jsonify(result)


@app.route("/remediate/run/<finding_id>", methods=["POST"])
def remediate_run(finding_id):
    """Execute remediation for a finding, saving a snapshot first."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No auto-remediation for {finding_id}. Use guided remediation.",
                        "tier": 2, "guidance": TIER2_GUIDANCE.get(finding_id, {})}), 200
    
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Unknown"))
    auth        = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment",
                                                 "writeAuthSame","writeAuthMethod","writeTenantId","writeClientId","writeClientSecret","writeCertThumbprint"]}
    auth["writeAuthSame"] = body.get("writeAuthSame", True)
    mapping     = REMEDIATION_MAP[finding_id]

    # Determine effective write auth label for logging
    write_same = auth.get("writeAuthSame", True)
    if write_same:
        write_label = auth.get("authMethod", "interactive")
    else:
        write_label = auth.get("writeAuthMethod", "interactive")

    # Create snapshot file path
    safe          = client_name.replace(" ", "_").replace("/", "-")
    timestamp     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_name = f"Snapshot_{safe}_{finding_id}_{timestamp}.json"
    snapshot_path = os.path.join(OUTPUT_DIR, snapshot_name)
    
    ps_args = build_ps_args_remediation(auth) + ["-SnapshotPath", snapshot_path]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["script"], ps_args)
    if error:
        save_remediation_log(client_name, finding_id, "remediate", {"success": False, "details": error})
        return jsonify({"error": error}), 500
    
    result["snapshotFile"] = snapshot_name
    save_remediation_log(client_name, finding_id, "remediate", result, snapshot_name)
    return jsonify(result)


@app.route("/remediate/rollback/<finding_id>", methods=["POST"])
def remediate_rollback(finding_id):
    """Roll back a previously remediated finding using its snapshot."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No rollback available for {finding_id}"}), 400
    
    body          = request.get_json()
    client_name   = body.get("orgName", body.get("clientName", "Unknown"))
    snapshot_name = body.get("snapshotFile", "")
    auth          = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment",
                                                   "writeAuthSame","writeAuthMethod","writeTenantId","writeClientId","writeClientSecret","writeCertThumbprint"]}
    auth["writeAuthSame"] = body.get("writeAuthSame", True)
    mapping       = REMEDIATION_MAP[finding_id]
    
    if not snapshot_name:
        return jsonify({"error": "No snapshot file specified for rollback"}), 400
    
    snapshot_path = os.path.join(OUTPUT_DIR, snapshot_name)
    if not os.path.exists(snapshot_path):
        return jsonify({"error": f"Snapshot file not found: {snapshot_name}"}), 404
    
    ps_args = build_ps_args_remediation(auth) + ["-SnapshotPath", snapshot_path]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["rollback"], ps_args)
    if error:
        save_remediation_log(client_name, finding_id, "rollback", {"success": False, "details": error})
        return jsonify({"error": error}), 500
    
    save_remediation_log(client_name, finding_id, "rollback", result, snapshot_name)
    return jsonify(result)



@app.route("/remediate/commands/<finding_id>", methods=["GET"])
def get_manual_commands(finding_id):
    """Return manual PowerShell commands for a finding."""
    if finding_id in REMEDIATION_MAP:
        mapping = REMEDIATION_MAP[finding_id]
        return jsonify({
            "findingId": finding_id,
            "tier": mapping.get("tier", 1),
            "manual_fix": mapping.get("manual_fix", "No manual command available"),
            "manual_rollback": mapping.get("manual_rollback", "No manual rollback available"),
        })
    return jsonify({"error": "No commands found"}), 404

@app.route("/remediate/guidance/<finding_id>", methods=["GET"])
def remediate_guidance(finding_id):
    """Return Tier 2 guided remediation steps for a finding."""
    if finding_id in TIER2_GUIDANCE:
        return jsonify({"tier": 2, "findingId": finding_id, "guidance": TIER2_GUIDANCE[finding_id]})
    elif finding_id in REMEDIATION_MAP:
        return jsonify({"tier": 1, "findingId": finding_id, "message": "Use /remediate/run for auto-fix"})
    return jsonify({"error": "No guidance available"}), 404


@app.route("/remediate/log/<client_name>", methods=["GET"])
def get_remediation_log(client_name):
    """Return the remediation log for a client."""
    safe     = client_name.replace(" ", "_").replace("/", "-")
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
    if not os.path.exists(log_path):
        return jsonify({"log": []})
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)
        return jsonify({"log": log})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def build_ps_args_remediation(auth):
    """Build PS args for remediation scripts.
    If separate write credentials are configured (writeAuthSame=False), use them.
    Otherwise fall back to the read (assessment) credentials — preserves existing behaviour.
    """
    write_same   = auth.get("writeAuthSame", True)
    write_method = auth.get("writeAuthMethod", "")

    if not write_same and write_method:
        # Separate write credentials provided
        if write_method == "appreg":
            return ["-AuthMethod", "AppReg",
                    "-TenantId",     auth.get("writeTenantId", ""),
                    "-ClientId",     auth.get("writeClientId", ""),
                    "-ClientSecret", auth.get("writeClientSecret", "")]
        elif write_method == "certificate":
            return ["-AuthMethod",        "Certificate",
                    "-TenantId",          auth.get("writeTenantId", ""),
                    "-ClientId",          auth.get("writeClientId", ""),
                    "-CertThumbprint",    auth.get("writeCertThumbprint", "")]
        else:
            args = ["-AuthMethod", "Interactive"]
            if auth.get("writeTenantId"):
                args += ["-TenantId", auth["writeTenantId"]]
            return args
    else:
        # Same as assessment — use read credentials (existing behaviour)
        if auth.get("authMethod") == "appreg":
            return ["-AuthMethod", "AppReg",
                    "-TenantId",     auth.get("tenantId", ""),
                    "-ClientId",     auth.get("clientId", ""),
                    "-ClientSecret", auth.get("clientSecret", "")]
        elif auth.get("authMethod") == "certificate":
            return ["-AuthMethod",     "Certificate",
                    "-TenantId",       auth.get("tenantId", ""),
                    "-ClientId",       auth.get("clientId", ""),
                    "-CertThumbprint", auth.get("certThumbprint", "")]
        else:
            args = ["-AuthMethod", "Interactive"]
            if auth.get("tenantId"):
                args += ["-TenantId", auth["tenantId"]]
            return args

# =================================================================
#  INVESTIGATION SCRIPTS
#  Ready-to-run PowerShell scripts returned per finding so the
#  consultant can dig deeper without leaving the tool.
# =================================================================

INVESTIGATION_SCRIPTS = {

    "ID-001": {
        "title": "Who is missing MFA?",
        "description": "Lists every enabled user without a registered MFA method and exports to CSV.",
        "script": r"""# ID-001 — Users Without MFA
# Requires: Microsoft.Graph module
# Permissions: User.Read.All, UserAuthenticationMethod.Read.All

Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome

$users = Get-MgUser -All -Filter "accountEnabled eq true" `
         -Property Id,DisplayName,UserPrincipalName | Sort-Object UserPrincipalName

$noMFA  = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Checking MFA" -Status $user.UserPrincipalName `
                   -PercentComplete ($i / $users.Count * 100)
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    $hasMFA  = ($methods | Where-Object {
        $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
    }).Count -gt 0
    if (-not $hasMFA) {
        $noMFA.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
        })
    }
}
Write-Progress -Completed -Activity "Checking MFA"

$csv = "NoMFA_Users_$(Get-Date -Format yyyyMMdd).csv"
$noMFA | Export-Csv $csv -NoTypeInformation
$noMFA | Format-Table -AutoSize
Write-Host "$($noMFA.Count) of $($users.Count) users have no MFA. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-002": {
        "title": "Global Administrator details",
        "description": "Lists every Global Admin with last sign-in date to identify stale or excessive accounts.",
        "script": r"""# ID-002 — Global Administrator Audit
# Requires: Microsoft.Graph module
# Permissions: Directory.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "Directory.Read.All", "AuditLog.Read.All" -NoWelcome

$gaRole   = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$members  = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All
$report   = [System.Collections.Generic.List[object]]::new()

foreach ($m in $members) {
    $user   = Get-MgUser -UserId $m.Id `
              -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime `
              -ErrorAction SilentlyContinue
    if (-not $user) { continue }
    $signIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($m.Id)'" -Top 1 |
               Select-Object -First 1).CreatedDateTime
    $report.Add([PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName       = $user.DisplayName
        AccountEnabled    = $user.AccountEnabled
        AccountCreated    = $user.CreatedDateTime
        LastSignIn        = $signIn ?? 'No record'
    })
}

$csv = "GlobalAdmins_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$col = if ($report.Count -gt 3) { 'Red' } else { 'Green' }
Write-Host "$($report.Count) Global Administrators found. Target: 2-3. Exported: $csv" -ForegroundColor $col
Disconnect-MgGraph"""
    },

    "ID-003": {
        "title": "Permanent privileged role assignments",
        "description": "Lists all permanent (non-PIM-eligible) admin role assignments across the tenant.",
        "script": r"""# ID-003 — Permanent Role Assignment Audit
# Requires: Microsoft.Graph module
# Permissions: RoleManagement.Read.Directory, Directory.Read.All

Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All" -NoWelcome

$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All `
               -ExpandProperty Principal,RoleDefinition

$report = $assignments | Where-Object { $_.Principal } | ForEach-Object {
    $upn = $_.Principal.AdditionalProperties['userPrincipalName'] `
        ?? $_.Principal.AdditionalProperties['displayName'] `
        ?? $_.PrincipalId
    [PSCustomObject]@{
        Principal    = $upn
        Role         = $_.RoleDefinition.DisplayName
        Assignment   = 'Permanent (not PIM-eligible)'
        CreatedDate  = $_.CreatedDateTime
    }
} | Sort-Object Role, Principal

$csv = "PermanentRoles_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) permanent assignments. Use PIM to convert high-risk roles to eligible. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-004": {
        "title": "Guest user inventory",
        "description": "Lists all guest accounts with invite date and last sign-in to identify stale access.",
        "script": r"""# ID-004 — Guest User Review
# Requires: Microsoft.Graph module
# Permissions: User.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

$guests = Get-MgUser -Filter "userType eq 'Guest'" -All `
          -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime

$report = [System.Collections.Generic.List[object]]::new()
foreach ($g in $guests) {
    $signIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($g.Id)'" -Top 1 |
               Select-Object -First 1).CreatedDateTime
    $days   = if ($signIn) { [math]::Round(((Get-Date) - [datetime]$signIn).TotalDays) } else { $null }
    $report.Add([PSCustomObject]@{
        UserPrincipalName = $g.UserPrincipalName
        DisplayName       = $g.DisplayName
        AccountEnabled    = $g.AccountEnabled
        InvitedDate       = $g.CreatedDateTime
        LastSignIn        = $signIn ?? 'Never'
        DaysSinceSignIn   = $days   ?? 'Never'
    })
}

$csv = "GuestUsers_$(Get-Date -Format yyyyMMdd).csv"
$report | Sort-Object DaysSinceSignIn -Descending | Export-Csv $csv -NoTypeInformation
$report | Sort-Object DaysSinceSignIn -Descending | Format-Table -AutoSize
$stale = ($report | Where-Object { $_.DaysSinceSignIn -is [int] -and $_.DaysSinceSignIn -gt 90 }).Count
Write-Host "$($report.Count) guests — $stale inactive 90+ days. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-005": {
        "title": "Licence allocation breakdown",
        "description": "Shows assigned vs. unassigned licence counts per SKU so unused licences can be identified and removed.",
        "script": r"""# ID-005 — Licence Usage Breakdown
# Requires: Microsoft.Graph module
# Permissions: Organization.Read.All

Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome

$skus   = Get-MgSubscribedSku -All
$report = $skus | Where-Object { $_.PrepaidUnits.Enabled -gt 0 } | ForEach-Object {
    $pct = [math]::Round($_.ConsumedUnits / $_.PrepaidUnits.Enabled * 100, 1)
    [PSCustomObject]@{
        SKU              = $_.SkuPartNumber
        Total            = $_.PrepaidUnits.Enabled
        Assigned         = $_.ConsumedUnits
        Unassigned       = $_.PrepaidUnits.Enabled - $_.ConsumedUnits
        UtilisationPct   = "$pct%"
    }
} | Sort-Object Unassigned -Descending

$csv = "LicenceUsage_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$total = ($report | Measure-Object Unassigned -Sum).Sum
Write-Host "$total total unassigned licences across $($report.Count) SKUs. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "APP-001": {
        "title": "High-privilege OAuth application inventory",
        "description": "Lists third-party apps with tenant-wide Graph permissions that could be used for persistent access.",
        "script": r"""# APP-001 — High-Privilege OAuth App Review
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome

# Permissions considered high-risk for tenant-wide app access
$highRisk = @(
    'Mail.ReadWrite.All','Files.ReadWrite.All','Directory.ReadWrite.All',
    'User.ReadWrite.All','RoleManagement.ReadWrite.Directory',
    'Mail.Read.All','Calendars.ReadWrite.All','Notes.ReadWrite.All',
    'MailboxSettings.ReadWrite','TeamSettings.ReadWrite.All'
)

# Get the Microsoft Graph service principal to resolve role names
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Build role ID → name lookup
$roleMap = @{}
$graphSP.AppRoles | ForEach-Object { $roleMap[$_.Id.ToString()] = $_.Value }

# Check all non-Microsoft service principals
$sps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
$report = [System.Collections.Generic.List[object]]::new()

foreach ($sp in $sps) {
    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                   Where-Object { $_.ResourceId -eq $graphSP.Id }
    $dangerous   = $assignments | Where-Object { $highRisk -contains $roleMap[$_.AppRoleId.ToString()] }
    if ($dangerous) {
        $report.Add([PSCustomObject]@{
            AppName     = $sp.DisplayName
            AppId       = $sp.AppId
            Publisher   = $sp.PublisherName ?? 'Unknown'
            Permissions = ($dangerous | ForEach-Object { $roleMap[$_.AppRoleId.ToString()] }) -join ', '
            Created     = $sp.CreatedDateTime
        })
    }
}

$csv = "HighPrivApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize -Wrap
Write-Host "$($report.Count) apps with high-privilege permissions. Review each in Entra ID > Enterprise Applications > Permissions. Exported: $csv" -ForegroundColor Red
Disconnect-MgGraph"""
    },

    "MON-001": {
        "title": "Defender alert policy status",
        "description": "Shows all Microsoft Defender for Office 365 alert policies and which are disabled.",
        "script": r"""# MON-001 — Defender Alert Policy Review
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$policies = Get-ProtectionAlert | Select-Object Name, IsEnabled, Severity, Category, NotifyUser
$enabled  = $policies | Where-Object { $_.IsEnabled }
$disabled = $policies | Where-Object { -not $_.IsEnabled }

Write-Host "`nEnabled  alert policies: $($enabled.Count)" -ForegroundColor Green
Write-Host "Disabled alert policies: $($disabled.Count)" -ForegroundColor $(if($disabled.Count -gt 0){'Yellow'}else{'Green'})

if ($disabled) {
    Write-Host "`nDisabled policies (consider enabling):" -ForegroundColor Yellow
    $disabled | Format-Table Name, Severity, Category -AutoSize
}

$csv = "AlertPolicies_$(Get-Date -Format yyyyMMdd).csv"
$policies | Export-Csv $csv -NoTypeInformation
Write-Host "Full policy list exported: $csv" -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-001": {
        "title": "Active forwarding rules inventory",
        "description": "Finds mailbox-level forwarding and inbox rules that redirect mail externally.",
        "script": r"""# EXO-001 — External Forwarding Rule Discovery
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$report = [System.Collections.Generic.List[object]]::new()

# 1. Mailbox-level ForwardingAddress / ForwardingSmtpAddress
Write-Host "Checking mailbox forwarding settings..." -ForegroundColor Cyan
$fwdMailboxes = Get-Mailbox -ResultSize Unlimited |
                Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }
foreach ($mbx in $fwdMailboxes) {
    $report.Add([PSCustomObject]@{
        Mailbox         = $mbx.UserPrincipalName
        ForwardTo       = $mbx.ForwardingAddress ?? $mbx.ForwardingSmtpAddress
        KeepCopy        = $mbx.DeliverToMailboxAndForward
        Type            = 'Mailbox Forwarding'
    })
}

# 2. Inbox rules with forwarding or redirect actions
Write-Host "Scanning inbox rules for forwarding actions..." -ForegroundColor Cyan
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $rules = Get-InboxRule -Mailbox $_.Identity -ErrorAction SilentlyContinue |
             Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
    foreach ($rule in $rules) {
        $dest = ($rule.ForwardTo + $rule.ForwardAsAttachmentTo + $rule.RedirectTo) -join '; '
        $report.Add([PSCustomObject]@{
            Mailbox   = $_.UserPrincipalName
            ForwardTo = $dest
            KeepCopy  = -not [bool]$rule.RedirectTo
            Type      = "Inbox Rule: $($rule.Name)"
        })
    }
}

if ($report.Count -eq 0) {
    Write-Host "No forwarding rules found." -ForegroundColor Green
} else {
    $report | Format-Table -AutoSize
    $csv = "ForwardingRules_$(Get-Date -Format yyyyMMdd).csv"
    $report | Export-Csv $csv -NoTypeInformation
    Write-Host "$($report.Count) forwarding rule(s) found. Exported: $csv" -ForegroundColor Red
}
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "MDM-001": {
        "title": "Non-compliant device list",
        "description": "Lists all Intune-managed devices that are not compliant, with last sync date and OS version.",
        "script": r"""# MDM-001 — Non-Compliant Device Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementManagedDevices.Read.All

Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

$all     = Get-MgDeviceManagementManagedDevice -All `
           -Property DeviceName,UserPrincipalName,ComplianceState,OperatingSystem,OsVersion,LastSyncDateTime,ManagementState
$nonComp = $all | Where-Object { $_.ComplianceState -ne 'compliant' }

$report = $nonComp | ForEach-Object {
    [PSCustomObject]@{
        DeviceName      = $_.DeviceName
        User            = $_.UserPrincipalName
        OS              = "$($_.OperatingSystem) $($_.OsVersion)"
        ComplianceState = $_.ComplianceState
        ManagementState = $_.ManagementState
        LastSync        = $_.LastSyncDateTime
        DaysSinceSync   = if ($_.LastSyncDateTime) {
                              [math]::Round(((Get-Date) - [datetime]$_.LastSyncDateTime).TotalDays)
                          } else { 'Never' }
    }
} | Sort-Object ComplianceState, OS

$csv = "NonCompliantDevices_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$col = if ($nonComp.Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "$($nonComp.Count) non-compliant of $($all.Count) total managed devices. Exported: $csv" -ForegroundColor $col
Disconnect-MgGraph"""
    },

    "SEC-001": {
        "title": "Secure Score breakdown",
        "description": "Shows your current Secure Score, percentage, and top improvement actions ranked by points available.",
        "script": r"""# SEC-001 — Secure Score Breakdown
# Requires: Microsoft.Graph module
# Permissions: SecurityEvents.Read.All

Connect-MgGraph -Scopes "SecurityEvents.Read.All" -NoWelcome

$latest = Get-MgSecuritySecureScore -Top 1 | Select-Object -First 1
$pct    = [math]::Round(($latest.CurrentScore / $latest.MaxScore) * 100, 1)
$col    = if ($pct -lt 50) { 'Red' } elseif ($pct -lt 75) { 'Yellow' } else { 'Green' }

Write-Host "`nCurrent Secure Score: $($latest.CurrentScore) / $($latest.MaxScore) ($pct%)" -ForegroundColor $col
Write-Host "Score Date: $($latest.CreatedDateTime)" -ForegroundColor Cyan

Write-Host "`nTop improvement actions by points available:" -ForegroundColor Cyan
$actions = Get-MgSecuritySecureScoreControlProfile -All |
           Sort-Object MaxScore -Descending |
           Select-Object -First 20

$actions | Select-Object Title, MaxScore, @{N='Category';E={$_.ControlCategory}} |
           Format-Table -AutoSize

$csv = "SecureScore_$(Get-Date -Format yyyyMMdd).csv"
$actions | Export-Csv $csv -NoTypeInformation
Write-Host "Full action list exported: $csv" -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "SEC-002": {
        "title": "Security defaults and CA policy status",
        "description": "Shows whether Security Defaults are enabled and whether Conditional Access policies are covering the same ground.",
        "script": r"""# SEC-002 — Security Defaults vs Conditional Access
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$defaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
$col      = if ($defaults.IsEnabled) { 'Green' } else { 'Red' }
Write-Host "`nSecurity Defaults: $(if($defaults.IsEnabled){'ENABLED'}else{'DISABLED'})" -ForegroundColor $col

$all     = Get-MgIdentityConditionalAccessPolicy -All
$enabled = $all | Where-Object { $_.State -eq 'enabled' }
$report  = $all | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }

Write-Host "`nConditional Access: $($all.Count) total | $($enabled.Count) enforced | $($report.Count) report-only" -ForegroundColor Cyan

if (-not $defaults.IsEnabled -and $enabled.Count -eq 0) {
    Write-Host "`nCRITICAL: Security Defaults disabled AND no CA policies enforced." -ForegroundColor Red
    Write-Host "The tenant has no baseline MFA enforcement." -ForegroundColor Red
} elseif (-not $defaults.IsEnabled) {
    Write-Host "`nRelying on $($enabled.Count) Conditional Access policy/policies." -ForegroundColor Yellow
    Write-Host "Verify CA policies cover: MFA for all users, block legacy auth, require compliant device." -ForegroundColor Yellow
} else {
    Write-Host "`nSecurity Defaults active. Note: conflicts with custom CA policies if both are enabled." -ForegroundColor Green
}

Write-Host "`nEnabled CA Policies:" -ForegroundColor Cyan
$enabled | Select-Object DisplayName, State | Format-Table -AutoSize
Disconnect-MgGraph"""
    },

    "SEC-003": {
        "title": "MFA number matching status",
        "description": "Checks whether number matching (MFA fatigue protection) is enabled in the Microsoft Authenticator policy.",
        "script": r"""# SEC-003 — MFA Fatigue Protection (Number Matching)
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$msAuth = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
          -AuthenticationMethodConfigurationId "MicrosoftAuthenticator"

Write-Host "`nMicrosoft Authenticator: $($msAuth.State)" -ForegroundColor $(if($msAuth.State -eq 'enabled'){'Green'}else{'Red'})

$props = $msAuth.AdditionalProperties
if ($props.featureSettings) {
    $nm  = $props.featureSettings.numberMatchingRequiredState
    $ctx = $props.featureSettings.displayAppInformationRequiredState
    Write-Host "Number Matching:    $(if($nm.state -eq 'enabled'){'ENABLED'}else{'DISABLED'})" `
               -ForegroundColor $(if($nm.state -eq 'enabled'){'Green'}else{'Red'})
    Write-Host "Additional Context: $(if($ctx.state -eq 'enabled'){'ENABLED'}else{'DISABLED'})" `
               -ForegroundColor $(if($ctx.state -eq 'enabled'){'Green'}else{'Red'})
} else {
    Write-Host "Could not read feature settings. Check Entra ID > Authentication Methods > Microsoft Authenticator." -ForegroundColor Yellow
}

Write-Host "`nNumber matching prevents MFA fatigue attacks (push bombing)." -ForegroundColor Cyan
Write-Host "Enable at: Entra ID > Protection > Authentication Methods > Microsoft Authenticator > Configure" -ForegroundColor White
Disconnect-MgGraph"""
    },

    "SEC-004": {
        "title": "Enabled authentication methods",
        "description": "Lists all enabled authentication methods in the tenant, flagging weak options such as SMS and voice call.",
        "script": r"""# SEC-004 — Authentication Method Inventory
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$weak   = @('Sms','Voice','Email')
$strong = @('MicrosoftAuthenticator','Fido2','WindowsHelloForBusiness','SoftwareOath','TemporaryAccessPass')

$policy = Get-MgPolicyAuthenticationMethodPolicy
Write-Host "`nAuthentication Method Status:" -ForegroundColor Cyan

foreach ($method in $policy.AuthenticationMethodConfigurations) {
    $isWeak   = $weak   -contains $method.Id
    $isStrong = $strong -contains $method.Id
    $tag      = if ($isWeak) { '  [WEAK — consider disabling]' } elseif ($isStrong) { '  [Strong]' } else { '' }
    $col      = if ($method.State -eq 'enabled' -and $isWeak) { 'Red' } `
                elseif ($method.State -eq 'enabled' -and $isStrong) { 'Green' } `
                else { 'Gray' }
    Write-Host "  $($method.Id.PadRight(32)) $($method.State)$tag" -ForegroundColor $col
}

Write-Host "`nSMS and Voice are vulnerable to SIM swapping and SS7 interception." -ForegroundColor Yellow
Write-Host "Disable weak methods once Authenticator or FIDO2 is fully deployed." -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "SEC-005": {
        "title": "User app consent configuration",
        "description": "Shows whether users can consent to OAuth applications without admin approval, and lists existing user-level grants.",
        "script": r"""# SEC-005 — User App Consent Policy
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" -NoWelcome

$authPolicy  = Get-MgPolicyAuthorizationPolicy | Select-Object -First 1
$grantPolicies = $authPolicy.PermissionGrantPolicyIdsAssignedToDefaultUserRole

Write-Host "`nUser Consent Policy:" -ForegroundColor Cyan
Write-Host "  Permission grant policies: $($grantPolicies -join ', ')" -ForegroundColor White

if ($grantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
    Write-Host "`n  WARNING: Users can consent to any OAuth app requesting any permission." -ForegroundColor Red
    Write-Host "  This enables illicit consent grant (OAuth phishing) attacks." -ForegroundColor Red
} elseif ($grantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low') {
    Write-Host "`n  Users can consent to low-risk permissions only." -ForegroundColor Yellow
    Write-Host "  Consider requiring admin approval for all third-party apps." -ForegroundColor Yellow
} elseif (-not $grantPolicies) {
    Write-Host "`n  Users cannot consent to apps — admin approval required. Good." -ForegroundColor Green
}

Write-Host "`nUser-level OAuth permission grants in tenant:" -ForegroundColor Cyan
$grants = Get-MgOauth2PermissionGrant -All | Where-Object { $_.ConsentType -eq 'Principal' }
Write-Host "  $($grants.Count) user-level OAuth grant(s) found" -ForegroundColor $(if($grants.Count -gt 0){'Yellow'}else{'Green'})

if ($grants.Count -gt 0) {
    $csv = "OAuthUserGrants_$(Get-Date -Format yyyyMMdd).csv"
    $grants | Select-Object ClientId, ConsentType, PrincipalId, Scope | Export-Csv $csv -NoTypeInformation
    Write-Host "  Exported: $csv" -ForegroundColor Cyan
    Write-Host "  Review each grant in Entra ID > Enterprise Applications > Permissions" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "CA-001": {
        "title": "Conditional Access policy inventory",
        "description": "Lists all Conditional Access policies by state — enforced, report-only, and disabled — to identify coverage gaps.",
        "script": r"""# CA-001 — Conditional Access Policy Inventory
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$all        = Get-MgIdentityConditionalAccessPolicy -All
$enabled    = $all | Where-Object { $_.State -eq 'enabled' }
$reportOnly = $all | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
$disabled   = $all | Where-Object { $_.State -eq 'disabled' }

Write-Host "`nConditional Access Policy Summary:" -ForegroundColor Cyan
Write-Host "  Total:        $($all.Count)" -ForegroundColor White
Write-Host "  Enforced:     $($enabled.Count)" -ForegroundColor $(if($enabled.Count -gt 0){'Green'}else{'Red'})
Write-Host "  Report-only:  $($reportOnly.Count)" -ForegroundColor Yellow
Write-Host "  Disabled:     $($disabled.Count)" -ForegroundColor Gray

if ($enabled.Count -eq 0) {
    Write-Host "`n  CRITICAL: No policies are enforced. Users are not protected by Conditional Access." -ForegroundColor Red
}

Write-Host "`nEnforced Policies:" -ForegroundColor Green
if ($enabled) { $enabled | Select-Object DisplayName, State, ModifiedDateTime | Format-Table -AutoSize }
else { Write-Host "  None" -ForegroundColor Red }

Write-Host "`nReport-Only Policies (not yet enforced):" -ForegroundColor Yellow
if ($reportOnly) { $reportOnly | Select-Object DisplayName | Format-Table -AutoSize }
else { Write-Host "  None" -ForegroundColor Gray }

$csv = "CAPolicies_$(Get-Date -Format yyyyMMdd).csv"
$all | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime | Export-Csv $csv -NoTypeInformation
Write-Host "Full policy list exported: $csv" -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "CA-002": {
        "title": "Legacy authentication sign-in activity",
        "description": "Checks for a CA policy blocking legacy auth and shows recent sign-ins using legacy protocols from sign-in logs.",
        "script": r"""# CA-002 — Legacy Authentication Check
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All" -NoWelcome

# Check for CA policy blocking legacy auth
$allPolicies  = Get-MgIdentityConditionalAccessPolicy -All
$legacyBlock  = $allPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and
    $_.Conditions.ClientAppTypes -contains 'other' -and
    $_.GrantControls.BuiltInControls -contains 'block'
}

if ($legacyBlock) {
    Write-Host "`nLegacy authentication is BLOCKED by CA policy:" -ForegroundColor Green
    $legacyBlock | Select-Object DisplayName, State | Format-Table -AutoSize
} else {
    Write-Host "`nWARNING: No CA policy found blocking legacy authentication." -ForegroundColor Red
    Write-Host "Legacy auth bypasses MFA — a primary vector for password spray attacks." -ForegroundColor Red
}

# Check sign-in logs for legacy protocol usage (last 7 days)
Write-Host "`nChecking sign-in logs for legacy protocol usage (last 7 days)..." -ForegroundColor Cyan
$signIns = Get-MgAuditLogSignIn `
           -Filter "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" `
           -Top 100 -ErrorAction SilentlyContinue

if ($signIns) {
    $grouped = $signIns | Group-Object ClientAppUsed | Sort-Object Count -Descending
    Write-Host "`nLegacy protocol usage breakdown:" -ForegroundColor Yellow
    $grouped | Select-Object Name, Count | Format-Table -AutoSize
    $csv = "LegacyAuthSignIns_$(Get-Date -Format yyyyMMdd).csv"
    $signIns | Select-Object UserPrincipalName, ClientAppUsed, AppDisplayName, CreatedDateTime, IpAddress |
               Export-Csv $csv -NoTypeInformation
    Write-Host "Sign-in details exported: $csv" -ForegroundColor Cyan
} else {
    Write-Host "No legacy authentication sign-ins found." -ForegroundColor Green
}
Disconnect-MgGraph"""
    },

    "EXO-002": {
        "title": "Mailbox audit configuration",
        "description": "Checks org-level audit status and lists any mailboxes with auditing explicitly disabled.",
        "script": r"""# EXO-002 — Mailbox Audit Status
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled
Write-Host "`nOrganisation-level auditing: $(if(-not $orgConfig.AuditDisabled){'ENABLED'}else{'DISABLED'})" `
           -ForegroundColor $(if(-not $orgConfig.AuditDisabled){'Green'}else{'Red'})

$disabled = Get-Mailbox -ResultSize Unlimited -Filter "AuditEnabled -eq `$false" |
            Select-Object UserPrincipalName, DisplayName, RecipientTypeDetails

if ($disabled.Count -eq 0) {
    Write-Host "All mailboxes have auditing enabled." -ForegroundColor Green
} else {
    Write-Host "`n$($disabled.Count) mailbox(es) with auditing explicitly disabled:" -ForegroundColor Red
    $disabled | Format-Table -AutoSize
    $csv = "AuditDisabledMailboxes_$(Get-Date -Format yyyyMMdd).csv"
    $disabled | Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
}

# Show audit actions on a sample mailbox
$sample = Get-Mailbox -ResultSize 1 -RecipientTypeDetails UserMailbox
if ($sample) {
    Write-Host "`nSample mailbox audit actions ($($sample.UserPrincipalName)):" -ForegroundColor Cyan
    $audit = Get-Mailbox -Identity $sample.UserPrincipalName |
             Select-Object AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin
    Write-Host "  Enabled:   $($audit.AuditEnabled)"
    Write-Host "  Owner:     $($audit.AuditOwner -join ', ')"
    Write-Host "  Delegate:  $($audit.AuditDelegate -join ', ')"
    Write-Host "  Admin:     $($audit.AuditAdmin -join ', ')"
}
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-003": {
        "title": "Anti-phishing policy review",
        "description": "Shows spoof intelligence, mailbox intelligence, and impersonation protection settings across all anti-phishing policies.",
        "script": r"""# EXO-003 — Anti-Phishing Policy Review
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$policies = Get-AntiPhishPolicy | Sort-Object IsDefault -Descending

foreach ($policy in $policies) {
    $label = if ($policy.IsDefault) { ' [Default]' } else { '' }
    Write-Host "`nPolicy: $($policy.Name)$label" -ForegroundColor Cyan
    Write-Host "  Enabled:                  $($policy.Enabled)" `
               -ForegroundColor $(if($policy.Enabled){'Green'}else{'Red'})
    Write-Host "  Spoof Intelligence:       $($policy.EnableSpoofIntelligence)" `
               -ForegroundColor $(if($policy.EnableSpoofIntelligence){'Green'}else{'Red'})
    Write-Host "  Mailbox Intelligence:     $($policy.EnableMailboxIntelligence)" `
               -ForegroundColor $(if($policy.EnableMailboxIntelligence){'Green'}else{'Red'})
    Write-Host "  Honour DMARC Policy:      $($policy.HonorDmarcPolicy)" `
               -ForegroundColor $(if($policy.HonorDmarcPolicy){'Green'}else{'Yellow'})
    Write-Host "  User Impersonation:       $($policy.EnableTargetedUserProtection)" `
               -ForegroundColor $(if($policy.EnableTargetedUserProtection){'Green'}else{'Yellow'})
    Write-Host "  Domain Impersonation:     $($policy.EnableTargetedDomainsProtection)" `
               -ForegroundColor $(if($policy.EnableTargetedDomainsProtection){'Green'}else{'Yellow'})
    Write-Host "  Phish Threshold Level:    $($policy.PhishThresholdLevel)  (1=Standard 2=Aggressive 3=More 4=Most)"
}

$csv = "AntiPhishPolicies_$(Get-Date -Format yyyyMMdd).csv"
$policies | Select-Object Name, Enabled, EnableSpoofIntelligence, HonorDmarcPolicy,
            EnableMailboxIntelligence, EnableTargetedUserProtection, PhishThresholdLevel |
            Export-Csv $csv -NoTypeInformation
Write-Host "`nFull policy export: $csv" -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "TEAMS-001": {
        "title": "Teams external access configuration",
        "description": "Shows federation settings and whether external Teams users can communicate freely or only via an allowed domain list.",
        "script": r"""# TEAMS-001 — Teams External Access Review
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

$config = Get-CsTenantFederationConfiguration

Write-Host "`nTeams External Access Settings:" -ForegroundColor Cyan
Write-Host "  AllowFederatedUsers:       $($config.AllowFederatedUsers)" `
           -ForegroundColor $(if($config.AllowFederatedUsers){'Yellow'}else{'Green'})
Write-Host "  AllowPublicUsers:          $($config.AllowPublicUsers)" `
           -ForegroundColor $(if($config.AllowPublicUsers){'Yellow'}else{'Green'})
Write-Host "  AllowTeamsConsumer:        $($config.AllowTeamsConsumer)" `
           -ForegroundColor $(if($config.AllowTeamsConsumer){'Red'}else{'Green'})

if ($config.AllowFederatedUsers) {
    $allowed = Get-CsAllowedDomain
    $blocked = Get-CsBlockedDomain
    if ($allowed.Count -gt 0) {
        Write-Host "`n  Allowed domains list (restricted federation — good):" -ForegroundColor Green
        $allowed | Select-Object Domain | Format-Table -AutoSize
    } else {
        Write-Host "`n  Open federation — any external Teams tenant can contact your users." -ForegroundColor Red
        Write-Host "  Recommendation: Restrict to an allowed domain list of approved partners." -ForegroundColor Yellow
    }
    if ($blocked.Count -gt 0) {
        Write-Host "  Explicitly blocked domains: $($blocked.Count)" -ForegroundColor Yellow
    }
}

$csv = "TeamsFederation_$(Get-Date -Format yyyyMMdd).csv"
[PSCustomObject]@{
    AllowFederatedUsers = $config.AllowFederatedUsers
    AllowPublicUsers    = $config.AllowPublicUsers
    AllowTeamsConsumer  = $config.AllowTeamsConsumer
    AllowedDomains      = (Get-CsAllowedDomain).Count
    BlockedDomains      = (Get-CsBlockedDomain).Count
} | Export-Csv $csv -NoTypeInformation
Write-Host "`nConfiguration exported: $csv" -ForegroundColor Cyan
Disconnect-MicrosoftTeams"""
    },

    "TEAMS-002": {
        "title": "Teams consumer access status",
        "description": "Checks whether personal Microsoft accounts (Teams personal/Skype) can communicate with your tenant users.",
        "script": r"""# TEAMS-002 — Teams Consumer (Personal Account) Access
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

$config = Get-CsTenantFederationConfiguration

Write-Host "`nTeams Consumer Access Settings:" -ForegroundColor Cyan
Write-Host "  AllowTeamsConsumer:        $($config.AllowTeamsConsumer)" `
           -ForegroundColor $(if($config.AllowTeamsConsumer){'Red'}else{'Green'})
Write-Host "  AllowTeamsConsumerInbound: $($config.AllowTeamsConsumerInbound)" `
           -ForegroundColor $(if($config.AllowTeamsConsumerInbound){'Red'}else{'Green'})

if ($config.AllowTeamsConsumer -or $config.AllowTeamsConsumerInbound) {
    Write-Host "`n  WARNING: Personal Microsoft accounts can communicate with your users." -ForegroundColor Red
    Write-Host "  Files and chats can be shared with unmanaged, unaudited accounts." -ForegroundColor Red
    Write-Host "`n  To disable:" -ForegroundColor Yellow
    Write-Host "  Set-CsTenantFederationConfiguration -AllowTeamsConsumer `$false -AllowTeamsConsumerInbound `$false" -ForegroundColor White
} else {
    Write-Host "`n  Teams consumer access is blocked. Good." -ForegroundColor Green
}

$meetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global
Write-Host "`n  Anonymous meeting join: $($meetingPolicy.AllowAnonymousUsersToJoinMeeting)" `
           -ForegroundColor $(if($meetingPolicy.AllowAnonymousUsersToJoinMeeting){'Yellow'}else{'Green'})
Disconnect-MicrosoftTeams"""
    },

    "SPO-001": {
        "title": "SharePoint sharing level and anonymous links",
        "description": "Checks the tenant-level sharing setting and identifies sites with Anyone (anonymous) link sharing enabled.",
        "script": r"""# SPO-001 — SharePoint Sharing Level Audit
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant
$level  = $tenant.SharingCapability

$levelDesc = switch ($level) {
    'Disabled'                       { 'Sharing disabled — most restrictive' }
    'ExistingExternalUserSharingOnly'{ 'Existing external users only' }
    'ExternalUserSharingOnly'        { 'New and existing guests (sign-in required)' }
    'ExternalUserAndGuestSharing'    { 'Anyone — anonymous links ALLOWED' }
    default                          { $level }
}
$col = if ($level -eq 'ExternalUserAndGuestSharing') { 'Red' } `
       elseif ($level -eq 'ExternalUserSharingOnly') { 'Yellow' } else { 'Green' }

Write-Host "`nTenant Sharing Level: $level" -ForegroundColor $col
Write-Host "  $levelDesc" -ForegroundColor $col
Write-Host "  Anyone link expiry: $($tenant.RequireAnonymousLinksExpireInDays) days (0 = no expiry)" `
           -ForegroundColor $(if($tenant.RequireAnonymousLinksExpireInDays -eq 0 -and $level -eq 'ExternalUserAndGuestSharing'){'Red'}else{'Green'})
Write-Host "  Default link type: $($tenant.DefaultSharingLinkType)" -ForegroundColor Cyan

Write-Host "`nChecking sites with Anyone link sharing enabled..." -ForegroundColor Cyan
$sites = Get-SPOSite -Limit All -IncludePersonalSite $false |
         Where-Object { $_.SharingCapability -eq 'ExternalUserAndGuestSharing' }

if ($sites.Count -gt 0) {
    Write-Host "$($sites.Count) site(s) allow anonymous links:" -ForegroundColor Red
    $sites | Select-Object Url, SharingCapability | Format-Table -AutoSize
    $csv = "SPOAnonymousSites_$(Get-Date -Format yyyyMMdd).csv"
    $sites | Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
} else {
    Write-Host "No sites with anonymous link sharing found." -ForegroundColor Green
}
Disconnect-SPOService"""
    },

    "SPO-002": {
        "title": "SharePoint legacy authentication status",
        "description": "Shows whether legacy authentication protocols are enabled in SharePoint, allowing connections that bypass MFA.",
        "script": r"""# SPO-002 — SharePoint Legacy Authentication
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant

Write-Host "`nSharePoint Legacy Authentication:" -ForegroundColor Cyan
Write-Host "  LegacyAuthProtocolsEnabled: $($tenant.LegacyAuthProtocolsEnabled)" `
           -ForegroundColor $(if($tenant.LegacyAuthProtocolsEnabled){'Red'}else{'Green'})
Write-Host "  BrowserSSOEnabled:          $($tenant.BrowserSSOEnabled)" `
           -ForegroundColor $(if($tenant.BrowserSSOEnabled){'Green'}else{'Yellow'})
Write-Host "  ConditionalAccessPolicy:    $($tenant.ConditionalAccessPolicy)" -ForegroundColor Cyan

if ($tenant.LegacyAuthProtocolsEnabled) {
    Write-Host "`n  WARNING: Legacy authentication is enabled." -ForegroundColor Red
    Write-Host "  Basic auth connections can bypass MFA and Conditional Access." -ForegroundColor Red
    Write-Host "`n  To disable:" -ForegroundColor Yellow
    Write-Host "  Set-SPOTenant -LegacyAuthProtocolsEnabled `$false" -ForegroundColor White
} else {
    Write-Host "`n  Legacy authentication is disabled. Good." -ForegroundColor Green
}

Write-Host "`nAdditional settings:" -ForegroundColor Cyan
Write-Host "  EmailAttestationRequired:              $($tenant.EmailAttestationRequired)"
Write-Host "  AllowDownloadingNonWebViewableFiles:   $($tenant.AllowDownloadingNonWebViewableFiles)"
Disconnect-SPOService"""
    },

    "MDM-002": {
        "title": "Intune compliance policy inventory",
        "description": "Lists all Intune compliance policies, shows platform coverage, and identifies any policies with no assignments.",
        "script": r"""# MDM-002 — Intune Compliance Policy Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

$policies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction SilentlyContinue

if (-not $policies -or $policies.Count -eq 0) {
    Write-Host "`nCRITICAL: No Intune compliance policies found." -ForegroundColor Red
    Write-Host "Without compliance policies, device health cannot be enforced and" -ForegroundColor Red
    Write-Host "Conditional Access cannot block non-compliant devices from accessing resources." -ForegroundColor Red
    Write-Host "`nCreate compliance policies at: https://intune.microsoft.com > Devices > Compliance" -ForegroundColor Yellow
} else {
    Write-Host "`nIntune Compliance Policies: $($policies.Count) found" -ForegroundColor Green

    Write-Host "`nPlatform coverage:" -ForegroundColor Cyan
    $policies | Group-Object {
        $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.','' -replace 'CompliancePolicy',''
    } | Select-Object Name, Count | Format-Table -AutoSize

    # Check for unassigned policies
    Write-Host "Checking assignments..." -ForegroundColor Cyan
    $unassigned = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment `
                       -DeviceCompliancePolicyId $p.Id -ErrorAction SilentlyContinue
        if (-not $assignments) { $unassigned.Add($p) }
    }

    if ($unassigned.Count -gt 0) {
        Write-Host "`n$($unassigned.Count) policy/policies exist but are NOT assigned to any users or devices:" -ForegroundColor Yellow
        $unassigned | Select-Object DisplayName | Format-Table -AutoSize
    } else {
        Write-Host "All compliance policies are assigned." -ForegroundColor Green
    }

    $csv = "CompliancePolicies_$(Get-Date -Format yyyyMMdd).csv"
    $policies | Select-Object DisplayName, CreatedDateTime, LastModifiedDateTime | Export-Csv $csv -NoTypeInformation
    Write-Host "`nFull list exported: $csv" -ForegroundColor Cyan
}
Disconnect-MgGraph"""
    },

    "ID-006": {
        "title": "Risky user details",
        "description": "Lists all high and medium risk users from Entra ID Identity Protection with their risk level, state, and last update.",
        "script": r"""# ID-006 — Risky User Review
# Requires: Microsoft.Graph module
# Permissions: IdentityRiskyUser.Read.All

Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All" -NoWelcome

$riskyUsers = Get-MgRiskyUser -All -Filter "riskState ne 'remediated' and riskState ne 'dismissed'" |
              Where-Object { $_.RiskLevel -in @('high','medium') } |
              Sort-Object RiskLevel, RiskLastUpdatedDateTime -Descending

if ($riskyUsers.Count -eq 0) {
    Write-Host "`nNo high or medium risk users found. Good." -ForegroundColor Green
} else {
    Write-Host "`n$($riskyUsers.Count) risky user(s) requiring attention:" -ForegroundColor Red
    $riskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime |
                  Format-Table -AutoSize

    $csv = "RiskyUsers_$(Get-Date -Format yyyyMMdd).csv"
    $riskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime |
                  Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
    Write-Host "`nRecommended actions:" -ForegroundColor Yellow
    Write-Host "  - High risk: block sign-in and require password reset immediately" -ForegroundColor White
    Write-Host "  - Medium risk: require MFA re-registration and password change" -ForegroundColor White
    Write-Host "  - Dismiss false positives in Entra ID > Protection > Risky users" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "ID-007": {
        "title": "Emergency access account detection",
        "description": "Attempts to identify break-glass accounts by looking for Global Admins excluded from all enabled Conditional Access policies.",
        "script": r"""# ID-007 — Emergency Access Account Detection
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" -NoWelcome

# Get all Global Admins
$gaRole   = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$gaMembers = @{}
if ($gaRole) {
    Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All | ForEach-Object {
        $gaMembers[$_.Id] = $_.AdditionalProperties['userPrincipalName'] ?? $_.Id
    }
}

# Get all enabled CA policies and their excluded users
$policies       = Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq 'enabled' }
$exclusionCount = @{}
foreach ($p in $policies) {
    foreach ($uid in $p.Conditions.Users.ExcludeUsers) {
        $exclusionCount[$uid] = ($exclusionCount[$uid] ?? 0) + 1
    }
}

# Find Global Admins excluded from ALL enabled CA policies
$totalPolicies   = $policies.Count
$breakGlassFound = [System.Collections.Generic.List[object]]::new()

foreach ($uid in $gaMembers.Keys) {
    $exCount = $exclusionCount[$uid] ?? 0
    if ($totalPolicies -gt 0 -and $exCount -eq $totalPolicies) {
        $breakGlassFound.Add([PSCustomObject]@{
            UserPrincipalName = $gaMembers[$uid]
            UserId            = $uid
            ExcludedFromPolicies = $exCount
            TotalPolicies        = $totalPolicies
            Assessment = 'Likely break-glass account'
        })
    }
}

Write-Host "`nGlobal Administrators: $($gaMembers.Count)" -ForegroundColor Cyan
Write-Host "Enabled CA Policies:   $totalPolicies" -ForegroundColor Cyan

if ($breakGlassFound.Count -gt 0) {
    Write-Host "`nPotential emergency access account(s) detected:" -ForegroundColor Green
    $breakGlassFound | Format-Table -AutoSize
    Write-Host "Verify these accounts have credentials stored securely offline." -ForegroundColor Yellow
} else {
    Write-Host "`nNo account found that is excluded from ALL CA policies." -ForegroundColor Red
    Write-Host "Consider creating a dedicated emergency access account excluded from all CA policies." -ForegroundColor Yellow
    Write-Host "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "SEC-006": {
        "title": "Microsoft Sentinel connection status",
        "description": "Checks for Sentinel alert activity via the Microsoft Security Graph API as a proxy for whether Sentinel is connected.",
        "script": r"""# SEC-006 — Microsoft Sentinel Connection Check
# Requires: Microsoft.Graph module
# Permissions: SecurityEvents.Read.All

Connect-MgGraph -Scopes "SecurityEvents.Read.All" -NoWelcome

Write-Host "`nChecking for Microsoft Sentinel alert activity..." -ForegroundColor Cyan

try {
    # Check for Sentinel alerts via Security API
    $sentinelAlerts = Get-MgSecurityAlert -All -ErrorAction Stop |
                      Where-Object { $_.VendorInformation.Provider -match 'Sentinel|Azure Sentinel' }

    if ($sentinelAlerts.Count -gt 0) {
        Write-Host "Microsoft Sentinel alerts found: $($sentinelAlerts.Count)" -ForegroundColor Green
        Write-Host "Sentinel appears to be connected and generating alerts.`n" -ForegroundColor Green
        $sentinelAlerts | Select-Object Title, Severity, Status, CreatedDateTime |
                          Sort-Object CreatedDateTime -Descending |
                          Select-Object -First 10 |
                          Format-Table -AutoSize
    } else {
        Write-Host "No Sentinel alerts found via Security Graph API." -ForegroundColor Yellow
        Write-Host "This may indicate Sentinel is not connected, or no alerts have been generated." -ForegroundColor Yellow
        Write-Host "`nTo verify directly, check:" -ForegroundColor Cyan
        Write-Host "  Azure Portal > Microsoft Sentinel > Overview" -ForegroundColor White
        Write-Host "  https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/MainMenuBlade" -ForegroundColor White
    }

    # Also check all security alert providers for context
    $allProviders = Get-MgSecurityAlert -All -ErrorAction SilentlyContinue |
                    Group-Object { $_.VendorInformation.Provider } |
                    Sort-Object Count -Descending
    if ($allProviders) {
        Write-Host "`nSecurity alert providers currently active:" -ForegroundColor Cyan
        $allProviders | Select-Object Name, Count | Format-Table -AutoSize
    }
} catch {
    Write-Host "Could not query Security alerts: $_" -ForegroundColor Red
    Write-Host "Check permissions: SecurityEvents.Read.All is required." -ForegroundColor Yellow
}
Disconnect-MgGraph"""
    },

    "EXO-004": {
        "title": "DMARC DNS record check",
        "description": "Performs a DNS lookup for the DMARC TXT record on your primary domain and shows the current policy.",
        "script": r"""# EXO-004 — DMARC Configuration Check
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

# Get primary accepted domain
$primaryDomain = (Get-AcceptedDomain | Where-Object { $_.Default -eq $true }).DomainName
Write-Host "`nPrimary domain: $primaryDomain" -ForegroundColor Cyan

# Check DMARC
Write-Host "`nDMARC Record:" -ForegroundColor Cyan
try {
    $dmarc = Resolve-DnsName -Name "_dmarc.$primaryDomain" -Type TXT -ErrorAction Stop
    $dmarcRecord = ($dmarc | Where-Object { $_.Strings -match 'v=DMARC1' }).Strings -join ''
    if ($dmarcRecord) {
        Write-Host "  FOUND: $dmarcRecord" -ForegroundColor Green
        if ($dmarcRecord -match 'p=none')      { Write-Host "  Policy: none (monitoring only — not enforced)" -ForegroundColor Yellow }
        elseif ($dmarcRecord -match 'p=quarantine') { Write-Host "  Policy: quarantine (failing emails go to spam)" -ForegroundColor Yellow }
        elseif ($dmarcRecord -match 'p=reject') { Write-Host "  Policy: reject (failing emails blocked — strongest)" -ForegroundColor Green }
    } else {
        Write-Host "  TXT record found but no DMARC record present." -ForegroundColor Red
    }
} catch {
    Write-Host "  NOT FOUND — no DMARC record at _dmarc.$primaryDomain" -ForegroundColor Red
    Write-Host "  Attackers can spoof @$primaryDomain in phishing emails." -ForegroundColor Red
}

# Check SPF while we're here
Write-Host "`nSPF Record:" -ForegroundColor Cyan
try {
    $spf = Resolve-DnsName -Name $primaryDomain -Type TXT -ErrorAction Stop
    $spfRecord = ($spf | Where-Object { $_.Strings -match 'v=spf1' }).Strings -join ''
    if ($spfRecord) {
        Write-Host "  FOUND: $spfRecord" -ForegroundColor Green
    } else {
        Write-Host "  NOT FOUND — no SPF record on $primaryDomain" -ForegroundColor Red
    }
} catch {
    Write-Host "  Could not resolve DNS for $primaryDomain" -ForegroundColor Red
}

# DKIM
Write-Host "`nDKIM Signing Status:" -ForegroundColor Cyan
$dkim = Get-DkimSigningConfig -ErrorAction SilentlyContinue
$dkim | Select-Object Domain, Enabled, Status | Format-Table -AutoSize

Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-005": {
        "title": "SPF and DKIM configuration",
        "description": "Checks SPF DNS record on the primary domain and DKIM signing configuration in Exchange Online.",
        "script": r"""# EXO-005 — SPF and DKIM Configuration Check
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$primaryDomain = (Get-AcceptedDomain | Where-Object { $_.Default -eq $true }).DomainName
Write-Host "`nPrimary domain: $primaryDomain" -ForegroundColor Cyan

# SPF check
Write-Host "`nSPF Record:" -ForegroundColor Cyan
try {
    $spf = Resolve-DnsName -Name $primaryDomain -Type TXT -ErrorAction Stop
    $spfRecord = ($spf | Where-Object { $_.Strings -match 'v=spf1' }).Strings -join ''
    if ($spfRecord) {
        Write-Host "  FOUND: $spfRecord" -ForegroundColor Green
        if ($spfRecord -match '~all') { Write-Host "  Qualifier: ~all (SoftFail — not rejected, marked as suspicious)" -ForegroundColor Yellow }
        elseif ($spfRecord -match '-all') { Write-Host "  Qualifier: -all (HardFail — failing mail rejected)" -ForegroundColor Green }
        elseif ($spfRecord -match '\+all') { Write-Host "  WARNING: +all allows any server to send as your domain" -ForegroundColor Red }
    } else {
        Write-Host "  NOT FOUND — no SPF record on $primaryDomain" -ForegroundColor Red
        Write-Host "  Outbound email may be rejected by recipient servers." -ForegroundColor Red
    }
} catch {
    Write-Host "  Could not resolve DNS for $primaryDomain" -ForegroundColor Red
}

# DKIM check
Write-Host "`nDKIM Signing Configuration:" -ForegroundColor Cyan
$dkimConfigs = Get-DkimSigningConfig -ErrorAction SilentlyContinue

if (-not $dkimConfigs) {
    Write-Host "  No DKIM signing configurations found." -ForegroundColor Red
} else {
    foreach ($d in $dkimConfigs) {
        $col = if ($d.Enabled) { 'Green' } else { 'Red' }
        Write-Host "  $($d.Domain.PadRight(50)) Enabled: $($d.Enabled)  Status: $($d.Status)" -ForegroundColor $col
    }
    $disabled = $dkimConfigs | Where-Object { -not $_.Enabled }
    if ($disabled) {
        Write-Host "`n  To enable DKIM for a domain:" -ForegroundColor Yellow
        Write-Host "  Set-DkimSigningConfig -Identity domain.com -Enabled `$true" -ForegroundColor White
        Write-Host "  Or: New-DkimSigningConfig -DomainName domain.com -Enabled `$true" -ForegroundColor White
    }
}

# All accepted domains summary
Write-Host "`nAll accepted domains:" -ForegroundColor Cyan
Get-AcceptedDomain | Select-Object DomainName, Default, DomainType | Format-Table -AutoSize

Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-006": {
        "title": "Zero-Hour Auto Purge (ZAP) status",
        "description": "Checks ZAP configuration across the default malware filter and anti-spam policies — malware ZAP, phishing ZAP and spam ZAP.",
        "script": r"""# EXO-006 — Zero-Hour Auto Purge (ZAP) Configuration Check
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

Write-Host "`n=== Zero-Hour Auto Purge (ZAP) Status ===" -ForegroundColor Cyan
Write-Host "ZAP retroactively removes emails already delivered to mailboxes when they are later"
Write-Host "identified as malware, phishing or spam. Disabled ZAP means malicious email stays in inboxes.`n"

# Malware ZAP
Write-Host "── Malware ZAP (Anti-Malware Policy) ─────────────────────" -ForegroundColor Cyan
try {
    $malwarePolicies = Get-MalwareFilterPolicy
    foreach ($p in $malwarePolicies) {
        $col = if ($p.ZapEnabled) { 'Green' } else { 'Red' }
        $status = if ($p.ZapEnabled) { "ENABLED" } else { "DISABLED ← FIX REQUIRED" }
        $default = if ($p.IsDefault) { " [Default]" } else { "" }
        Write-Host "  Policy: $($p.Name)$default" -ForegroundColor White
        Write-Host "  ZAP: $status`n" -ForegroundColor $col
    }
} catch {
    Write-Host "  Could not retrieve malware filter policies: $_" -ForegroundColor Red
}

# Phishing and Spam ZAP
Write-Host "── Phishing and Spam ZAP (Anti-Spam Policy) ───────────────" -ForegroundColor Cyan
try {
    $spamPolicies = Get-HostedContentFilterPolicy
    foreach ($p in $spamPolicies) {
        $default = if ($p.IsDefault) { " [Default]" } else { "" }
        Write-Host "  Policy: $($p.Name)$default" -ForegroundColor White

        # PhishZapEnabled (newer module versions)
        if ($p.PSObject.Properties['PhishZapEnabled']) {
            $col = if ($p.PhishZapEnabled) { 'Green' } else { 'Red' }
            $status = if ($p.PhishZapEnabled) { "ENABLED" } else { "DISABLED ← FIX REQUIRED" }
            Write-Host "  Phishing ZAP : $status" -ForegroundColor $col
        } else {
            # Older module — ZapEnabled covers both
            $col = if ($p.ZapEnabled) { 'Green' } else { 'Red' }
            $status = if ($p.ZapEnabled) { "ENABLED" } else { "DISABLED ← FIX REQUIRED" }
            Write-Host "  Phishing ZAP : $status (via legacy ZapEnabled flag)" -ForegroundColor $col
        }

        # SpamZapEnabled (newer module versions)
        if ($p.PSObject.Properties['SpamZapEnabled']) {
            $col = if ($p.SpamZapEnabled) { 'Green' } else { 'Red' }
            $status = if ($p.SpamZapEnabled) { "ENABLED" } else { "DISABLED ← FIX REQUIRED" }
            Write-Host "  Spam ZAP     : $status" -ForegroundColor $col
        } else {
            $col = if ($p.ZapEnabled) { 'Green' } else { 'Red' }
            $status = if ($p.ZapEnabled) { "ENABLED" } else { "DISABLED ← FIX REQUIRED" }
            Write-Host "  Spam ZAP     : $status (via legacy ZapEnabled flag)" -ForegroundColor $col
        }
        Write-Host ""
    }
} catch {
    Write-Host "  Could not retrieve anti-spam policies: $_" -ForegroundColor Red
}

Write-Host "── How to fix ─────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "  Portal: https://security.microsoft.com/antimalwarev2"
Write-Host "  Email & Collaboration > Policies & Rules > Threat policies"
Write-Host "  - Anti-malware default policy: Edit protection settings > Enable ZAP"
Write-Host "  - Anti-spam inbound default: Edit actions > Enable ZAP for phishing + spam`n"

Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "MDM-003": {
        "title": "Windows Update ring inventory",
        "description": "Lists all Windows Update for Business rings configured in Intune with their deferral periods.",
        "script": r"""# MDM-003 — Windows Update Ring Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

$allConfigs   = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue
$updateRings  = $allConfigs | Where-Object {
    $_.AdditionalProperties['@odata.type'] -like '*windowsUpdateForBusiness*'
}

if (-not $updateRings -or $updateRings.Count -eq 0) {
    Write-Host "`nNo Windows Update rings found in Intune." -ForegroundColor Red
    Write-Host "Without update rings, Windows devices may not receive patches consistently." -ForegroundColor Red
    Write-Host "`nCreate update rings at: Intune > Devices > Windows > Update rings for Windows 10 and later" -ForegroundColor Yellow
} else {
    Write-Host "`nWindows Update Rings: $($updateRings.Count) found" -ForegroundColor Green

    foreach ($ring in $updateRings) {
        $props = $ring.AdditionalProperties
        Write-Host "`nRing: $($ring.DisplayName)" -ForegroundColor Cyan
        Write-Host "  Quality update deferral:  $($props['qualityUpdatesDeferralPeriodInDays'] ?? 'Not set') days"
        Write-Host "  Feature update deferral:  $($props['featureUpdatesDeferralPeriodInDays'] ?? 'Not set') days"
        Write-Host "  Automatic update behavior: $($props['automaticUpdateMode'] ?? 'Not set')"
        Write-Host "  Created: $($ring.CreatedDateTime)"
    }

    # Check assignments
    Write-Host "`nChecking ring assignments..." -ForegroundColor Cyan
    $unassigned = [System.Collections.Generic.List[object]]::new()
    foreach ($ring in $updateRings) {
        $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment `
                       -DeviceConfigurationId $ring.Id -ErrorAction SilentlyContinue
        if (-not $assignments) { $unassigned.Add($ring) }
    }
    if ($unassigned.Count -gt 0) {
        Write-Host "$($unassigned.Count) ring(s) are not assigned to any users or devices:" -ForegroundColor Yellow
        $unassigned | Select-Object DisplayName | Format-Table -AutoSize
    } else {
        Write-Host "All rings are assigned." -ForegroundColor Green
    }
}
Disconnect-MgGraph"""
    },

    "MDM-004": {
        "title": "BitLocker enforcement check",
        "description": "Looks for BitLocker requirements in Intune compliance policies and device configuration profiles.",
        "script": r"""# MDM-004 — BitLocker Enforcement Check
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

Write-Host "`nChecking Intune compliance policies for BitLocker requirement..." -ForegroundColor Cyan
$compPolicies    = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction SilentlyContinue
$bitlockerCompPolicies = $compPolicies | Where-Object {
    $_.AdditionalProperties['storageRequireDeviceEncryption'] -eq $true -or
    $_.AdditionalProperties['bitLockerEnabled'] -eq $true
}

if ($bitlockerCompPolicies) {
    Write-Host "  BitLocker required in compliance policy/policies:" -ForegroundColor Green
    $bitlockerCompPolicies | Select-Object DisplayName | Format-Table -AutoSize
} else {
    Write-Host "  No compliance policy found requiring BitLocker/device encryption." -ForegroundColor Red
}

Write-Host "`nChecking device configuration profiles for BitLocker settings..." -ForegroundColor Cyan
$configProfiles    = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue
$bitlockerConfigs  = $configProfiles | Where-Object {
    $_.AdditionalProperties['@odata.type'] -like '*bitLocker*' -or
    $_.AdditionalProperties['bitLockerFixedDrivePolicy'] -or
    $_.AdditionalProperties['bitLockerSystemDrivePolicy'] -or
    $_.DisplayName -match 'bitlocker|encryption|encrypt'
}

if ($bitlockerConfigs) {
    Write-Host "  BitLocker configuration profile(s) found:" -ForegroundColor Green
    $bitlockerConfigs | Select-Object DisplayName, @{N='Type';E={$_.AdditionalProperties['@odata.type']}} |
                        Format-Table -AutoSize
} else {
    Write-Host "  No BitLocker configuration profiles found." -ForegroundColor Red
}

if (-not $bitlockerCompPolicies -and -not $bitlockerConfigs) {
    Write-Host "`nCRITICAL: BitLocker is not enforced via any Intune policy." -ForegroundColor Red
    Write-Host "Devices that are lost or stolen will have unencrypted data." -ForegroundColor Red
    Write-Host "`nTo fix:" -ForegroundColor Yellow
    Write-Host "  1. Intune > Devices > Compliance policies > Create > Windows 10+ > Require BitLocker" -ForegroundColor White
    Write-Host "  2. Intune > Devices > Configuration > Create > Windows > BitLocker (Endpoint Protection)" -ForegroundColor White
}

Disconnect-MgGraph"""
    },

    "ENTRA-001": {
        "title": "What are the high-privilege app registrations?",
        "description": "Lists all app registrations with Critical or High risk Graph application permissions.",
        "script": r"""# ENTRA-001 — High-Privilege App Registrations
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All" -NoWelcome

$HighPriv = @(
    'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','User.ReadWrite.All',
    'Group.ReadWrite.All','Application.ReadWrite.All','Mail.ReadWrite','Mail.Send',
    'Files.ReadWrite.All','Sites.FullControl.All','Sites.ReadWrite.All',
    'UserAuthenticationMethod.ReadWrite.All','Policy.ReadWrite.ConditionalAccess',
    'Domain.ReadWrite.All','Mail.Read','Mail.ReadBasic.All','Files.Read.All',
    'Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All',
    'IdentityRiskyUser.Read.All','SecurityEvents.ReadWrite.All','Organization.ReadWrite.All'
)

$GraphSP   = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$RoleMap   = @{}; $GraphSP.AppRoles | ForEach-Object { $RoleMap[$_.Id] = $_.Value }
$Grants    = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $GraphSP.Id -All
$AllApps   = Get-MgApplication -All -Property AppId,DisplayName
$AppMap    = @{}; $AllApps | ForEach-Object { $AppMap[$_.AppId] = $_.DisplayName }
$SPMap     = @{}; Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" -All |
             ForEach-Object { $SPMap[$_.Id] = $_.AppId }

$report = [System.Collections.Generic.List[object]]::new()
foreach ($g in $Grants) {
    $perm = $RoleMap[$g.AppRoleId]
    if ($perm -and $HighPriv -contains $perm) {
        $appId = $SPMap[$g.PrincipalId]
        $name  = if ($appId) { $AppMap[$appId] } else { $g.PrincipalDisplayName }
        $risk  = if ($perm -in @('Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory',
                     'User.ReadWrite.All','Application.ReadWrite.All','Mail.ReadWrite',
                     'Mail.Send','Files.ReadWrite.All','Group.ReadWrite.All')) { 'Critical' } else { 'High' }
        $report.Add([PSCustomObject]@{ AppName=$name; Permission=$perm; Risk=$risk; SPObjectId=$g.PrincipalId })
    }
}

$csv = "HighPrivApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object Risk,AppName | Format-Table -AutoSize
Write-Host "$($report.Count) high-privilege permission grant(s) found. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Red'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-002": {
        "title": "Which app registrations have expired credentials?",
        "description": "Lists all app registrations with client secrets or certificates that have already expired.",
        "script": r"""# ENTRA-002 — Expired App Registration Credentials
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Now    = Get-Date
$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    foreach ($Cred in @($App.PasswordCredentials) + @($App.KeyCredentials)) {
        if ($null -eq $Cred) { continue }
        if ($Cred.EndDateTime -and $Cred.EndDateTime -lt $Now) {
            $report.Add([PSCustomObject]@{
                AppName    = $App.DisplayName
                CredType   = if ($Cred.PSObject.TypeNames[0] -match 'Password') {'Secret'} else {'Certificate'}
                CredHint   = $Cred.DisplayName ?? $Cred.CustomKeyIdentifier
                ExpiredOn  = $Cred.EndDateTime.ToString("yyyy-MM-dd")
                DaysExpired= [int]($Now - $Cred.EndDateTime).TotalDays
            })
        }
    }
}

$csv = "ExpiredCredentials_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object DaysExpired -Descending | Format-Table -AutoSize
Write-Host "$($report.Count) expired credential(s) found across app registrations. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Red'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-003": {
        "title": "Which app registrations have credentials expiring within 30 days?",
        "description": "Lists app registrations with credentials expiring within 30 days.",
        "script": r"""# ENTRA-003 — Credentials Expiring Within 30 Days
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Now    = Get-Date
$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    foreach ($Cred in @($App.PasswordCredentials) + @($App.KeyCredentials)) {
        if ($null -eq $Cred -or $null -eq $Cred.EndDateTime) { continue }
        $daysLeft = [int]($Cred.EndDateTime - $Now).TotalDays
        if ($daysLeft -ge 0 -and $daysLeft -le 30) {
            $report.Add([PSCustomObject]@{
                AppName   = $App.DisplayName
                CredType  = if ($Cred.PSObject.TypeNames[0] -match 'Password') {'Secret'} else {'Certificate'}
                CredHint  = $Cred.DisplayName ?? $Cred.CustomKeyIdentifier
                ExpiresOn = $Cred.EndDateTime.ToString("yyyy-MM-dd")
                DaysLeft  = $daysLeft
            })
        }
    }
}

$csv = "ExpiringCredentials30d_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object DaysLeft | Format-Table -AutoSize
Write-Host "$($report.Count) credential(s) expiring within 30 days. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-004": {
        "title": "Which app registrations have credentials expiring within 90 days?",
        "description": "Lists app registrations with credentials expiring within 31–90 days.",
        "script": r"""# ENTRA-004 — Credentials Expiring Within 90 Days
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Now    = Get-Date
$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    foreach ($Cred in @($App.PasswordCredentials) + @($App.KeyCredentials)) {
        if ($null -eq $Cred -or $null -eq $Cred.EndDateTime) { continue }
        $daysLeft = [int]($Cred.EndDateTime - $Now).TotalDays
        if ($daysLeft -gt 30 -and $daysLeft -le 90) {
            $report.Add([PSCustomObject]@{
                AppName   = $App.DisplayName
                CredType  = if ($Cred.PSObject.TypeNames[0] -match 'Password') {'Secret'} else {'Certificate'}
                CredHint  = $Cred.DisplayName ?? $Cred.CustomKeyIdentifier
                ExpiresOn = $Cred.EndDateTime.ToString("yyyy-MM-dd")
                DaysLeft  = $daysLeft
            })
        }
    }
}

$csv = "ExpiringCredentials90d_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object DaysLeft | Format-Table -AutoSize
Write-Host "$($report.Count) credential(s) expiring within 31–90 days. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-005": {
        "title": "Which app registrations have credentials set to never expire?",
        "description": "Lists app registrations with credentials that have no expiry date configured.",
        "script": r"""# ENTRA-005 — Never-Expiring Credentials
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    foreach ($Cred in @($App.PasswordCredentials) + @($App.KeyCredentials)) {
        if ($null -eq $Cred) { continue }
        if ($null -eq $Cred.EndDateTime) {
            $report.Add([PSCustomObject]@{
                AppName  = $App.DisplayName
                CredType = if ($Cred.PSObject.TypeNames[0] -match 'Password') {'Secret'} else {'Certificate'}
                CredHint = $Cred.DisplayName ?? $Cred.CustomKeyIdentifier
                Created  = $Cred.StartDateTime?.ToString("yyyy-MM-dd") ?? 'Unknown'
            })
        }
    }
}

$csv = "NeverExpiringCredentials_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) never-expiring credential(s) found. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-006": {
        "title": "Which app registrations have no owner?",
        "description": "Lists all app registrations that have no owner assigned.",
        "script": r"""# ENTRA-006 — Unowned App Registrations
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All" -NoWelcome

$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName
$report = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($App in $Apps) {
    $i++
    Write-Progress -Activity "Checking owners" -Status $App.DisplayName `
                   -PercentComplete ($i / $Apps.Count * 100)
    $Owners = Get-MgApplicationOwner -ApplicationId $App.Id -ErrorAction SilentlyContinue
    if ($null -eq $Owners -or $Owners.Count -eq 0) {
        $report.Add([PSCustomObject]@{ AppName=$App.DisplayName; AppId=$App.AppId })
    }
}
Write-Progress -Completed -Activity "Checking owners"

$csv = "UnownedApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) of $($Apps.Count) app registrations have no owner. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-007": {
        "title": "Which app registrations are multi-tenant?",
        "description": "Lists app registrations configured to accept sign-ins from external Entra tenants.",
        "script": r"""# ENTRA-007 — Multi-Tenant App Registrations
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,SignInAudience
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    if ($App.SignInAudience -and $App.SignInAudience -ne 'AzureADMyOrg') {
        $report.Add([PSCustomObject]@{
            AppName        = $App.DisplayName
            AppId          = $App.AppId
            SignInAudience = $App.SignInAudience
        })
    }
}

$csv = "MultiTenantApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) multi-tenant app registration(s) found. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-008": {
        "title": "Which app registrations have implicit grant flow enabled?",
        "description": "Lists app registrations with ID token or access token issuance via implicit grant flow.",
        "script": r"""# ENTRA-008 — Implicit Grant Flow
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,Web
$report = [System.Collections.Generic.List[object]]::new()

foreach ($App in $Apps) {
    if ($App.Web -and $App.Web.ImplicitGrantSettings) {
        $idToken  = $App.Web.ImplicitGrantSettings.EnableIdTokenIssuance
        $accToken = $App.Web.ImplicitGrantSettings.EnableAccessTokenIssuance
        if ($idToken -eq $true -or $accToken -eq $true) {
            $report.Add([PSCustomObject]@{
                AppName            = $App.DisplayName
                AppId              = $App.AppId
                IDTokenEnabled     = $idToken
                AccessTokenEnabled = $accToken
            })
        }
    }
}

$csv = "ImplicitGrantApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) app(s) with implicit grant flow enabled. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Yellow'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-009": {
        "title": "Which service principals hold high-privilege directory roles?",
        "description": "Lists service principals (enterprise applications) assigned to high-privilege Entra directory roles.",
        "script": r"""# ENTRA-009 — Service Principals with High-Privilege Directory Roles
# Requires: Microsoft.Graph module
# Permissions: Directory.Read.All, RoleManagement.Read.Directory

Connect-MgGraph -Scopes "Directory.Read.All","RoleManagement.Read.Directory" -NoWelcome

$HighPrivRoles = @(
    'Global Administrator','Privileged Role Administrator','Application Administrator',
    'Cloud Application Administrator','Exchange Administrator','SharePoint Administrator',
    'Security Administrator','Conditional Access Administrator',
    'User Administrator','Hybrid Identity Administrator'
)

$report = [System.Collections.Generic.List[object]]::new()
foreach ($roleName in $HighPrivRoles) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if ($role) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $m.Id -ErrorAction SilentlyContinue
                if ($sp -and $sp.ServicePrincipalType -eq 'Application') {
                    $report.Add([PSCustomObject]@{
                        ServicePrincipal = $sp.DisplayName
                        AppId            = $sp.AppId
                        Role             = $roleName
                        SPObjectId       = $sp.Id
                    })
                }
            } catch {}
        }
    }
}

$csv = "PrivilegedServicePrincipals_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object Role,ServicePrincipal | Format-Table -AutoSize
Write-Host "$($report.Count) service principal(s) with high-privilege roles found. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Red'} else {'Green'})
Disconnect-MgGraph"""
    },

    "ENTRA-010": {
        "title": "Which managed identities hold high-privilege directory roles?",
        "description": "Lists managed identities assigned to high-privilege Entra directory roles.",
        "script": r"""# ENTRA-010 — Managed Identities with High-Privilege Directory Roles
# Requires: Microsoft.Graph module
# Permissions: Directory.Read.All, RoleManagement.Read.Directory

Connect-MgGraph -Scopes "Directory.Read.All","RoleManagement.Read.Directory" -NoWelcome

$HighPrivRoles = @(
    'Global Administrator','Privileged Role Administrator','Application Administrator',
    'Cloud Application Administrator','Exchange Administrator','SharePoint Administrator',
    'Security Administrator','Conditional Access Administrator',
    'User Administrator','Hybrid Identity Administrator'
)

$report = [System.Collections.Generic.List[object]]::new()
foreach ($roleName in $HighPrivRoles) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if ($role) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $m.Id -ErrorAction SilentlyContinue
                if ($sp -and $sp.ServicePrincipalType -eq 'ManagedIdentity') {
                    $miType = if ($sp.AlternativeNames -match '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/') {
                        'UserAssigned'
                    } else { 'SystemAssigned' }
                    $report.Add([PSCustomObject]@{
                        ManagedIdentity = $sp.DisplayName
                        MIType          = $miType
                        Role            = $roleName
                        ObjectId        = $sp.Id
                    })
                }
            } catch {}
        }
    }
}

$csv = "PrivilegedManagedIdentities_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Sort-Object Role,ManagedIdentity | Format-Table -AutoSize
Write-Host "$($report.Count) managed identit(ies) with high-privilege roles found. Exported: $csv" -ForegroundColor $(if ($report.Count -gt 0) {'Red'} else {'Green'})
Disconnect-MgGraph"""
    },

    "CA-003": {
        "title": "MFA enforcement for all users",
        "description": "Reviews all enabled Conditional Access policies and identifies whether any enforce MFA broadly against all users.",
        "script": r"""# CA-003 — MFA All-Users CA Policy Check
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

Write-Host "`n=== Conditional Access — MFA Coverage Check ===" -ForegroundColor Cyan
Write-Host "Checking for a CA policy that enforces MFA on all users...`n"

$policies = Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq "enabled" }
Write-Host "Total enabled CA policies: $($policies.Count)`n"

$mfaAllUsers = @()
$mfaPartial  = @()
$noMfa       = @()

foreach ($p in $policies) {
    $includeUsers  = $p.Conditions.Users.IncludeUsers
    $includeGroups = $p.Conditions.Users.IncludeGroups
    $grants        = $p.GrantControls.BuiltInControls
    $requiresMfa   = $grants -contains "mfa"

    if ($requiresMfa -and $includeUsers -contains "All") {
        $mfaAllUsers += $p
    } elseif ($requiresMfa) {
        $mfaPartial += $p
    } else {
        $noMfa += $p
    }
}

if ($mfaAllUsers.Count -gt 0) {
    Write-Host "PASS — MFA policy targeting all users found:" -ForegroundColor Green
    foreach ($p in $mfaAllUsers) {
        Write-Host "  [$($p.State)] $($p.DisplayName)" -ForegroundColor Green
        Write-Host "    Exclude users: $($p.Conditions.Users.ExcludeUsers -join ', ')" -ForegroundColor Gray
        Write-Host "    Exclude groups: $($p.Conditions.Users.ExcludeGroups -join ', ')" -ForegroundColor Gray
    }
} else {
    Write-Host "FAIL — No CA policy enforces MFA for all users." -ForegroundColor Red
    Write-Host "  Any user without explicit MFA assignment can sign in with only a password." -ForegroundColor Red
}

if ($mfaPartial.Count -gt 0) {
    Write-Host "`nMFA policies with partial user scope (not all users):" -ForegroundColor Yellow
    foreach ($p in $mfaPartial) {
        Write-Host "  [$($p.State)] $($p.DisplayName)" -ForegroundColor Yellow
        Write-Host "    Targets: $($p.Conditions.Users.IncludeUsers -join ', ') | Groups: $($p.Conditions.Users.IncludeGroups.Count)" -ForegroundColor Gray
    }
}

Write-Host "`nAll enabled policies summary:" -ForegroundColor Cyan
$policies | Select-Object DisplayName,State,
    @{N="IncludeUsers"; E={$_.Conditions.Users.IncludeUsers -join ", "}},
    @{N="MFA"; E={$_.GrantControls.BuiltInControls -contains "mfa"}} | Format-Table -AutoSize

Disconnect-MgGraph"""
    },

    "TEAMS-003": {
        "title": "Anonymous meeting join policy",
        "description": "Checks the global Teams meeting policy to determine whether unauthenticated users can join meetings.",
        "script": r"""# TEAMS-003 — Anonymous Meeting Join Check
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

Write-Host "`n=== Anonymous Meeting Join Policy ===" -ForegroundColor Cyan
Write-Host "An unauthenticated user is anyone who joins via a link without signing in.`n"

$globalPolicy = Get-CsTeamsMeetingPolicy -Identity Global
$anonJoin     = $globalPolicy.AllowAnonymousUsersToJoinMeeting

Write-Host "Global Policy — AllowAnonymousUsersToJoinMeeting: $anonJoin" `
           -ForegroundColor $(if($anonJoin){'Red'}else{'Green'})

if ($anonJoin) {
    Write-Host "`n  RISK: Anyone with a meeting link can join without authentication." -ForegroundColor Red
    Write-Host "  This includes external parties, competitors, or attackers who obtained a link." -ForegroundColor Red
    Write-Host "`n  To fix:" -ForegroundColor Yellow
    Write-Host "  Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting `$false" -ForegroundColor White
} else {
    Write-Host "`n  Anonymous meeting join is disabled. Good." -ForegroundColor Green
}

# Check custom policies that might allow anonymous join
Write-Host "`nChecking custom meeting policies that override global..." -ForegroundColor Cyan
$allPolicies = Get-CsTeamsMeetingPolicy | Where-Object { $_.Identity -ne "Global" -and $_.AllowAnonymousUsersToJoinMeeting -eq $true }
if ($allPolicies) {
    Write-Host "$($allPolicies.Count) custom policy(ies) still allow anonymous join:" -ForegroundColor Yellow
    $allPolicies | Select-Object Identity, AllowAnonymousUsersToJoinMeeting | Format-Table -AutoSize
} else {
    Write-Host "  No custom policies allow anonymous join." -ForegroundColor Green
}

Write-Host "`nAdditional meeting policy settings (Global):" -ForegroundColor Cyan
Write-Host "  AllowExternalParticipantGiveRequestControl : $($globalPolicy.AllowExternalParticipantGiveRequestControl)"
Write-Host "  AllowAnonymousUsersToStartMeeting          : $($globalPolicy.AllowAnonymousUsersToStartMeeting)"
Write-Host "  AutoAdmittedUsers                          : $($globalPolicy.AutoAdmittedUsers)"

Disconnect-MicrosoftTeams"""
    },

    "TEAMS-004": {
        "title": "Third-party Teams app permissions",
        "description": "Checks the global app permission policy to determine whether all third-party store apps are allowed without restriction.",
        "script": r"""# TEAMS-004 — Third-Party Teams App Permission Policy
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

Write-Host "`n=== Teams App Permission Policy ===" -ForegroundColor Cyan

$globalAppPolicy = Get-CsTeamsAppPermissionPolicy -Identity Global

Write-Host "`nGlobal App Permission Policy:" -ForegroundColor Cyan
$msApps      = $globalAppPolicy.DefaultCatalogApps
$thirdParty  = $globalAppPolicy.GlobalCatalogApps
$privateApps = $globalAppPolicy.PrivateCatalogApps

$col = if ($thirdParty -eq "Allow") { 'Red' } elseif ($thirdParty -eq "BlockWithNotification") { 'Yellow' } else { 'Green' }
Write-Host "  Microsoft apps (DefaultCatalogApps)  : $msApps"
Write-Host "  Third-party apps (GlobalCatalogApps) : $thirdParty" -ForegroundColor $col
Write-Host "  Custom apps (PrivateCatalogApps)     : $privateApps"

if ($thirdParty -eq "Allow") {
    Write-Host "`n  RISK: All third-party apps from the Teams store are unrestricted." -ForegroundColor Red
    Write-Host "  Users can install any app that may read messages, access files, or join meetings." -ForegroundColor Red
    Write-Host "`n  To restrict:" -ForegroundColor Yellow
    Write-Host "  Teams Admin Centre > Teams apps > Permission policies > Global" -ForegroundColor White
    Write-Host "  Change Third-party apps from 'Allow all' to 'Block all' or an approved app list" -ForegroundColor White
} else {
    Write-Host "`n  Third-party apps are restricted. Good." -ForegroundColor Green
}

# Check allowed app list if using allow-specific
if ($globalAppPolicy.AllowedAppList) {
    Write-Host "`nApproved apps list:" -ForegroundColor Cyan
    $globalAppPolicy.AllowedAppList | Format-Table -AutoSize
}

Write-Host "`nCustom app permission policies (may override global for some users):" -ForegroundColor Cyan
Get-CsTeamsAppPermissionPolicy | Where-Object { $_.Identity -ne "Global" } |
    Select-Object Identity, GlobalCatalogApps | Format-Table -AutoSize

Disconnect-MicrosoftTeams"""
    },

    "SPO-003": {
        "title": "OneDrive external sharing level",
        "description": "Checks the OneDrive for Business sharing level — this is separate from the SharePoint sharing setting and often overlooked.",
        "script": r"""# SPO-003 — OneDrive External Sharing Level
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant

Write-Host "`n=== OneDrive External Sharing ===" -ForegroundColor Cyan
Write-Host "Note: OneDrive sharing is controlled separately from SharePoint sharing.`n"

$odLevel = $tenant.ODBSharingCapability
$spLevel = $tenant.SharingCapability

$levelDesc = {
    param($lvl)
    switch ($lvl) {
        'Disabled'                       { 'Disabled — no external sharing' }
        'ExistingExternalUserSharingOnly'{ 'Existing guests only' }
        'ExternalUserSharingOnly'        { 'New and existing guests (sign-in required)' }
        'ExternalUserAndGuestSharing'    { 'Anyone — anonymous links ALLOWED' }
        default                          { $lvl }
    }
}

$spCol = if ($spLevel -eq 'ExternalUserAndGuestSharing') {'Red'} elseif ($spLevel -eq 'ExternalUserSharingOnly') {'Yellow'} else {'Green'}
$odCol = if ($odLevel -eq 'ExternalUserAndGuestSharing') {'Red'} elseif ($odLevel -eq 'ExternalUserSharingOnly') {'Yellow'} else {'Green'}

Write-Host "SharePoint sharing : $spLevel" -ForegroundColor $spCol
Write-Host "  $(& $levelDesc $spLevel)" -ForegroundColor $spCol
Write-Host ""
Write-Host "OneDrive sharing   : $odLevel" -ForegroundColor $odCol
Write-Host "  $(& $levelDesc $odLevel)" -ForegroundColor $odCol

if ($odLevel -eq 'ExternalUserAndGuestSharing') {
    Write-Host "`n  RISK: OneDrive allows Anyone links — files can be shared with no authentication." -ForegroundColor Red
    Write-Host "  Shared files are accessible to anyone with the URL — no sign-in or audit trail." -ForegroundColor Red
    Write-Host "`n  To fix:" -ForegroundColor Yellow
    Write-Host "  Set-SPOTenant -ODBSharingCapability ExistingExternalUserSharingOnly" -ForegroundColor White
}

Write-Host "`nAnonymous link settings:" -ForegroundColor Cyan
Write-Host "  RequireAnonymousLinksExpireInDays : $($tenant.RequireAnonymousLinksExpireInDays) (0 = no expiry)"
Write-Host "  DefaultLinkPermission             : $($tenant.DefaultLinkPermission)"
Write-Host "  DefaultSharingLinkType            : $($tenant.DefaultSharingLinkType)"

Disconnect-SPOService"""
    },

    "SPO-004": {
        "title": "Guest access expiry configuration",
        "description": "Checks whether external user (guest) access expiry is configured in SharePoint Online.",
        "script": r"""# SPO-004 — Guest Access Expiry Configuration
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant

Write-Host "`n=== Guest Access Expiry Settings ===" -ForegroundColor Cyan

$expiryRequired = $tenant.ExternalUserExpirationRequired
$expiryDays     = $tenant.ExternalUserExpireInDays
$linkExpiry     = $tenant.RequireAnonymousLinksExpireInDays

$col = if ($expiryRequired) { 'Green' } else { 'Red' }
Write-Host "ExternalUserExpirationRequired : $expiryRequired" -ForegroundColor $col

if ($expiryRequired) {
    Write-Host "ExternalUserExpireInDays       : $expiryDays days" -ForegroundColor Green
    Write-Host "`n  Guest access expires automatically after $expiryDays days. Good." -ForegroundColor Green
} else {
    Write-Host "`n  RISK: Guest accounts do not expire automatically." -ForegroundColor Red
    Write-Host "  Ex-employees of partner orgs, ex-contractors, and stale service accounts retain access indefinitely." -ForegroundColor Red
    Write-Host "`n  To fix:" -ForegroundColor Yellow
    Write-Host "  Set-SPOTenant -ExternalUserExpirationRequired `$true -ExternalUserExpireInDays 60" -ForegroundColor White
}

$linkCol = if ($linkExpiry -gt 0) { 'Green' } else { 'Yellow' }
Write-Host "`nAnonymous link expiry: $linkExpiry days $(if($linkExpiry -eq 0){'(no expiry — review recommended)'})" -ForegroundColor $linkCol

Write-Host "`nCurrent sharing settings summary:" -ForegroundColor Cyan
Write-Host "  SharingCapability    : $($tenant.SharingCapability)"
Write-Host "  ODBSharingCapability : $($tenant.ODBSharingCapability)"
Write-Host "  DefaultLinkPermission: $($tenant.DefaultLinkPermission)"

Disconnect-SPOService"""
    },

    "MDM-005": {
        "title": "Mobile device compliance policy coverage",
        "description": "Checks whether Intune compliance policies exist for iOS and Android devices.",
        "script": r"""# MDM-005 — Mobile Device Compliance Policy Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All" -NoWelcome

Write-Host "`n=== Mobile Device Compliance Policy Coverage ===" -ForegroundColor Cyan

$allPolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All -WarningAction SilentlyContinue
Write-Host "Total compliance policies: $($allPolicies.Count)`n"

$iosPolicies     = $allPolicies | Where-Object { $_.AdditionalProperties['@odata.type'] -like '*ios*' }
$androidPolicies = $allPolicies | Where-Object { $_.AdditionalProperties['@odata.type'] -like '*android*' -or $_.AdditionalProperties['@odata.type'] -like '*Android*' }
$windowsPolicies = $allPolicies | Where-Object { $_.AdditionalProperties['@odata.type'] -like '*windows*' }

$iosCol     = if ($iosPolicies.Count -gt 0) { 'Green' } else { 'Red' }
$androidCol = if ($androidPolicies.Count -gt 0) { 'Green' } else { 'Red' }

Write-Host "iOS compliance policies     : $($iosPolicies.Count)" -ForegroundColor $iosCol
Write-Host "Android compliance policies : $($androidPolicies.Count)" -ForegroundColor $androidCol
Write-Host "Windows compliance policies : $($windowsPolicies.Count)" -ForegroundColor $(if($windowsPolicies.Count -gt 0){'Green'}else{'Yellow'})

if ($iosPolicies.Count -gt 0) {
    Write-Host "`niOS Policies:" -ForegroundColor Cyan
    $iosPolicies | Select-Object DisplayName, @{N="Type";E={$_.AdditionalProperties['@odata.type']}} | Format-Table -AutoSize
}

if ($androidPolicies.Count -gt 0) {
    Write-Host "Android Policies:" -ForegroundColor Cyan
    $androidPolicies | Select-Object DisplayName, @{N="Type";E={$_.AdditionalProperties['@odata.type']}} | Format-Table -AutoSize
}

if ($iosPolicies.Count -eq 0 -or $androidPolicies.Count -eq 0) {
    Write-Host "`n  RISK: Mobile devices can connect to M365 with no compliance requirement." -ForegroundColor Red
    Write-Host "  Jailbroken, unmanaged, or compromised phones may access Exchange, Teams and SharePoint." -ForegroundColor Red
    Write-Host "`n  Create compliance policies at: Intune > Devices > Compliance policies" -ForegroundColor Yellow
}

# Enrolled mobile device count
Write-Host "`nEnrolled mobile devices (top 100):" -ForegroundColor Cyan
$mobileDevices = Get-MgDeviceManagementManagedDevice -All -WarningAction SilentlyContinue |
    Where-Object { $_.OperatingSystem -in @('iOS','Android') } | Select-Object -First 100
Write-Host "  iOS:     $(($mobileDevices | Where-Object OperatingSystem -eq 'iOS').Count)"
Write-Host "  Android: $(($mobileDevices | Where-Object OperatingSystem -eq 'Android').Count)"

Disconnect-MgGraph"""
    },

    "MDM-006": {
        "title": "Defender for Endpoint Intune integration",
        "description": "Checks whether Microsoft Defender for Endpoint is connected to Intune via Mobile Threat Defence connector.",
        "script": r"""# MDM-006 — Defender for Endpoint MTD Connector Status
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

Write-Host "`n=== Microsoft Defender for Endpoint — Intune Integration ===" -ForegroundColor Cyan
Write-Host "The MTD connector passes device risk signals from Defender into Conditional Access.`n"

try {
    $connectors = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/mobileThreatDefenseConnectors"

    if (-not $connectors.value -or $connectors.value.Count -eq 0) {
        Write-Host "  No Mobile Threat Defence connectors configured." -ForegroundColor Red
        Write-Host "  Device risk signals from Defender cannot flow into Conditional Access." -ForegroundColor Red
    } else {
        Write-Host "Configured MTD connectors:" -ForegroundColor Cyan
        foreach ($c in $connectors.value) {
            Write-Host "`n  Connector: $($c.id)" -ForegroundColor White
            Write-Host "  Android enabled : $($c.androidEnabled)" -ForegroundColor $(if($c.androidEnabled){'Green'}else{'Yellow'})
            Write-Host "  iOS enabled     : $($c.iosEnabled)" -ForegroundColor $(if($c.iosEnabled){'Green'}else{'Yellow'})
            Write-Host "  Windows enabled : $($c.windowsEnabled)" -ForegroundColor $(if($c.windowsEnabled){'Green'}else{'Yellow'})
            $anyEnabled = $c.androidEnabled -or $c.iosEnabled -or $c.windowsEnabled
            if ($anyEnabled) {
                Write-Host "  STATUS: Active — at least one platform is connected" -ForegroundColor Green
            } else {
                Write-Host "  STATUS: Connector exists but no platforms are enabled" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  Could not retrieve MTD connectors: $_" -ForegroundColor Red
}

Write-Host "`nTo configure:" -ForegroundColor Yellow
Write-Host "  Intune > Endpoint security > Microsoft Defender for Endpoint"
Write-Host "  Portal: https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/mdeConnector"

Disconnect-MgGraph"""
    },
}


@app.route("/investigate/<finding_id>", methods=["GET"])
def get_investigation_script(finding_id):
    """Return a ready-to-run PowerShell investigation script for a finding."""
    data = INVESTIGATION_SCRIPTS.get(finding_id)
    if not data:
        return jsonify({"error": f"No investigation script for {finding_id}"}), 404
    return jsonify({
        "findingId":   finding_id,
        "title":       data["title"],
        "description": data["description"],
        "script":      data["script"],
    })


@app.route("/findings-library", methods=["GET"])
def get_findings_library():
    return jsonify([{k: v for k, v in f.items() if k != "threshold"} for f in FINDINGS_LIBRARY])


@app.route("/docs/cis-m365-benchmark")
def serve_cis_benchmark():
    """Serve the local CIS M365 Foundations Benchmark PDF."""
    pdf_path = os.path.join(BASE_DIR, "CIS", "CIS_Microsoft_365_Foundations_Benchmark_v7.0.0.pdf")
    if os.path.exists(pdf_path):
        return send_file(pdf_path, mimetype="application/pdf")
    return "CIS benchmark PDF not found", 404


@app.route("/")
def serve_index():
    """Serve the frontend HTML file - avoids file:// CORS issues."""
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    return "index.html not found", 404


# =================================================================
#  SCHEDULED SCANS — Windows Task Scheduler Integration
# =================================================================

HEADLESS_RUNNER_PATH = os.path.join(BASE_DIR, "run_scheduled_scan.py")

def _ensure_headless_runner():
    """Write the headless scan runner script if it doesn't exist."""
    script = r'''#!/usr/bin/env python3
"""
Headless scheduled scan runner for M365 Assessment Toolkit.
Called by Windows Task Scheduler — uses App Registration auth only.
Results are saved as JSON + CSV to the output folder.
"""
import sys, os, json, datetime, subprocess, pathlib

BASE_DIR = pathlib.Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--client-name',   required=True)
    parser.add_argument('--tenant-id',     required=True)
    parser.add_argument('--client-id',     required=True)
    parser.add_argument('--client-secret', required=True)
    parser.add_argument('--modules',       required=True, help='Comma-separated list')
    args = parser.parse_args()

    modules = [m.strip() for m in args.modules.split(',') if m.strip()]
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = "".join(c if c.isalnum() or c in '-_' else '_' for c in args.client_name)

    log_path = BASE_DIR / 'output' / f'scheduled_{safe_name}_{ts}.log'
    log = open(log_path, 'w', encoding='utf-8')
    log.write(f"M365 Assessment Toolkit — Scheduled Scan\n")
    log.write(f"Client: {args.client_name}\nModules: {', '.join(modules)}\nStarted: {ts}\n\n")
    log.flush()

    # Call the backend scan endpoint via HTTP (backend must be running)
    import urllib.request, urllib.error
    payload = json.dumps({
        "client_name": args.client_name,
        "auth_method": "app_registration",
        "tenant_id": args.tenant_id,
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "modules": modules,
        "scheduled": True,
    }).encode()

    try:
        req = urllib.request.Request(
            'http://127.0.0.1:5000/run',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode())
        out_path = BASE_DIR / 'output' / f'scheduled_{safe_name}_{ts}.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        log.write(f"Scan completed. Score: {result.get('score','?')}\n")
        log.write(f"Findings: {len(result.get('findings', []))}\n")
        log.write(f"Output: {out_path}\n")
        print(f"[OK] Scheduled scan complete. Output: {out_path}")
    except Exception as e:
        log.write(f"ERROR: {e}\n")
        print(f"[ERROR] {e}")
        sys.exit(1)
    finally:
        log.close()

if __name__ == '__main__':
    main()
'''
    if not os.path.exists(HEADLESS_RUNNER_PATH):
        with open(HEADLESS_RUNNER_PATH, 'w', encoding='utf-8') as f:
            f.write(script)
    return HEADLESS_RUNNER_PATH


@app.route("/schedule", methods=["POST"])
def create_schedule():
    body          = request.get_json()
    client_name   = body.get("clientName", "").strip()
    tenant_id     = body.get("tenantId", "").strip()
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    frequency     = body.get("frequency", "weekly")
    modules       = body.get("modules", ["identity", "security"])

    if not all([client_name, tenant_id, client_id, client_secret]):
        return jsonify({"error": "Missing required fields"}), 400
    if not modules:
        return jsonify({"error": "No modules selected"}), 400

    runner_path = _ensure_headless_runner()

    # Determine Task Scheduler trigger
    freq_map = {
        "weekly":  "/SC WEEKLY /D MON /ST 06:00",
        "daily":   "/SC DAILY /ST 06:00",
        "monthly": "/SC MONTHLY /D 1 /ST 06:00",
    }
    schedule_args = freq_map.get(frequency, freq_map["weekly"])
    next_run_map = {
        "weekly": "Next Monday at 06:00",
        "daily": "Tomorrow at 06:00",
        "monthly": "1st of next month at 06:00",
    }

    safe_name = "".join(c if c.isalnum() or c in '-_ ' else '_' for c in client_name)[:30]
    task_name = f"M365Scan_{safe_name.replace(' ','_')}"

    python_exe = sys.executable.replace("pythonw.exe", "python.exe")
    modules_str = ",".join(modules)

    # Build the schtasks command
    run_cmd = (
        f'"{python_exe}" "{runner_path}"'
        f' --client-name "{client_name}"'
        f' --tenant-id "{tenant_id}"'
        f' --client-id "{client_id}"'
        f' --client-secret "{client_secret}"'
        f' --modules "{modules_str}"'
    )

    schtasks_cmd = (
        f'schtasks /Create /TN "{task_name}" /TR "{run_cmd}"'
        f' {schedule_args} /RL HIGHEST /F'
    )

    try:
        result = subprocess.run(
            schtasks_cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": f"Task Scheduler error: {err}"}), 500

        return jsonify({
            "success": True,
            "taskName": task_name,
            "nextRun": next_run_map.get(frequency, "As configured"),
            "modules": modules,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/schedule/list", methods=["GET"])
def list_schedules():
    """List M365Scan_* tasks from Windows Task Scheduler."""
    try:
        result = subprocess.run(
            'schtasks /Query /FO CSV /NH', shell=True,
            capture_output=True, text=True, timeout=15
        )
        tasks = []
        for line in result.stdout.splitlines():
            if '"M365Scan_' in line:
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 3:
                    tasks.append({"name": parts[0], "nextRun": parts[1], "status": parts[2]})
        return jsonify({"tasks": tasks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    import webbrowser, threading

    print("=" * 60)
    print("  M365 Assessment Tool - Backend v2")
    print("  M365 Assessment Toolkit")
    print("=" * 60)
    print(f"  Auth modes:      Interactive Login + App Registration")
    print(f"  Scripts folder:  {SCRIPTS_DIR}")
    print(f"  Output folder:   {OUTPUT_DIR}")
    print(f"  Reports folder:  {REPORTS_DIR}")
    print(f"  Findings loaded: {len(FINDINGS_LIBRARY)}")
    print("=" * 60)
    print("  Opening tool at http://localhost:5000")
    print("  Keep this window open while using the tool.")
    print()

    # Open browser automatically after a short delay
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open("http://localhost:5000")

    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
