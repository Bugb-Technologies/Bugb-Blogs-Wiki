---
title: "GitHub Enterprise SAML Encrypted Assertions Exposure Assessment"
slug: "ghes-saml-encrypted-assertions-exposure"
date: "2026-03-04"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Assess GitHub Enterprise Server for SAML encrypted assertion misconfiguration (CVE-2024-4985)."
category: "infrastructure-security"
---

# GHES SAML Encrypted Assertions Exposure (CVE-2024-4985 / CVE-2024-9487)

## Executive Summary

CVE-2024-4985 is a maximum severity (CVSS 10.0) authentication bypass vulnerability affecting GitHub Enterprise Server (GHES) when using SAML single sign-on with encrypted assertions enabled. When exploited, attackers can forge SAML responses and gain administrative access without any prior authentication.

This CERT-X-GEN template provides **high-confidence exposure detection** by correlating GHES version fingerprinting with SAML configuration analysis, enabling organizations to identify deployments at risk without attempting active exploitation.

> **Key Insight**: This template performs exposure assessment through version and configuration analysis. It does NOT forge SAML responses or attempt authentication bypass—this is a deliberate design choice for safe, enterprise-friendly scanning.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 10.0 (Maximum) |
| **CVE IDs** | CVE-2024-4985, CVE-2024-9487 |
| **CWE** | CWE-347 (Improper Signature Verification), CWE-290 (Auth Bypass) |
| **Affected Versions** | GHES < 3.9.15, < 3.10.12, < 3.11.10, < 3.12.4 |
| **Detection Confidence** | 85% (exposure-based) |
| **Detection Type** | Exposure Assessment (Non-Exploit) |

---


> **Run this check with CERT-X-GEN** — the polyglot security scanner that executes templates in real programming languages. [Get the templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) | [Install CERT-X-GEN](https://github.com/Bugb-Technologies/cert-x-gen)
>
> **Related templates:** [`devops/github/`](https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/devops/github) *(dedicated SAML assertions template coming soon)*

## Ethical & Safety Boundary

This CERT-X-GEN template is intentionally designed as an **exposure detector**, not an exploitation tool.

### It does NOT:
- Forge or submit SAML responses
- Attempt authentication bypass
- Impersonate users or administrators
- Create sessions or modify accounts
- Exploit the vulnerability in any way

### Instead, it identifies deployments exposed to CVE-2024-4985 by correlating:
- GitHub Enterprise Server version
- SAML authentication enablement
- Encrypted assertions configuration signals (from metadata)

### This design ensures:
- **Safe, internet-scale scanning** - No risk of disrupting production systems
- **Enterprise-friendly usage** - Suitable for internal security teams and auditors
- **Responsible vulnerability identification** - Enables remediation without exploitation
- **Legal compliance** - No unauthorized access attempts

> *Note: SAML metadata reflects encryption capability and configuration signals; actual enforcement depends on runtime IdP and SP behavior. Manual verification is recommended for critical systems.*

---

## Understanding the Vulnerability

### How SAML Authentication Works

SAML (Security Assertion Markup Language) enables Single Sign-On (SSO) by allowing an Identity Provider (IdP) to authenticate users and pass assertions to a Service Provider (SP):

```
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ User │────►│ IdP │────►│ GHES (SP) │
│ │ │ (Okta, etc) │ │ │
└──────────────┘ └──────────────┘ └──────────────┘
 │ │ │
 │ 1. Login Request │ │
 │───────────────────►│ │
 │ │ │
 │ 2. Authentication │ │
 │◄──────────────────►│ │
 │ │ │
 │ 3. SAML Response │ │
 │◄───────────────────│ │
 │ │ │
 │ 4. Forward Response to SP │
 │────────────────────────────────────────►│
 │ │ │
 │ 5. Session Created│ │
 │◄────────────────────────────────────────│
```

### The Encrypted Assertions Feature

GitHub Enterprise Server supports **encrypted assertions**, an optional security feature that encrypts the SAML assertions before transmission. This is intended to provide additional confidentiality, but an implementation flaw in vulnerable versions creates a critical vulnerability.

### The Vulnerability Mechanism (For Context)

The vulnerability exploits improper signature validation when encrypted assertions are configured:

1. **Signature Extraction Timing**: GHES extracts signatures BEFORE decrypting encrypted assertions
2. **Signature Priority**: If a signature exists on the outer Response, the inner Assertion signature is never validated
3. **Signature Wrapping**: Attackers can wrap a valid SAMLResponse inside a `<ds:Object>` element
4. **Forged Assertion**: Create a new assertion with victim's identity that won't be signature-verified

**This template does NOT exploit this mechanism. It only identifies systems where the exposure conditions exist.**

---

## Why Traditional Scanners Fail

### The YAML Limitation

YAML-based scanners like Nuclei work through pattern matching and simple HTTP requests:

```yaml
# What Nuclei CAN do:
id: ghes-detection
requests:
 - method: GET
 path:
 - "{{BaseURL}}/api/v3/meta"
 matchers:
 - type: regex
 regex:
 - 'X-GitHub-Enterprise-Version: ([0-9.]+)'
```

This detects GHES but **cannot**:

| Capability | YAML | CERT-X-GEN |
|------------|------|------------|
| Detect GHES instance | | |
| Extract version from headers | | |
| Parse SAML metadata XML | | |
| Handle XML namespaces | | |
| Detect encryption configuration | | |
| Version comparison logic | | |
| Multi-endpoint correlation | | |
| **Exposure Assessment Confidence** | ~30% | **85%** |

### The Detection Gap

YAML can detect *that a GHES instance exists*. CERT-X-GEN can assess:
- Exact version and exposure status
- SAML authentication configuration
- Encryption configuration signals from metadata
- SP certificate presence

---

## The CERT-X-GEN Approach

### Detection Strategy (Exposure Assessment)

```
┌──────────────────────────────────────────────────────────────────┐
│ CERT-X-GEN EXPOSURE DETECTION FLOW │
├──────────────────────────────────────────────────────────────────┤
│ │
│ Scanner ──────► Target: GET /api/v3/meta │
│ │ Check X-GitHub-Enterprise-Version header │
│ ▼ │
│ Scanner ──────► Target: GET / and /login │
│ │ Detect GHES indicators │
│ ▼ │
│ Scanner ──────► SAML: GET /saml/metadata │
│ │ Parse EntityDescriptor, check for encryption │
│ ▼ │
│ Scanner: Extract entity ID, ACS URL, certificates │
│ │ │
│ ▼ │
│ Scanner: Compare version against known exposed ranges │
│ │ │
│ ▼ │
│ Version < 3.9.15, 3.10.12, 3.11.10, or 3.12.4? │
│ │ + Encryption configuration detected? │
│ ▼ │
│ CRITICAL: Deployment exposed to CVE-2024-4985 │
│ OR │
│ Patched / Not exposed │
│ │
│ NO EXPLOITATION ATTEMPTED AT ANY POINT │
│ │
└──────────────────────────────────────────────────────────────────┘
```

### Key Advantages

1. **Accurate Version Detection**: Extracts version from multiple sources (headers, API, HTML)
2. **SAML Configuration Analysis**: Parses XML metadata with proper namespace handling
3. **Encryption Detection**: Identifies if encryption is configured based on metadata signals
4. **Comprehensive Reporting**: Provides detailed evidence for remediation
5. **Safe Operation**: No exploitation or authentication bypass attempts

---

## Detection Flow Visualization

### Exposure Conditions Assessed

```
┌─────────────────────────────────────────────────────────────────┐
│ CVE-2024-4985 EXPOSURE CONDITIONS │
├─────────────────────────────────────────────────────────────────┤
│ │
│ CONDITION 1: GitHub Enterprise Server │
│ ├─► Detected via X-GitHub-Enterprise-Version header │
│ ├─► Detected via /api/v3/meta response │
│ └─► Detected via page content indicators │
│ │
│ CONDITION 2: Vulnerable Version │
│ ├─► 3.9.x where x < 15 │
│ ├─► 3.10.x where x < 12 │
│ ├─► 3.11.x where x < 10 │
│ └─► 3.12.x where x < 4 │
│ │
│ CONDITION 3: SAML Authentication Enabled │
│ ├─► /saml/metadata endpoint accessible │
│ ├─► SAML redirect on /login │
│ └─► SSO indicators in page content │
│ │
│ CONDITION 4: Encryption Configuration (from metadata) │
│ ├─► KeyDescriptor with use="encryption" present │
│ └─► X509Certificate for encryption available │
│ │
│ ALL CONDITIONS MET? → CRITICAL EXPOSURE │
│ SOME CONDITIONS MET? → HIGH/MEDIUM (needs verification) │
│ CONDITIONS NOT MET? → NOT EXPOSED │
│ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Version Exposure Check

```python
def is_version_vulnerable(version: str) -> Tuple[bool, str]:
 """Check if GHES version is exposed to CVE-2024-4985."""
 parsed = parse_version(version)
 major, minor, patch = parsed
 
 if major == 3:
 if minor == 9 and patch < 15:
 return True, f"Version {version} < 3.9.15 (exposed)"
 if minor == 10 and patch < 12:
 return True, f"Version {version} < 3.10.12 (exposed)"
 if minor == 11 and patch < 10:
 return True, f"Version {version} < 3.11.10 (exposed)"
 if minor == 12 and patch < 4:
 return True, f"Version {version} < 3.12.4 (exposed)"
 if minor >= 13:
 return False, f"Version {version} >= 3.13.0 (patched)"
 
 return False, f"Version {version} appears to be patched"
```

### SAML Metadata Parsing

```python
def parse_saml_metadata(xml_content: str) -> Dict[str, Any]:
 """
 Parse SAML metadata to extract configuration signals.
 
 Note: Metadata reflects encryption capability and configuration;
 actual enforcement depends on runtime IdP and SP behavior.
 """
 from lxml import etree
 
 root = etree.fromstring(xml_content.encode())
 
 # Check for encryption key descriptor
 key_desc = root.find('.//md:KeyDescriptor[@use="encryption"]', SAML_NAMESPACES)
 
 return {
 'entity_id': root.get('entityID'),
 'encryption_configured': key_desc is not None,
 'certificate': extract_certificate(key_desc),
 }
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a GHES instance for exposure
cert-x-gen scan --scope ghes.example.com --templates ghes-saml-encrypted-assertions-exposure.py

# With explicit port
cert-x-gen scan --scope ghes.example.com --ports 443,8443 --templates ghes-saml-encrypted-assertions-exposure.py

# JSON output
cert-x-gen scan --scope ghes.example.com --templates ghes-saml-encrypted-assertions-exposure.py --output-format json

# Multiple targets from file
cert-x-gen scan --scope @ghes-targets.txt --templates ghes-saml-encrypted-assertions-exposure.py
```

### Direct Template Execution

```bash
# Run Python template directly
python3 ghes-saml-encrypted-assertions-exposure.py ghes.example.com --verbose

# JSON output
python3 ghes-saml-encrypted-assertions-exposure.py ghes.example.com --json
```

### Expected Output (Exposed)

```json
{
 "template_id": "ghes-saml-encrypted-assertions-exposure",
 "severity": "critical",
 "confidence": 85,
 "title": "CVE-2024-4985: GHES Deployment Exposed to SAML Auth Bypass",
 "description": "CRITICAL: GitHub Enterprise Server deployment exposed to CVE-2024-4985...",
 "evidence": {
 "version_from_header": "3.9.9",
 "encryption_configured": true,
 "version_exposed": true,
 "exposure_reason": "Version 3.9.9 < 3.9.15 (exposed)",
 "detection_type": "exposure_assessment"
 }
}
```

### Expected Output (Patched)

```json
{
 "template_id": "ghes-saml-encrypted-assertions-exposure",
 "severity": "info",
 "title": "GitHub Enterprise Server - Patched Version",
 "description": "GHES 3.15.13 detected with SAML authentication. Version 3.15.13 >= 3.13.0 (patched)",
 "evidence": {
 "version_from_header": "3.15.13",
 "version_exposed": false,
 "detection_type": "exposure_assessment"
 }
}
```

---

## Real-World Test Results

The template was tested against live GitHub Enterprise Server instances discovered via FOFA:

| Target | Version | SAML | Encryption | Exposed | Result |
|--------|---------|------|------------|---------|--------|
| 34.73.115.176 | 3.9.9 | | | Yes | HIGH - Potentially exposed |
| 20.7.130.112 | 3.20.0 | | | No | INFO - Patched |
| 52.232.249.25 | 3.17.6 | | | No | INFO - Patched |
| 54.85.240.31 | 3.15.13 | | | No | INFO - Patched |
| github.mheducation.com | 3.15.13 | | | No | INFO - Patched |

**Key Finding**: Most production GHES instances have been patched. The template successfully:

1. Detects GHES instances via multiple methods
2. Extracts accurate version information
3. Parses SAML metadata for encryption configuration signals
4. Correctly identifies exposed vs patched versions
5. Provides detailed evidence for security teams
6. Operates safely without exploitation attempts

---

## Defense & Remediation

### Immediate Actions

```
PRIORITY 1: UPGRADE IMMEDIATELY
─────────────────────────────────
Patched Versions:
 • 3.9.x → Upgrade to 3.9.15+
 • 3.10.x → Upgrade to 3.10.12+
 • 3.11.x → Upgrade to 3.11.10+
 • 3.12.x → Upgrade to 3.12.4+
 • Any → Upgrade to 3.13.0+

PRIORITY 2: TEMPORARY MITIGATION
─────────────────────────────────
If upgrade is not immediately possible:
 • Consider disabling encrypted assertions in SAML config
 • Enable audit logging for authentication
 • Restrict network access to GHES instance
 • Monitor for suspicious admin provisioning
```

### Verification Steps

1. **Check Version**: Settings → Enterprise overview → About Enterprise
2. **Review SAML Config**: Settings → Authentication → SAML
3. **Audit Logs**: Monitor for unexpected admin account creation
4. **Network Access**: Ensure GHES is not publicly accessible

### Long-Term Recommendations

- Enable automatic security updates
- Implement network segmentation
- Configure SIEM integration for auth monitoring
- Regular penetration testing of GHES deployment
- Subscribe to GitHub security advisories

---

## Future Verification Mode (Planned)

CERT-X-GEN may introduce an **explicit opt-in verification mode** in the future for controlled environments, allowing authorized users to validate authentication behavior under strict safeguards.

Such functionality will:
- Never be enabled by default
- Require explicit opt-in flags
- Include appropriate warnings
- Only be recommended for authorized testing environments

---

## References

### Official Advisories

- [GitHub Advisory GHSA-5pw9-f9r4-mv2r](https://github.com/advisories/GHSA-5pw9-f9r4-mv2r)
- [CERT-EU Advisory 2024-047](https://cert.europa.eu/publications/security-advisories/2024-047/)
- [NVD CVE-2024-4985](https://nvd.nist.gov/vuln/detail/CVE-2024-4985)

### Technical Analysis

- [ProjectDiscovery Blog: GitHub Enterprise SAML Authentication Bypass](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass)
- [GitHub Release Notes 3.12.4](https://docs.github.com/en/enterprise-server@3.12/admin/release-notes#3.12.4)

### Related Vulnerabilities

| CVE | Description | CVSS |
|-----|-------------|------|
| CVE-2024-4985 | Original SAML auth bypass | 10.0 |
| CVE-2024-9487 | Follow-up fix bypass | 9.5 |
| CVE-2024-6800 | SAML auth bypass (different vector) | 9.8 |

---

