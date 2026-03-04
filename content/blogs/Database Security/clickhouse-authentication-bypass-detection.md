---
title: "ClickHouse Authentication Bypass Detection: From Discovery to Data Extraction"
slug: "clickhouse-authentication-bypass-detection"
date: "2026-03-04"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Detect ClickHouse HTTP interfaces exposed without authentication using CERT-X-GEN Python templates."
category: "database-security"
---

# ClickHouse Authentication Bypass Detection

## Executive Summary

ClickHouse is a high-performance columnar database management system designed for online analytical processing (OLAP). By default, ClickHouse's HTTP interface on port 8123 can be configured to allow connections without authentication, creating a critical security vulnerability that exposes sensitive data and database operations to unauthorized users.

**The result?** Complete database access. An attacker can execute queries, enumerate tables, extract data, and potentially modify database contents—all without credentials.

> **Key Insight**: This vulnerability cannot be detected through simple port scanning or banner grabbing. It requires actual query execution, authentication testing, and database enumeration—exactly what CERT-X-GEN's polyglot templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 8.6 (High) |
| **CWE** | CWE-306 (Missing Authentication) |
| **Default Port** | 8123 (HTTP), 8443 (HTTPS) |
| **Detection Complexity** | Medium (requires query execution) |
| **Exploitation Difficulty** | Low (once exposed) |
| **Global Exposure** | 108,253+ instances (FOFA data, Jan 2026) |

---


> **Run this check with CERT-X-GEN** — the polyglot security scanner that executes templates in real programming languages. [Get the templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) | [Install CERT-X-GEN](https://github.com/Bugb-Technologies/cert-x-gen)
>
> **Template source:** [`clickhouse-auth-bypass.py`](https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/templates/databases/clickhouse/clickhouse-auth-bypass.py)

## Understanding the Vulnerability

### ClickHouse Authentication Architecture

ClickHouse supports multiple authentication methods for its HTTP interface:

| Method | Configuration | Security |
|--------|--------------|----------|
| **No Authentication** | Default user without password | VULNERABLE |
| **Basic Auth** | User/password in request | SECURE |
| **X-ClickHouse-User/Key** | Custom headers | SECURE |
| **X.509 Certificates** | Certificate-based auth | SECURE |
| **Network Restrictions** | IP whitelist | SECURE |

### The Vulnerability Mechanism

The attack exploits a dangerous default configuration:

```
┌─────────────────────────────────────────────────────────────────┐
│ CLICKHOUSE AUTHENTICATION BYPASS ATTACK │
├─────────────────────────────────────────────────────────────────┤
│ │
│ 1. Attacker discovers ClickHouse HTTP interface (port 8123) │
│ ↓ │
│ 2. Attacker sends unauthenticated query: SELECT 1 │
│ ↓ │
│ 3. Server receives query WITHOUT credentials │
│ ↓ │
│ 4. Server checks: Is 'default' user password set? │
│ ├── Yes: Returns 516 AUTHENTICATION_FAILED │
│ └── No: Processes query and returns results │
│ ↓ │
│ 5. Query executes successfully! ACCESS GRANTED │
│ ↓ │
│ 6. Attacker enumerates system tables: SELECT * FROM system.* │
│ ↓ │
│ 7. Attacker extracts data, modifies tables, exfiltrates DB │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Happens

Vulnerable ClickHouse instances typically result from:

1. **Default Installation**: ClickHouse installs with a `default` user and empty password
2. **Misconfigured Networks**: `<listen_host>::</listen_host>` allows public access
3. **Missing Access Controls**: No IP restrictions or firewall rules
4. **Outdated Documentation**: Older tutorials don't emphasize security best practices

Vulnerable configuration (`/etc/clickhouse-server/users.xml`):

```xml
<!-- VULNERABLE: Default user without password -->
<yandex>
 <users>
 <default>
 <!-- No password element = empty password = NO AUTHENTICATION -->
 <networks>
 <ip>::/0</ip> <!-- Allows any IP -->
 </networks>
 <profile>default</profile>
 <quota>default</quota>
 </default>
 </users>
</yandex>
```

---

## Why Traditional Scanners Fall Short

### The YAML Limitation

Traditional YAML-based scanners can detect ClickHouse services but cannot verify authentication:

```yaml
# What Nuclei CAN do:
id: clickhouse-detection
requests:
 - method: GET
 path:
 - "{{BaseURL}}/ping"
 matchers:
 - type: word
 words:
 - "Ok."
 - type: header
 headers:
 - "X-ClickHouse-Server"
```

This detects the service but **cannot**:

| Capability | YAML | CERT-X-GEN |
|------------|------|------------|
| Detect ClickHouse service | | |
| Send test SQL query | | |
| Parse query response | | |
| Enumerate system tables | | |
| Count accessible tables | | |
| Distinguish auth errors | | |
| **Confidence Level** | ~30% | **95%** |

### The Detection Gap

YAML-based scanners can detect *indicators* of ClickHouse presence. CERT-X-GEN can verify *actual exploitability* by executing queries and enumerating database access.

**Key Limitations of YAML:**
- Cannot execute SQL queries
- Cannot parse tabular response data
- Cannot distinguish between authentication errors and network issues
- Cannot test multiple authentication vectors
- Cannot validate database-level permissions

---

## The CERT-X-GEN Approach

CERT-X-GEN uses Python's `urllib` and custom parsing to perform actual database queries, not just service detection.

### Detection Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│ CERT-X-GEN DETECTION FLOW │
├──────────────────────────────────────────────────────────────────┤
│ │
│ Scanner ──────► Target: GET /ping (service detection) │
│ │ │
│ ▼ │
│ Scanner: Parse response headers for ClickHouse indicators │
│ │ │
│ ▼ │
│ Scanner ──────► Target: /?query=SELECT 1 (no auth) │
│ │ │
│ ▼ │
│ Response Analysis: │
│ ├── HTTP 200 + "1" ───► Continue to system table test │
│ ├── HTTP 516 ───► Authentication enabled (not vulnerable) │
│ └── HTTP 403 ───► Access denied (not vulnerable) │
│ │ │
│ ▼ │
│ Scanner ──────► Target: /?query=SELECT count() FROM system.tables│
│ │ │
│ ▼ │
│ Response 200 + table count? ───► CRITICAL: Full DB access! │
│ Response 4xx/5xx? ──────────► MEDIUM: Limited access │
│ │
└──────────────────────────────────────────────────────────────────┘
```

### Key Advantages

1. **Actual Query Execution**: We execute real SQL queries to verify access
2. **Zero False Positives**: If queries execute, it's vulnerable
3. **Severity Classification**: Distinguishes between query access and data access
4. **Graceful Error Handling**: Properly handles timeouts, network errors, auth errors
5. **Multi-Protocol Testing**: Tests both HTTP and HTTPS automatically
6. **Evidence Collection**: Captures query responses, headers, table counts

---

## Attack Flow Visualization

### Complete Attack Chain

**Phase 1: Service Discovery**
- Port Scan: Detect port 8123 or 8443
- Ping Endpoint: GET /ping
- Identify ClickHouse Service

**Phase 2: Authentication Testing**
- No Credentials: /?query=SELECT 1
- Default Credentials: user=default&password=
- Analyze Response Codes

**Phase 3: Access Verification**
- System Tables: SELECT count() FROM system.tables
- Database Enumeration: SELECT name FROM system.databases
- Count Accessible Resources

**Phase 4: Impact Assessment**
- Data Access: Can read data?
- Write Access: Can modify data?
- Classify Severity: CRITICAL or HIGH

### Query Response Patterns

```
┌─────────────────────────────────────────────────────────────────┐
│ UNAUTHENTICATED QUERY TEST │
├─────────────────────────────────────────────────────────────────┤
│ │
│ Request: GET http://target:8123/?query=SELECT 1 │
│ │
│ ┌─ VULNERABLE RESPONSE ────────────────────────────────────┐ │
│ │ HTTP/1.1 200 OK │ │
│ │ X-ClickHouse-Server-Display-Name: clickhouse-server │ │
│ │ X-ClickHouse-Query-Id: abc-123-def-456 │ │
│ │ X-ClickHouse-Format: TabSeparated │ │
│ │ │ │
│ │ 1 ◀── Query result! │ │
│ └──────────────────────────────────────────────────────────┘ │
│ │
│ ┌─ SECURED RESPONSE ───────────────────────────────────────┐ │
│ │ HTTP/1.1 403 Forbidden │ │
│ │ X-ClickHouse-Exception-Code: 516 │ │
│ │ │ │
│ │ Code: 516. DB::Exception: default: Authentication │ │
│ │ failed: password is incorrect or there is no user │ │
│ │ with such name. (AUTHENTICATION_FAILED) │ │
│ └──────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Core Detection Implementation

```python
def test_unauthenticated_query(base_url, query, timeout=5):
 """
 Test if query executes without authentication.
 Returns: (success, status_code, response_data, headers)
 """
 try:
 # URL encode the query
 encoded_query = quote(query)
 test_url = f"{base_url}/?query={encoded_query}"
 
 req = Request(test_url)
 req.add_header('User-Agent', 'Mozilla/5.0')
 req.add_header('Accept', '*/*')
 
 ctx = create_ssl_context()
 with urlopen(req, timeout=timeout, context=ctx) as response:
 status_code = response.getcode()
 headers = dict(response.info())
 response_data = response.read().decode('utf-8', errors='ignore')
 
 # Check for successful query execution
 if status_code == 200 and response_data:
 return True, status_code, response_data, headers
 
 except HTTPError as e:
 status_code = e.code
 response_data = e.read().decode('utf-8', errors='ignore')
 
 # Check for authentication errors (indicates security is enabled)
 if status_code == 401:
 return False, status_code, response_data, {}
 elif status_code == 516 or 'Authentication failed' in response_data:
 return False, status_code, response_data, {}
 
 return False, None, None, {}
```

### Service Detection

```python
def detect_clickhouse_service(base_url, timeout=5):
 """
 Detect if ClickHouse HTTP interface is present.
 Returns: (is_clickhouse, version, server_name)
 """
 try:
 # Ping endpoint
 req = Request(f"{base_url}/ping")
 req.add_header('User-Agent', 'Mozilla/5.0')
 
 ctx = create_ssl_context()
 with urlopen(req, timeout=timeout, context=ctx) as response:
 headers = dict(response.info())
 response_data = response.read().decode('utf-8', errors='ignore')
 
 # Check for ClickHouse indicators
 server_header = headers.get('Server', '')
 display_name = headers.get('X-ClickHouse-Server-Display-Name', '')
 
 if 'ClickHouse' in server_header or 'X-ClickHouse' in str(headers) \
 or response_data.strip() == 'Ok.':
 # Extract version
 version_match = re.search(r'ClickHouse/([0-9.]+)', server_header)
 version = version_match.group(1) if version_match else "unknown"
 
 return True, version, display_name or "ClickHouse"
 except:
 pass
 
 return False, None, None
```

### System Table Enumeration

```python
def test_data_access(base_url, timeout=5):
 """
 Test if we can access system tables (conclusive proof of bypass).
 Returns: (success, table_count, error_message)
 """
 try:
 # Query system.tables to enumerate accessible tables
 query = "SELECT count() FROM system.tables"
 encoded_query = quote(query)
 test_url = f"{base_url}/?query={encoded_query}"
 
 req = Request(test_url)
 ctx = create_ssl_context()
 
 with urlopen(req, timeout=timeout, context=ctx) as response:
 if response.getcode() == 200:
 data = response.read().decode('utf-8', errors='ignore')
 table_count = int(data.strip())
 return True, table_count, None
 except HTTPError as e:
 error_msg = e.read().decode('utf-8', errors='ignore')
 return False, 0, error_msg
 
 return False, 0, None
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a target for ClickHouse authentication bypass
cxg scan --scope clickhouse.example.com --ports 8123 --templates clickhouse-auth-bypass.py

# Scan with default HTTP port
cxg scan --scope clickhouse.example.com --templates clickhouse-auth-bypass.py

# Scan HTTPS ClickHouse (port 8443)
cxg scan --scope clickhouse.example.com --ports 8443 --templates clickhouse-auth-bypass.py

# JSON output
cxg scan --scope clickhouse.example.com --templates clickhouse-auth-bypass.py --output-format json
```

### Direct Template Execution

```bash
# Run the Python template directly
export CERT_X_GEN_TARGET_HOST=clickhouse.example.com
export CERT_X_GEN_TARGET_PORT=8123
python3 clickhouse-auth-bypass.py
```

### Expected Output (Vulnerable - HIGH Severity)

```json
{
 "findings": [{
 "template_id": "clickhouse-auth-bypass",
 "template_name": "ClickHouse Authentication Bypass",
 "severity": "high",
 "cvss_score": 8.6,
 "host": "118.25.14.157",
 "port": 8123,
 "protocol": "http",
 "description": "ClickHouse HTTP interface on 118.25.14.157:8123 allows unauthenticated access. Queries execute without credentials, exposing database operations. System tables accessible - 132 tables enumerated.",
 "evidence": {
 "url": "http://118.25.14.157:8123",
 "clickhouse_version": "unknown",
 "server_name": "81f5ec6295ae",
 "test_query": "SELECT 1",
 "test_response": "1\\n",
 "status_code": 200,
 "system_table_access": true,
 "accessible_tables": 132
 }
 }]
}
```

### Expected Output (Not Vulnerable)

```json
{
 "findings": []
}
```

---

## Real-World Test Results

The template was tested against live ClickHouse instances discovered via FOFA in January 2026:

| Target IP | Port | Service Detected | Auth Bypass | Tables Found | Status |
|-----------|------|------------------|-------------|--------------|--------|
| 118.25.14.157 | 8123 | | VULNERABLE | 132 | CRITICAL |
| 185.218.21.253 | 8123 | | | 0 | SECURE |
| 39.98.62.208 | 8123 | | | 0 | SECURE |
| 94.130.12.239 | 8123 | | | 0 | SECURE |
| 116.198.36.114 | 8123 | | | 0 | SECURE |

**Detection Success Rate**: 20% (1 vulnerable out of 5 tested)

**Key Findings:**

1. **Service Detection**: All 5 targets correctly identified as ClickHouse
2. **Authentication Testing**: Successfully distinguished authenticated vs. unauthenticated
3. **System Table Access**: Verified full database access on vulnerable instance
4. **Zero False Positives**: No false alarms on secured instances
5. **Graceful Failure**: Handled timeouts and network errors appropriately

### Vulnerable Instance Deep Dive (118.25.14.157)

**Evidence Collected:**
```
Server: 81f5ec6295ae (Docker container ID)
Unauthenticated Query: SELECT 1 → Returned: 1
System Tables Query: SELECT count() FROM system.tables → Returned: 132
Status: VULNERABLE - Full database access without credentials
```

**Impact:**
- Complete read access to all 132 system tables
- Ability to enumerate databases, tables, columns
- Potential data exfiltration
- Risk of data modification or deletion

---

## Defense & Remediation

### Secure Configuration

#### Step 1: Set a Password for Default User

Edit `/etc/clickhouse-server/users.xml`:

```xml
<!-- SECURE: Configure password for default user -->
<yandex>
 <users>
 <default>
 <!-- Set a strong password -->
 <password>YourStrongPasswordHere</password>
 
 <!-- Or use SHA256 hash -->
 <password_sha256_hex>hash_of_your_password</password_sha256_hex>
 
 <!-- Restrict to localhost only -->
 <networks>
 <ip>127.0.0.1/8</ip>
 <ip>::1</ip>
 </networks>
 
 <profile>default</profile>
 <quota>default</quota>
 </default>
 </users>
</yandex>
```

#### Step 2: Create Dedicated Users with Strong Auth

```xml
<users>
 <!-- Application user with limited permissions -->
 <app_user>
 <password_sha256_hex>...</password_sha256_hex>
 <networks>
 <ip>10.0.0.0/8</ip> <!-- Private network only -->
 </networks>
 <profile>readonly</profile>
 <quota>default</quota>
 <!-- Read-only access -->
 <access_management>0</access_management>
 </app_user>
</users>
```

#### Step 3: Restrict Network Access

Edit `/etc/clickhouse-server/config.xml`:

```xml
<!-- SECURE: Listen only on specific interfaces -->
<yandex>
 <!-- Bind to localhost only -->
 <listen_host>127.0.0.1</listen_host>
 <listen_host>::1</listen_host>
 
 <!-- Or bind to specific private IP -->
 <!-- <listen_host>10.0.1.100</listen_host> -->
 
 <!-- Enable TLS for external access -->
 <https_port>8443</https_port>
</yandex>
```

#### Step 4: Enable TLS/SSL

```xml
<openSSL>
 <server>
 <certificateFile>/etc/clickhouse-server/server.crt</certificateFile>
 <privateKeyFile>/etc/clickhouse-server/server.key</privateKeyFile>
 <dhParamsFile>/etc/clickhouse-server/dhparam.pem</dhParamsFile>
 <verificationMode>relaxed</verificationMode>
 <loadDefaultCAFile>true</loadDefaultCAFile>
 <cacheSessions>true</cacheSessions>
 <disableProtocols>sslv2,sslv3</disableProtocols>
 <preferServerCiphers>true</preferServerCiphers>
 </server>
</openSSL>
```

### Defense Checklist

**Authentication:**
- Set passwords for all users
- Use SHA256 password hashes
- Implement X.509 certificate auth for production
- Disable default user or set strong password

**Network Security:**
- Bind to localhost or private IPs only
- Use firewall rules to restrict access
- Enable TLS/SSL on port 8443
- Disable insecure HTTP port 8123

**Access Control:**
- Create role-based users with minimal privileges
- Implement IP whitelisting
- Use read-only profiles for analytics users
- Enable query logging and auditing

**Monitoring:**
- Log all authentication attempts
- Alert on failed login attempts
- Monitor for suspicious query patterns
- Track database access from unexpected IPs

### Verification Commands

After remediation, verify security:

```bash
# Test 1: Unauthenticated query should fail
curl 'http://localhost:8123/?query=SELECT 1'
# Expected: Code: 516. DB::Exception: Authentication failed

# Test 2: With credentials should succeed
curl -H 'X-ClickHouse-User: myuser' \
 -H 'X-ClickHouse-Key: mypassword' \
 'http://localhost:8123/?query=SELECT 1'
# Expected: 1

# Test 3: External access should be blocked
curl 'http://external-ip:8123/ping'
# Expected: Connection refused or timeout
```

---

## Extending the Template

### Adding Custom Query Tests

```python
# Add custom SQL queries to test
custom_queries = [
 "SELECT version()",
 "SELECT name FROM system.databases",
 "SELECT name, engine FROM system.tables LIMIT 5",
]

for query in custom_queries:
 success, status, data, headers = test_unauthenticated_query(base_url, query)
 if success:
 findings.append({"query": query, "result": data})
```

### Testing Alternative Authentication Methods

```python
def test_with_headers(base_url, user, password):
 """Test with X-ClickHouse-User and X-ClickHouse-Key headers."""
 req = Request(f"{base_url}/?query=SELECT 1")
 req.add_header('X-ClickHouse-User', user)
 req.add_header('X-ClickHouse-Key', password)
 # ...
```

### Supporting Additional Ports

```python
# Test multiple common ClickHouse ports
ports = [8123, 8443, 9000, 9009, 9363]
for port in ports:
 finding = detect_auth_bypass(host, port)
 if finding:
 findings.append(finding)
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: ClickHouse Security Scan
 run: |
 cxg scan \
 --scope ${{ secrets.CLICKHOUSE_HOST }} \
 --ports 8123 \
 --templates clickhouse-auth-bypass.py \
 --output-format sarif \
 --output clickhouse-results.sarif
```

---

## References

### Official Documentation

1. [ClickHouse HTTP Interface](https://clickhouse.com/docs/interfaces/http)
2. [ClickHouse User Management](https://clickhouse.com/docs/guides/sre/user-management/users-and-roles)
3. [ClickHouse Security Best Practices](https://clickhouse.com/docs/operations/security)
4. [ClickHouse Network Configuration](https://altinitydb.medium.com/locking-down-clickhouse-networking)

### Security Research

1. ClickHouse MCP Unauthorized Access (Issue #68, 2025)
2. JFrog Security: 7 RCE and DoS Vulnerabilities in ClickHouse (2021)
3. Wiz Security: Securing Cloud Databases with ClickHouse (2025)

### CVE Database

| CVE | Component | Description |
|-----|-----------|-------------|
| CVE-2021-42387 | LZ4 codec | Heap out-of-bounds read |
| CVE-2021-42388 | LZ4 codec | Heap out-of-bounds read |
| CVE-2021-42389 | Delta codec | Divide by zero |
| CVE-2023-44487 | HTTP/2 | Rapid reset attack |
| CVE-2024-22412 | Query cache | Improper authorization |

### Additional Resources

- [Building Single Page Apps with ClickHouse](https://clickhouse.com/blog/building-single-page-applications-with-clickhouse-and-http)
- [FOFA Cyber Threat Intelligence](https://en.fofa.info)
- [OWASP Missing Authentication](https://owasp.org/www-community/vulnerabilities/Missing_Authentication)

---

