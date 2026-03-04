---
title: "GraphQL Batching Denial-of-Service Detection"
slug: "graphql-batching-dos-detection"
date: "2026-03-04"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Detect GraphQL endpoints vulnerable to batching denial-of-service attacks."
category: "web-application-security"
---

# GraphQL Batching Denial of Service Detection

## Executive Summary

GraphQL's batching feature, while powerful for legitimate use cases, can be exploited to cause Denial of Service (DoS) attacks when proper controls are missing. Unlike REST APIs where each endpoint is a separate HTTP request, GraphQL allows sending multiple queries in a single request—potentially hundreds or thousands.

**The vulnerability exists when:**
- No limit on the number of queries per batch
- Missing query complexity scoring
- No rate limiting on batch operations
- Exponential resource consumption patterns

> **Key Insight**: Detecting GraphQL batching vulnerabilities requires dynamic JSON payload construction, response time measurement with statistical analysis, and incremental testing with configurable limits—exactly what CERT-X-GEN's Python templates excel at.

### Quick Stats

| Metric | Value |
|--------|-------|
| **CVSS Score** | 7.5 (High) |
| **CWE** | CWE-770 (Resource Allocation Without Limits), CWE-400 (Uncontrolled Resource Consumption) |
| **OWASP API** | API4:2023 - Unrestricted Resource Consumption |
| **Detection Complexity** | High (requires timing analysis) |
| **Exploitation Difficulty** | Low (simple batch payloads) |

---


> **Run this check with CERT-X-GEN** — the polyglot security scanner that executes templates in real programming languages. [Get the templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) | [Install CERT-X-GEN](https://github.com/Bugb-Technologies/cert-x-gen)
>
> **Related templates:** [`web/graphql/`](https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/web/graphql) *(dedicated batching DoS template coming soon)*

## Understanding the Vulnerability

### How GraphQL Batching Works

GraphQL supports two types of query batching:


#### Array-Based Batching (Most Common)

```json
// Single HTTP POST with multiple queries
[
 { "query": "{ user(id: 1) { name } }" },
 { "query": "{ user(id: 2) { name } }" },
 { "query": "{ user(id: 3) { name } }" },
 // ... potentially thousands more
]
```

#### Alias-Based Batching

```graphql
# Single query with multiple aliased operations
query BatchedQuery {
 user1: user(id: 1) { name email }
 user2: user(id: 2) { name email }
 user3: user(id: 3) { name email }
 # ... many more aliases
}
```

### The Attack Scenario

```
┌─────────────────────────────────────────────────────────────────┐
│ GRAPHQL BATCHING DoS ATTACK │
├─────────────────────────────────────────────────────────────────┤
│ │
│ ATTACKER TARGET SERVER │
│ │ │ │
│ │ Single HTTP Request with 10,000 queries │ │
│ │ ─────────────────────────────────────────▶ │ │
│ │ │ │
│ │ Server attempts to execute ALL queries │ │
│ │ │ │
│ │ ┌───────────────────────┐ │ │
│ │ │ CPU: 100% │ │ │
│ │ │ Memory: Exhausted │ │ │
│ │ │ DB Connections: Max │ │ │
│ │ │ Response: TIMEOUT │ │ │
│ │ └───────────────────────┘ │ │
│ │ │ │
│ │ Result: Service unavailable for all users │ │
│ │ │ │
└─────────────────────────────────────────────────────────────────┘
```

### Impact Scenarios

| Scenario | Impact | Real-World Example |
|----------|--------|-------------------|
| **Service Outage** | Complete unavailability | API crashes under batch load |
| **Database Overload** | Connection pool exhaustion | Thousands of concurrent DB queries |
| **Memory Exhaustion** | OOM killer invoked | Large response objects in memory |
| **Cloud Cost Amplification** | Massive billing spike | Pay-per-request serverless functions |
| **Cascading Failures** | Downstream services affected | Microservices architecture collapse |

---

## Why Traditional Scanners Fail

### Limitations of YAML-Based Detection

YAML-based scanners like Nuclei face fundamental limitations when detecting GraphQL batching vulnerabilities:

```yaml
# What YAML CANNOT do:

# 1. Dynamic JSON payload construction with variable batch sizes
# 2. Response time measurement and statistical analysis
# 3. Incremental testing with configurable limits
# 4. Complex introspection query parsing
# 5. Rate analysis and degradation detection
# 6. Timing correlation across multiple requests
```

### The Detection Challenge


| Detection Task | YAML Capability | Python Capability |
|----------------|-----------------|-------------------|
| Send batch payload | Static only | Dynamic construction |
| Measure response time | Not supported | High-precision timing |
| Statistical analysis | Not supported | Mean, variance, correlation |
| Incremental testing | Fixed payloads | Configurable batch sizes |
| Rate limiting detection | Not supported | Response code analysis |
| Introspection parsing | Pattern match only | Full JSON parsing |

---

## The CERT-X-GEN Approach

### Why Python Excels Here

CERT-X-GEN's Python template provides capabilities impossible in YAML:

```python
# What CERT-X-GEN Python templates CAN do:

# 1. Dynamic batch payload construction
batch_payload = [{"query": query} for _ in range(batch_size)]

# 2. High-precision timing measurement
start = time.perf_counter()
response = session.post(url, json=batch_payload)
elapsed = time.perf_counter() - start

# 3. Statistical analysis of timing data
baseline = statistics.mean(baseline_times)
degradation_factor = avg_batch_time / baseline

# 4. Incremental batch testing
for size in [2, 5, 10, 25, 50]:
 response = test_batch_size(size)
 analyze_response(response)

# 5. Intelligent endpoint discovery
for endpoint in GRAPHQL_ENDPOINTS:
 if test_introspection(endpoint):
 return endpoint
```

### Detection Methodology

```
┌────────────────────────────────────────────────────────────────┐
│ CERT-X-GEN DETECTION METHODOLOGY │
├────────────────────────────────────────────────────────────────┤
│ │
│ PHASE 1: ENDPOINT DISCOVERY │
│ ┌─────────────────────────────────────────────┐ │
│ │ Test common GraphQL paths: │ │
│ │ /graphql, /api/graphql, /v1/graphql... │ │
│ │ Verify with introspection query │ │
│ └─────────────────────────────────────────────┘ │
│ ↓ │
│ PHASE 2: BATCH SUPPORT DETECTION │
│ ┌─────────────────────────────────────────────┐ │
│ │ Test array-based batching [query1, query2] │ │
│ │ Test alias-based batching (q1: q2: q3:) │ │
│ │ Identify batch size limits │ │
│ └─────────────────────────────────────────────┘ │
│ ↓ │
│ PHASE 3: TIMING ANALYSIS │
│ ┌─────────────────────────────────────────────┐ │
│ │ Establish baseline (single query) │ │
│ │ Measure times for batch sizes: 2,5,10,25 │ │
│ │ Calculate degradation factor │ │
│ └─────────────────────────────────────────────┘ │
│ ↓ │
│ PHASE 4: VULNERABILITY ANALYSIS │
│ ┌─────────────────────────────────────────────┐ │
│ │ Check for unlimited batch sizes │ │
│ │ Detect missing rate limiting │ │
│ │ Identify exponential scaling │ │
│ │ Report findings with evidence │ │
│ └─────────────────────────────────────────────┘ │
│ │
└────────────────────────────────────────────────────────────────┘
```

---

## Attack Flow Visualization

### Resource Consumption Patterns


```
RESPONSE TIME vs BATCH SIZE

Response │
Time (ms) │ ╭──── Exponential (CRITICAL)
 │ ╭──╯
 2000 │ ╭──╯
 │ ╭──╯
 1500 │ ╭──╯
 │ ╭──╯
 1000 │ ╭──╯ ╭────────── Linear (WARNING)
 │ ╭──╯ ╭───╯
 500 │ ╭──╯ ╭───╯
 │ ╭──╯ ╭───╯ ╭──────── Constant (SAFE)
 100 │─────────────────────────────────────
 │ ╭───╯
 0 └────┴────┴────┴────┴────┴────┴────▶
 1 5 10 25 50 100 Batch Size

VULNERABILITY CLASSIFICATION:
 - Constant: Server has proper limits 
 - Linear: Some risk, predictable 
 - Exponential: Critical vulnerability 
```

### Batch Attack Amplification

```
┌─────────────────────────────────────────────────────────────────┐
│ AMPLIFICATION FACTOR │
├─────────────────────────────────────────────────────────────────┤
│ │
│ Traditional REST: │
│ 1 HTTP Request = 1 Database Query = 1x Resource Use │
│ │
│ Vulnerable GraphQL (1000 batch): │
│ 1 HTTP Request = 1000 Database Queries = 1000x Resource Use │
│ │
│ Amplification Factor: 1000x per request! │
│ │
│ Attack Economics: │
│ - Attacker bandwidth: 1 KB (single request) │
│ - Server processing: 1000x normal load │
│ - Asymmetric advantage: Extreme │
│ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template Deep Dive

### Core Detection Classes

```python
class GraphQLBatchingDoSTemplate:
 """
 CERT-X-GEN Template for GraphQL Batching DoS Detection
 
 ETHICAL BOUNDARY: This template performs safe detection only.
 - Uses small batch sizes (max 50) for testing
 - Measures timing with minimal requests
 - Does NOT attempt to crash or overwhelm services
 """
 
 def __init__(self):
 # Configuration - conservative for safe detection
 self.batch_test_sizes = [2, 5, 10, 25, 50] # Small increments
 self.timing_samples = 3 # Samples per batch size
 self.max_batch_size = 50 # Hard limit for ethical testing
```

### Endpoint Discovery Logic

```python
GRAPHQL_ENDPOINTS = [
 '/graphql',
 '/api/graphql',
 '/v1/graphql',
 '/v2/graphql',
 '/query',
 '/gql',
 '/graphiql',
 '/__graphql',
 '/playground',
]

def _discover_graphql_endpoint(self, session, base_url):
 """
 Discover GraphQL endpoint by testing common paths.
 Uses introspection query to verify GraphQL support.
 """
 for endpoint in GRAPHQL_ENDPOINTS:
 url = f"{base_url}{endpoint}"
 response = session.post(url, json={"query": INTROSPECTION_QUERY})
 
 if response.status_code == 200:
 data = response.json()
 if 'data' in data and data['data'] is not None:
 return url # Found valid GraphQL endpoint
 return None
```

### Batch Support Detection


```python
def create_batch_payload(query: str, count: int, use_aliases: bool = True):
 """Create a batch of GraphQL queries."""
 if use_aliases:
 # Array-based batching (most common)
 return [{"query": query} for _ in range(count)]
 else:
 # Single query with multiple aliases
 aliased_queries = []
 for i in range(count):
 aliased_queries.append(f"q{i}: __typename")
 combined_query = "query {{ {0} }}".format(" ".join(aliased_queries))
 return {"query": combined_query}
```

### Timing Degradation Analysis

```python
def _measure_timing_degradation(self, session, graphql_url):
 """
 Measure response time degradation with increasing batch sizes.
 SAFETY: Uses small batch sizes and minimal samples.
 """
 result = {
 'baseline_time': None,
 'batch_timings': {},
 'degradation_factor': None,
 'linear_scaling': False,
 'exponential_scaling': False,
 'rate_limiting_detected': False,
 }
 
 # Baseline: single query timing
 baseline_times = []
 for _ in range(self.timing_samples):
 elapsed, response = measure_request_time(session, url, single_query)
 if elapsed is not None:
 baseline_times.append(elapsed)
 
 result['baseline_time'] = statistics.mean(baseline_times)
 
 # Test increasing batch sizes
 for size in [2, 5, 10, 25]:
 batch_payload = create_batch_payload(query, size)
 elapsed, response = measure_request_time(session, url, batch_payload)
 
 if response.status_code == 429:
 result['rate_limiting_detected'] = True
 break
 
 result['batch_timings'][size] = {
 'avg_time': elapsed,
 'ratio_to_baseline': elapsed / result['baseline_time']
 }
 
 return result
```

---

## Usage Guide

### Basic Usage

```bash
# Scan a single target
python3 graphql-batching-dos.py api.example.com

# Specify custom port
python3 graphql-batching-dos.py api.example.com --port 8080

# JSON output for automation
python3 graphql-batching-dos.py api.example.com --json

# Verbose mode with evidence
python3 graphql-batching-dos.py api.example.com --verbose
```

### Using with CERT-X-GEN CLI

```bash
# Basic scan with extended timeout (recommended)
cxg scan --scope api.example.com \
 --templates templates/web/graphql/graphql-batching-dos.py \
 --timeout 90s

# Scan multiple targets
cxg scan --scope @graphql-targets.txt \
 --templates templates/web/graphql/graphql-batching-dos.py \
 --timeout 90s \
 --output-format json

# Filter by severity
cxg scan --scope api.example.com \
 --templates templates/web/graphql/graphql-batching-dos.py \
 --severity high,medium,critical \
 --timeout 90s
```

### Environment Variables

```bash
# Set target via environment
export CERT_X_GEN_TARGET_HOST="api.example.com"
export CERT_X_GEN_TARGET_PORT="443"
python3 graphql-batching-dos.py

# Engine mode for JSON output
export CERT_X_GEN_MODE="engine"
python3 graphql-batching-dos.py api.example.com
```

---

## Real-World Test Results

### Test 1: Rick and Morty API (rickandmortyapi.com)

```
┌─────────────────────────────────────────────────────────────────┐
│ TARGET: rickandmortyapi.com │
│ RESULT: MEDIUM - No Rate Limiting Detected │
├─────────────────────────────────────────────────────────────────┤
│ │
│ Batch Support: │
│ ├─ Array batching: Supported │
│ ├─ Max batch accepted: 25 queries │
│ └─ Batch limit: None detected │
│ │
│ Timing Analysis: │
│ ├─ Baseline (1 query): 0.184s │
│ ├─ 2 queries: 0.202s (1.1x) │
│ ├─ 5 queries: 0.258s (1.4x) │
│ ├─ 10 queries: 0.315s (1.7x) │
│ └─ 25 queries: 0.408s (2.2x) │
│ │
│ Findings: │
│ └─ No HTTP 429 (Too Many Requests) observed │
│ └─ No apparent request throttling │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Test 2: Countries API (countries.trevorblades.com)


```
┌─────────────────────────────────────────────────────────────────┐
│ TARGET: countries.trevorblades.com │
│ RESULT: INFO - Adequate Protection Detected │
├─────────────────────────────────────────────────────────────────┤
│ │
│ Batch Support: │
│ ├─ Array batching: Not supported │
│ ├─ Alias batching: Supported (limited to 5) │
│ └─ Batch limit: Enforced │
│ │
│ Analysis: │
│ └─ Server properly limits batch operations │
│ └─ Alias-based batching shows controlled behavior │
│ └─ No exponential resource consumption detected │
│ │
│ Conclusion: │
│ └─ This endpoint has adequate DoS protections in place │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Sample JSON Output

```json
{
 "template_id": "graphql-batching-dos",
 "severity": "medium",
 "confidence": 85,
 "title": "GraphQL Batch Query - No Rate Limiting Detected",
 "description": "GraphQL endpoint accepts batch queries without apparent rate limiting.",
 "evidence": {
 "graphql_endpoint": "https://rickandmortyapi.com/graphql",
 "batch_support": {
 "supported": true,
 "array_batching": true,
 "max_batch_accepted": 25
 },
 "timing_analysis": {
 "baseline_time": 0.184,
 "batch_timings": {
 "2": {"avg_time": 0.202, "ratio_to_baseline": 1.1},
 "5": {"avg_time": 0.258, "ratio_to_baseline": 1.4},
 "10": {"avg_time": 0.315, "ratio_to_baseline": 1.71},
 "25": {"avg_time": 0.408, "ratio_to_baseline": 2.21}
 },
 "rate_limiting_detected": false
 }
 },
 "cwe": ["CWE-770", "CWE-400"],
 "cvss_score": 7.5
}
```

---

## Defense & Remediation

### Recommended Controls

```
┌─────────────────────────────────────────────────────────────────┐
│ DEFENSE-IN-DEPTH STRATEGY │
├─────────────────────────────────────────────────────────────────┤
│ │
│ LAYER 1: BATCH LIMITS │
│ ┌─────────────────────────────────────────────┐ │
│ │ ■ Maximum queries per batch: 10-25 │ │
│ │ ■ Return 400 Bad Request for oversized │ │
│ │ ■ Enforce per-request query limit │ │
│ └─────────────────────────────────────────────┘ │
│ │
│ LAYER 2: QUERY COMPLEXITY │
│ ┌─────────────────────────────────────────────┐ │
│ │ ■ Assign cost to each field │ │
│ │ ■ Maximum depth limit: 5-10 levels │ │
│ │ ■ Total query cost threshold │ │
│ └─────────────────────────────────────────────┘ │
│ │
│ LAYER 3: RATE LIMITING │
│ ┌─────────────────────────────────────────────┐ │
│ │ ■ Per-IP rate limiting │ │
│ │ ■ Per-user rate limiting (authenticated) │ │
│ │ ■ Return HTTP 429 when exceeded │ │
│ └─────────────────────────────────────────────┘ │
│ │
│ LAYER 4: TIMEOUTS │
│ ┌─────────────────────────────────────────────┐ │
│ │ ■ Query execution timeout: 5-30 seconds │ │
│ │ ■ Resolver-level timeouts │ │
│ │ ■ Database query timeouts │ │
│ └─────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Examples

#### Apollo Server (Node.js)

```javascript
const { ApolloServer } = require('apollo-server');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
 typeDefs,
 resolvers,
 validationRules: [
 // Limit query depth to 10 levels
 depthLimit(10),
 // Limit query complexity
 createComplexityLimitRule(1000, {
 onCost: (cost) => console.log('Query cost:', cost),
 }),
 ],
 // Limit batch size
 plugins: [
 {
 async requestDidStart() {
 return {
 async parsingDidStart(ctx) {
 if (Array.isArray(ctx.request.query)) {
 if (ctx.request.query.length > 25) {
 throw new Error('Batch size exceeds maximum of 25 queries');
 }
 }
 },
 };
 },
 },
 ],
});
```

#### Express Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const graphqlLimiter = rateLimit({
 windowMs: 60 * 1000, // 1 minute
 max: 100, // 100 requests per minute
 message: { error: 'Too many requests, please try again later.' },
 standardHeaders: true,
 legacyHeaders: false,
});

app.use('/graphql', graphqlLimiter);
```

#### Nginx Configuration

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=graphql:10m rate=10r/s;

location /graphql {
 limit_req zone=graphql burst=20 nodelay;
 limit_req_status 429;
 
 # Maximum request body size (limits batch size)
 client_max_body_size 100k;
 
 proxy_pass http://graphql_backend;
}
```

---

## Ethical Boundaries


### Detection vs Exploitation

This template is designed as a **DETECTION** tool, not an exploitation tool.

```
┌─────────────────────────────────────────────────────────────────┐
│ ETHICAL BOUNDARY NOTICE │
├─────────────────────────────────────────────────────────────────┤
│ │
│ WHAT THIS TEMPLATE DOES: │
│ │
│ ■ Tests if batch queries are accepted │
│ ■ Measures response time with SMALL incremental batches │
│ ■ Checks for query complexity/depth limits │
│ ■ Identifies missing rate limiting │
│ ■ Reports vulnerability indicators │
│ │
│ WHAT THIS TEMPLATE DOES NOT DO: │
│ │
│ ■ Send overwhelming traffic to crash services │
│ ■ Conduct sustained DoS attacks │
│ ■ Exhaust server resources intentionally │
│ ■ Attempt to cause service unavailability │
│ │
│ HARD LIMITS: │
│ │
│ ■ Maximum batch size: 50 queries (conservative) │
│ ■ Timing samples: 3 per batch size │
│ ■ Inter-request delay: 100ms │
│ ■ Total requests: ~20-30 per scan │
│ │
└─────────────────────────────────────────────────────────────────┘
```

### Responsible Disclosure

If you discover a GraphQL batching vulnerability:

1. **Do NOT** attempt to verify exploitation capabilities by sending large batches
2. **Document** the detection findings from this template
3. **Report** through the organization's responsible disclosure program
4. **Allow** reasonable time for remediation before public disclosure
5. **Follow** your organization's security testing policies

---

## Extending the Template

### Adding Custom Endpoints

```python
# Add custom GraphQL endpoints for your target environment
CUSTOM_ENDPOINTS = [
 '/api/v3/graphql',
 '/internal/graphql',
 '/admin/graphql',
]

# Extend the template
class CustomGraphQLBatchingDoS(GraphQLBatchingDoSTemplate):
 def __init__(self):
 super().__init__()
 self.endpoints = GRAPHQL_ENDPOINTS + CUSTOM_ENDPOINTS
```

### Adjusting Timing Parameters

```python
# For more thorough testing (use with caution)
template = GraphQLBatchingDoSTemplate()
template.timing_samples = 5 # More samples
template.batch_test_sizes = [2, 5, 10, 25, 50, 75, 100] # Extended range
```

### Custom Vulnerability Rules

```python
def custom_analysis(self, batch_result, timing_result):
 """Add custom vulnerability detection rules."""
 vulnerabilities = []
 
 # Custom rule: Detect specific timing patterns
 if timing_result.get('degradation_factor', 0) > 5:
 vulnerabilities.append({
 'title': 'Severe Query Amplification Detected',
 'severity': 'critical',
 'description': 'Response time grows 5x faster than batch size increase.'
 })
 
 return vulnerabilities
```

---

## References

### Official Documentation

- [GraphQL Security Best Practices](https://graphql.org/learn/authorization/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [OWASP API Security Top 10 - API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)

### Security Research

- [Apollo GraphQL Security Guide](https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/)
- [How to GraphQL - Security](https://www.howtographql.com/advanced/4-security/)
- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

### Tools and Libraries

- [graphql-depth-limit](https://www.npmjs.com/package/graphql-depth-limit) - Depth limiting for Node.js
- [graphql-query-complexity](https://github.com/slicknode/graphql-query-complexity) - Query complexity analysis
- [graphql-rate-limit](https://www.npmjs.com/package/graphql-rate-limit) - Rate limiting middleware

---

