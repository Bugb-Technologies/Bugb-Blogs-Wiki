---
title: "GuardLink: Threat Modeling in Your Code, Not a Forgotten Document"
slug: "guardlink-threat-modeling-in-your-code"
date: "2026-10-14"
author: "Shahid Parvez Hakim"
authorTitle: "Founder & CEO, BugB Technologies"
excerpt: "GuardLink maps where untrusted input reaches sensitive actions and writes that map into your codebase. Developers and security share the context, from the repo to the pull request."
category: "company"
image: "https://e5bnabdufegbkfuq.public.blob.vercel-storage.com/blogs/guardlink-intro/cover.png"
---

# GuardLink: Threat Modeling in Your Code, Not a Forgotten Document

## Summary

A user sends your application a value. What can that value make the application do?

That is a useful starting point for threat modeling. You follow input from outside the system and ask whether it can reach something sensitive: a file, another server, a command, or a database query.

Then you ask what stops it from doing harm.

**GuardLink is an open-source tool that puts this map into the codebase itself.** Developers and security can read the same map in the repository and see its annotations in pull requests and CI—the automated checks around code changes.

The model lives where the work happens.

## Follow the Input, Not Just the Function Name

Consider an illustrative example: a SaaS application lets a user provide a URL so it can import a document.

The route accepts the URL. A helper passes it to another function. That function makes an outbound request.

Each function might look ordinary on its own. The security question lies in the connection: **can a user's URL cause the server to request a destination it should not reach?**

For a founder, the concern is whether a convenient import feature creates an unintended route into sensitive systems. For a developer, the next questions are concrete. Where is the destination checked? Does that check apply to this path? Can the input reach the request without passing through it?

GuardLink reads source code and follows those flows. It marks places where user-controlled data reaches a sensitive action without a control in the way, or where a control exists but may not cover the path.

That gives a reviewer somewhere specific to look.

## Put the Model Beside the Change

A separate threat-model document can be useful. But a developer reviewing a code change should not have to reconstruct its security context from a document elsewhere.

GuardLink writes its threat model into the codebase. Its annotations live in the repository, so they can appear alongside the work in pull requests and CI.

This changes the conversation:

- **The developer** can see the input path and the sensitive action under discussion.
- **The security reviewer** can examine the same code and ask whether the control covers that path.
- **Both** can discuss the proposed change using shared context rather than separate descriptions of the system.

This is what shifting security left should mean: bringing the security question into the code review, while the people changing the code are already there.

Not another warning handed over after the decision has been made.

## A Map Is Not a Verdict

A marked path is a reason to investigate. It is not proof that an attacker can exploit the application.

The running app may enforce a control that the source-level analysis has not established. A path may depend on access or conditions that need to be tested. The import example above is a question, not a claimed vulnerability.

**GuardLink maps where to look. It does not confirm exploits.**

That boundary is important. Calling every suspicious flow a confirmed issue creates noise. Calling an untested control effective creates false confidence. Neither helps the team make a good decision.

## From a Shared Map to a Tested Fix

The next step is to test the threat against a running copy of the application.

Cert-X-Gen, also open source, uses live probes and browser automation to confirm or refute threats through observed behavior. It supports authenticated testing with session state and request headers. Bravos orchestrates the larger loop, from environment setup and mapping to live testing and reporting.

In our illustrative import workflow, GuardLink identifies the path to the outbound request. Live testing then asks whether that path actually permits the unwanted request. After a change, testing can check whether the same behavior is blocked.

A blocked attempt is evidence about that tested path, not a promise that every possible path is safe.

The useful loop is straightforward: **share the map, test the threat, change the code, test the fix.** GuardLink gives developers and security a common place to start.
