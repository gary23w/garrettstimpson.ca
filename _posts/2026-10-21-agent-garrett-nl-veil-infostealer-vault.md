---
layout: post
title: "Inside the Infostealer: Agent Garrett, NL-VEIL, and the Cloudflare Vault"
seo_title: "Inside the Infostealer: NL-VEIL and the Cloudflare Vault"
date: 2026-10-21 17:00:00 -0400
author: Garrett Stimpson
permalink: /posts/2026/10/21/agent-garrett-nl-veil-infostealer-vault/
categories: [security, agent-garrett]
tags: [agent-garrett, nl-veil, mcp, malware-analysis, infostealer, cloudflare, incident-response]
excerpt: "A 92.5 MB installer, 1,387 archive entries, and a credential-output path to Telegram. A closer look at the real MCP calls behind Agent Garrett's latest case film."
description: "Follow Agent Garrett's private Cloudflare vault analysis of a suspicious PDF-viewer installer, presented through an NL-VEIL harness with real MCP results and a 60-second video."
image: /assets/img/agent-garrett-nl-veil-vault-poster.png
video:
  url: /assets/video/agent-garrett-nl-veil-vault.mp4
  poster: /assets/img/agent-garrett-nl-veil-vault-poster.png
  duration: PT1M
---

A suspicious download rarely introduces itself as a credential stealer. It gives you an ordinary reason to trust it: open a document, install a viewer, get back to work. The person clicking it has something else to do. That is the opening these campaigns depend on.

This investigation started while I was looking into suspected ConstructConnect impersonation pages. Along the way, a separate PDF-viewer download needed a closer look. Finding it during the same investigation did not establish that the two were operated by the same people. The installer needed its own evidence trail.

I wanted to know what was inside it, what it was built to collect, and where that information was intended to go. Agent Garrett's MCP tools gave us a way to follow those questions through a private Cloudflare vault, down into the packaged Python code, and out to a documented Telegram send path.

Here is the one-minute version. The rest of this post opens up the steps that go by quickly on screen.

<figure class="agent-demo" style="margin: 2rem 0;">
  <video controls playsinline preload="metadata" width="1920" height="1080" poster="{{ '/assets/img/agent-garrett-nl-veil-vault-poster.webp' | relative_url }}" aria-label="Agent Garrett MCP investigation presented through an NL-VEIL harness, from a goal prompt to Cloudflare vault analysis" style="display:block; width:100%; height:auto; border:1px solid var(--border); border-radius:10px; background:#020705;">
    <source src="{{ '/assets/video/agent-garrett-nl-veil-vault.mp4' | relative_url }}" type="video/mp4">
    <track kind="captions" src="{{ '/assets/video/agent-garrett-nl-veil-vault.vtt' | relative_url }}" srclang="en" label="English">
    Your browser does not support this video. <a href="{{ '/assets/video/agent-garrett-nl-veil-vault.mp4' | relative_url }}">Download the MP4</a>.
  </video>
  <figcaption style="margin-top:.8rem; font-size:.9em;">A 60-second reconstruction of the investigation using verified MCP results and an NL-VEIL harness view. It is an edited explanation, rather than a continuous recording of a live NL-VEIL session or a one-minute performance benchmark. Tool arguments are shortened; bot and administrator numbers are fictional; the token is withheld.</figcaption>
</figure>

[Download the video]({{ '/assets/video/agent-garrett-nl-veil-vault.mp4' | relative_url }}) · [Read the narration]({{ '/assets/video/agent-garrett-nl-veil-vault-transcript.txt' | relative_url }})

## Start with a job the agent can actually finish

“Investigate this” is easy to type. It also leaves a lot unresolved. What counts as a useful result? Should the file be preserved? Are we trying to identify packaging, credential access, an outbound destination, or all three?

The film condenses the investigation's objective into this prompt:

> Preserve this installer in the vault. Trace credential collection and destinations. Return verifiable evidence and uncertainty.

That gives the agent a concrete job. It needs a preserved artifact, an explanation of the relevant code, and a clear account of what the evidence supports. A plausible paragraph about malware would leave that job unfinished.

The NL-VEIL view makes the work visible: capture the file, unpack the archive, dissect the module, trace the arguments, and deliver the evidence. After each result, the next tool call should have a reason. An archive entry leads to a module inspection. A credential command leads to a focused argument trace. Each step answers something the previous step left open.

## What drives what

There are three parts to this workflow.

**NL-VEIL supplies the goal and tool-driving harness shown in the walkthrough.** It organizes the objective into steps and uses structured tool calls and returned evidence to move the plan forward. The short “observed” and “next action” panels summarize those decisions for the viewer.

**Agent Garrett supplies the security tooling through MCP.** MCP is the connection that lets an agent ask for a named operation with specific arguments and receive a structured result. The call, its arguments, its success or failure, and the returned evidence can be inspected. Garrett's runtime also carries NL-VEIL-derived planning and goal-loop behavior; authentication, tenant isolation, and permission enforcement remain Garrett's responsibility.

**Cloudflare supplies the service and storage boundary used here.** A Worker routes the authorized request to the private sample-vault service. R2 holds the preserved file. The inspection tools operate on that stored artifact and return bounded static findings through MCP.

That arrangement matters when the thing being examined might steal passwords. During this analysis, the sample stayed in the private Worker/R2 workflow. It was not downloaded to the analyst's computer or executed there. Later calls could refer to its hash instead of collecting it again.

## The run, step by step

### 1. Capture the complete installer

The recorded ingestion operation used `file_analyze` in `isolated_large` mode. In shortened form:

```json
{
  "name": "file_analyze",
  "arguments": {
    "mode": "isolated_large",
    "url": "[AUTHORIZED SAMPLE URL]"
  }
}
```

The source address is withheld in this public walkthrough. Ingestion requires an allowed target and the appropriate instance permissions.

The vault preserved **92,519,542 bytes**, roughly 92.5 MB, and calculated the file's SHA-256:

```text
344fd947fa5740d429c38d1b9cea214963edecb87cef5fb20961f78b05cc7dd5
```

The full-file receipt was the foundation for everything that followed. We could ask later questions about the same bytes and keep the results attached to an exact artifact. A clipped text preview would not have been enough to describe the contents of this installer.

### 2. Find the package inside the package

The next operation was `stored_sample_inspect`, using `mode: "archive"` and the preserved hash.

The result identified a **PyInstaller CArchive with 1,387 entries**, a Python version marker of **312**, and **`python312.dll`**. One member, **`remote_admin`**, became the next inspection target.

That changed the direction of the work. We had a Windows installer containing a packaged Python application, with an identifiable module to examine. There was a practical next question: what did that module contain?

### 3. Dissect the module without launching it

The next MCP call selected `remote_admin` from the same stored archive:

```json
{
  "name": "stored_sample_inspect",
  "arguments": {
    "mode": "archive",
    "hash": "344fd947…cc7dd5",
    "name": "remote_admin"
  }
}
```

The hash is shortened above for readability; actual calls use the complete value.

The unpacked member was **159,429 bytes**. The static parser recovered **114 Python code objects**. The resulting structure exposed Telegram configuration and command names associated with password collection, screenshots, and keylogging.

Those findings gave us a much more specific picture of the program. They also needed careful interpretation. A packaged command name or function is evidence of code present in the sample. It does not establish that the command ran successfully on someone's device.

The video uses invented numeric bot and administrator identifiers. The real bot token is not published, and it was not used to access a Telegram account or retrieve anyone's messages.

### 4. Follow the credential-output path

Finding “Telegram” in a file is a lead. To understand its role, we needed to connect the relevant collection code to the send operation.

The focused inspection used:

```json
{
  "name": "stored_sample_inspect",
  "arguments": {
    "mode": "archive",
    "hash": "344fd947…cc7dd5",
    "name": "remote_admin",
    "focus": "cmd_passwords_call_pattern"
  }
}
```

The returned static structure showed Chromium and Firefox extractor call patterns. It connected the accumulated output text to an encoded in-memory `BytesIO` buffer and then to the arguments supplied to Telegram's `send_document` operation.

The useful result can be read as a short chain:

```text
Browser extractor calls
    → output_lines / full_text
    → encoded text in BytesIO(buf)
    → Telegram send_document(chat_id, buf, …)
```

The focused result included these observations:

```text
extractorCallPatterns: chromium=true, firefox=true
bufAssignments source: bytesio_encoded_full_text
firstPositionalChatId: true
secondPositionalBuf: true
```

This was the strongest connection established in the analysis: a static path linking browser-credential collection code to a Telegram document-send call. It gave defenders a mechanism they could investigate, rather than an isolated service name pulled from a strings search.

It remains a static finding. We did not execute the sample, observe a live Telegram delivery, or verify that a particular victim's credentials were stolen.

### 5. Turn the result into something another person can use

The output of an investigation has to survive a handoff. Someone else should be able to see which file was examined, where a conclusion came from, and which questions still need work.

This run produced an exact file identifier, a package description, a module to inspect, code-structure findings, and a documented intended output route. Those pieces can support file-hash searches in authorized telemetry, a closer review of suspicious installer launches, and correlation with other evidence.

If an affected organization establishes that this sample ran, responders can then assess credential exposure and the appropriate account and session recovery steps. A static analysis alone cannot tell them which people were affected.

That is where protecting users becomes concrete. The person on the other end of a stolen account needs a response based on what happened to them. Good evidence helps the responder get there.

## What 170+ tools actually buys you

The platform catalog checked for this walkthrough contained **171 registered tools: 99 research and analysis tools, plus 72 native agent tools**. The tools available to a particular connection depend on its permissions, deployment, and enabled integrations.

That is a substantial amount of capability to put behind a goal. It spans public infrastructure research, DNS and certificate work, vulnerability context, artifact triage, decoding, evidence handling, timelines, and native agent operations. The value comes from being able to move between those jobs while keeping the investigation coherent.

This case used a small, relevant part of that catalog. One preserved file became the basis for several increasingly precise inspections. We did not need 171 calls to make progress. We needed the right calls, a durable artifact, and results detailed enough to justify the next question.

The cloud-backed design also made a difference. The installer did not have to be passed around between chat windows or downloaded repeatedly. The vault held the artifact while the tools returned the parts needed for the current step. The analyst could focus on the evidence instead of moving a suspicious executable between machines.

There is real engineering behind that convenience: authenticated requests, scoped ingestion, tenant-specific storage access, bounded parsers, and tool results that can report a failure or a limit. They are part of the capability. An agent needs to know when a question has not been answered.

## What we can say at the end

We preserved a specific installer, identified its packaged Python application, inspected the relevant module, and documented a static credential-output path to Telegram. The case figures and focused trace were checked against private-vault readbacks on **21 October 2026**.

We did not identify a human operator, prove a link to the ConstructConnect impersonation campaign, verify a victim, confirm successful exfiltration, or establish a takedown. A Telegram identifier would be an investigative lead; it would not, by itself, identify the person behind the operation.

I am proud of what this run shows. Agent Garrett took a substantial artifact and supported a sequence of specific, inspectable questions about it. The result was a useful explanation of how the packaged code was intended to move credential output, with the original file preserved and the unanswered questions still visible.

That is the capability I want people to see in the film: give the agent a clear goal, put real tools behind it, and make the evidence available to the people who have to act on the result. The reason to build all of this is to help protect their accounts, their work, and their private information.

[Connect Agent Garrett to NL-VEIL or another MCP client](/mcp/) · [Open Agent Garrett](https://agent.garrettstimpson.ca) · [Watch the longer setup guide](/posts/2026/10/16/how-to-use-agent-garrett/)
