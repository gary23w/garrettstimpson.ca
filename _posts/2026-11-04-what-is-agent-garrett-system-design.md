---
layout: post
title: "What Is Agent Garrett? Inside the System Design of a Security Agent That Keeps Working After You Log Off"
seo_title: "What Is Agent Garrett? Security Agent System Design"
date: 2026-11-04 18:00:00 -0500
author: Garrett Stimpson
permalink: /posts/2026/11/04/what-is-agent-garrett-system-design/
categories: [agent-garrett, architecture]
tags: [agent-garrett, system-design, mcp, tater-tot, durable-objects, cloudflare-workers, ai-agents, security-automation]
excerpt: "Agent Garrett is a hosted security agent: it watches your websites, monitors your identity, files data-broker removals and answers with evidence, on a schedule, with no browser open. Here is how the whole system works, layer by layer, and why I built it this way."
description: "How Agent Garrett works: one platform Worker, D1, Durable Objects, a private Linux runtime per customer, hosted AI routing and hash-chained evidence receipts."
image: /assets/img/og-card.png
---

I have written about Agent Garrett doing the work: investigating a cloud incident, pulling apart an infostealer installer in a private vault, walking through the setup screen by screen. Every one of those posts left the same question open. What is actually running behind the name?

This post is the answer. I am going to walk the whole system, layer by layer, the way I would explain it to another engineer who is about to build something similar and wants to know where the hard parts are.

![Agent Garrett system design: dashboard and MCP clients reach the Garrett platform Worker, which uses D1 for accounts, billing, authorization and scheduling and runs monitoring, notifications and Live services. Work reaches a private runtime Worker either synchronously or through a per-tenant work journal and dispatcher. The runtime addresses an instance-owned Durable Object that runs a Linux environment with the Go engine, PostgreSQL, a browser and tools, saves checkpoints and memory to R2, and calls Workers AI through a private AI gateway.](/assets/figures/agent-garrett-system-design.png)

*The whole system on one page. The rest of this post walks it from top to bottom.*

## The short version

- **Two ways in.** A web dashboard you can install as an app, and one MCP endpoint at `api.garrettstimpson.ca/mcp`.
- **One platform Worker** authenticates every request and decides which customer it belongs to.
- **D1** holds the source of truth: accounts, plans, authorization and the work schedule.
- **Durable Objects** are where long-running work lives: one per protected website, identity monitor, scam case, chat conversation and workspace.
- **A private Linux workspace per customer** runs the Go *tater-tot* engine with PostgreSQL, a headless browser and 74 native tools. It sleeps when idle and resumes from a checkpoint in R2.
- **Hosted AI** runs on Workers AI behind a private gateway, under a server-owned model policy and per-plan budgets.

Everything runs on Cloudflare's developer platform: Workers, Durable Objects, D1, R2, Containers and Workers AI. There is no fleet of servers to manage, and I did not want one. Managing servers is a job that competes with the actual work.

## The design rules

Five rules shaped almost every decision. I wrote them down before I wrote any code, and I have broken each one exactly once before learning why it was there.

1. **The work continues when you close the tab.** Attacks don't wait for you to be online. An agent that only runs while a browser is open is a demo, not a defense.
2. **Every claim needs a receipt.** A model's summary is not evidence. The tool output it was based on is. If I cannot show you the raw observation behind a conclusion, the conclusion does not ship.
3. **The model never chooses whose data it touches.** Which customer a request belongs to comes from authenticated credentials, never from text a model wrote. This is the one I refuse to negotiate on.
4. **Idle should cost almost nothing.** A full Linux environment per customer only makes sense if it sleeps.
5. **Risky capability needs a human.** Some actions need the owner's explicit approval, and some tools need an approved application.

## 1. Clients: the dashboard and MCP

Most people meet Garrett in the dashboard, which has tabs for scam checks, identity, websites, agent work and chat. It installs as a progressive web app and can push a notification when a chat reply is ready.

The second way in is MCP, the open protocol AI clients use to call external tools. Garrett exposes a single stateless JSON-RPC endpoint. NL-VEIL, Claude (through OAuth) or any other compatible client can list Garrett's tools and call them. Each API key belongs to exactly one workspace, and the database stores only a SHA-256 fingerprint of it, never the key itself. I have written enough infostealer write-ups to know better than to store a plaintext credential in a database.

That makes Garrett two products in one: an agent that works for you, and a tool server your own AI can use.

## 2. The platform Worker: one gate for everything

Every request lands on one Cloudflare Worker. For the browser, it checks the session, the exact origin and a CSRF token on every change. For MCP, it checks the key or OAuth grant, the plan and the rate limit.

The rule that matters most lives here: **the customer is selected by the authenticated credential and nothing else**. Request headers and model-generated arguments cannot point a call at another customer's workspace. Key checks and per-minute MCP limits run in a small Durable Object that belongs to each customer, so one busy account can't slow down authorization for everyone else.

I treated tenant isolation as a structural property, not a check sprinkled through the code. If isolation depends on every developer remembering a filter, it fails the first time someone forgets.

## 3. D1: accounts, billing, authorization and scheduling

Cloudflare D1, a serverless SQLite database, records who you are, which plan you're on, which workspaces and keys you own, what you've authorized, and when each piece of scheduled work is due.

Scheduling is a ledger in the database rather than an external queue. A job is claimed atomically and holds a lease. It stays monitored until the runtime confirms it has actually stopped, so a timed-out lease is never mistaken for finished work. A cron trigger runs every minute and repairs any wake-up that was missed.

That last sentence is the difference between a scheduler and a scheduler you can trust. I have lost count of the distributed systems that assume a lease expiring means the work finished. It usually means the opposite.

## 4. Durable Objects: where the agent keeps working

A Durable Object is a small, single-threaded, stateful actor with its own storage and its own alarm clock. Garrett uses one for each long-lived thing it looks after:

| Object | One for each | What it does |
| --- | --- | --- |
| Website guard | protected website | Runs scheduled checks and opens a scoped case when a tripwire fires |
| Identity check and response task | identity monitor | Collects from enabled sources; a new or changed finding queues one persistent response task |
| Scam case | case | Runs one saved phase per alarm, then scheduled follow-ups |
| Chat session | conversation | Runs one reply at a time, streams its progress and keeps its receipts |
| Work journal | customer | Queues long-running MCP work and holds the results |
| Auth gate | customer | Authorizes keys and counts request limits |
| Workspace container | workspace | Owns the customer's private Linux runtime |

Alarms are the heartbeat. Each object keeps its own state and wakes itself, so an investigation that began at midnight is still moving at 3 a.m., and a restart resumes where it stopped instead of starting over. Pause, close or delete stops future wake-ups.

This is the piece that makes "keeps working after you log off" true rather than marketing. The state and the timer live in the same place, so there is no gap where a scheduled check can quietly vanish.

## 5. Two ways to ask for work

The diagram splits into two paths.

**Synchronous requests** go straight to the private runtime: call a tool, get the result.

**Durable work mode** is for long jobs and unreliable connections. The call is queued in your work journal and Garrett answers at once with a receipt. Your client collects the actual result later with `garrett_work_get`. If your laptop sleeps halfway through an investigation, the work keeps going and the result waits for you.

## 6. A private Linux runtime for every customer

Behind the platform Worker sits a separate, private runtime Worker. For each workspace it reaches one instance-owned Durable Object, which controls a Cloudflare Container running Linux with:

- **The tater-tot engine**, written in Go: Garrett's goal loop, tool router and memory.
- **PostgreSQL**, for findings, facts, task graphs and history.
- **A headless browser and analysis tools**: 74 native tools in the current catalog.

The runtime is built from verified source, and the private source is removed from the container once the build is done. Each workspace has its own runtime credential and its own private storage prefix, so one customer's runtime can't read another's state.

When a workspace has nothing to do, it saves a checkpoint to R2 and stops. The next real task restores it. Reading your history, logs or status is answered from saved state without waking compute at all. That is what makes a Linux machine per customer affordable: you pay for the seconds it works, not the hours it waits.

### How tater-tot works a goal

The engine runs a bounded cycle: **recall, pick, act, measure, remember**.

1. Restore the goal's scoped memory and any recent guidance.
2. Let the model pick one allowed tool and its arguments.
3. Re-check the arguments against the tool's schema and the owner's authorization, and record the intent *before* anything runs.
4. Run the tool, record what actually came back, and have the model measure it against the goal.
5. Save what was learned. Then continue on the next heartbeat, or stop for review, a verified finish, a limit or a pause.

Because intent is written first, a crash can never leave a tool run with no record of it. Because steps and model calls are limited, a confused goal stops instead of burning budget. Both of those came from watching early versions do exactly the wrong thing.

## 7. Hosted AI: a private gateway to Workers AI

Garrett's own reasoning runs on Cloudflare Workers AI through a private gateway. The model is set by server policy, not by the browser, and every call is admitted against the plan's budget before it runs and metered after.

Dashboard chat routes each turn:

- A small classification model, **Clef**, decides whether the turn is routine.
- Routine turns go to a fast, inexpensive model, **Qwen3 30B**. A plain greeting skips classification and goes straight there.
- Specialist or uncertain turns go to a stronger chat model, **GLM-5.3 Flash**.

A plain message costs two model calls and a greeting costs one; a turn that uses tools costs more. If Workers AI is briefly out of capacity, the reply waits and retries within the same budget reservation instead of failing.

## 8. Chat that streams from the edge

Most conversations don't need the Linux runtime, so general chats run in their own Durable Object close to you. The reply starts immediately, progress streams as it happens, and a dropped connection picks up from the last frame it received.

Every tool call goes into a **hash-chained receipt log**: each receipt includes the hash of the one before it, so the record of what Garrett checked can't be quietly rewritten. If a reply is interrupted, Garrett never replays it, because its tools may already have run. It marks the reply interrupted and keeps the receipts.

Tools that act on the outside world are proposed, not run. You see the exact tool and inputs, and you describe the authorized target, account and purpose before you confirm.

## 9. Evidence you can trust

Alerts go only to addresses you've verified, and the full evidence stays in the dashboard behind your sign-in. Throughout, Garrett keeps what it observed separate from what it concluded:

- A clean threat-intelligence lookup never establishes that something is safe.
- An identity mention is a lead, not proof of a breach.
- A data-broker listing only counts as gone after Garrett re-checks the page and runs a fresh search.
- A failed tool or an unreadable file is reported as a coverage gap, not silently skipped.

Anyone who has read my malware write-ups knows this is the same discipline I apply to analysis: distinguish what the sample did from what I infer about it. An agent that blurs that line produces confident nonsense, and confident nonsense is worse than no answer.

## Standard and Advanced tooling

The chat security toolkit has 68 tools in nine categories, from vulnerability intelligence and infrastructure lookups to forensics, malware analysis and decoding. Some of them are dual-use by nature. People lookups, dark-web and leak searches, and recon that maps someone else's infrastructure are as useful to a stalker as to a defender.

So access comes in two levels:

- **Standard** comes with every plan: chat, the defensive and reference tools, your own workspace records, and every automated protection workflow.
- **Advanced** adds the people and dark-web tools, active recon, Garrett's full runtime toolset over MCP, and tasks you direct yourself. It is granted by application. You email your use case and who authorized your targets, sign an agreement, and an operator approves it.

The level is enforced on the server at every entry point, not just hidden in the interface, and a change takes effect on your very next request.

## What it does for you

- **Website protection.** Watch availability, page content, DNS and security headers. Investigate changes as a recorded case. For a supported Cloudflare Worker, roll back to a healthy version you approved in advance, then re-check.
- **Identity monitoring.** Scoped public-source monitoring for identities you're authorized to represent, with a separate opt-in for leak-post searches.
- **Data-broker removal.** Garrett prepares deletion and opt-out requests for listings you've confirmed are yours, and sends them as your disclosed agent only after you've signed an authorization and sending is enabled for your account. It isn't a guarantee of removal.
- **Scam checks and recovery.** Paste a message, a link or up to three files. Garrett picks the checks, assesses the evidence, builds a recovery checklist and follows up about 12 and 24 hours later.
- **Research chat.** Ask a security question and get an answer grounded in tool results you can open and inspect.
- **MCP tools.** Bring Garrett's toolkit into the AI you already use, with durable receipts for long jobs.

## Why this stands out in its category

Plenty of products put a chat box in front of a model and call it a security assistant. Garrett's design goes further in specific, checkable ways:

- **It works between your visits.** Alarms, leases and checkpoints keep investigations moving with no browser open.
- **Every customer gets a real Linux environment**, with a database, a browser and dozens of tools, that sleeps when idle and wakes for real work.
- **Its evidence is auditable.** Intent is recorded before action, receipts are hash-chained, and claims are limited to what was actually observed.
- **It's an agent and a tool server at once.** Let it work on its own, or put its tools inside the AI you already use.
- **Isolation is structural.** The customer comes from the credential, and model output can't redirect it.
- **There's no server fleet behind it.** The whole system is built from serverless building blocks.
- **It's priced for individuals.** Plans start at CA$2.99 a month, and automatic protection is included from the CA$4.99 Agent plan.

## Try it

Sign in at [agent.garrettstimpson.ca](https://agent.garrettstimpson.ca), or connect an MCP client to `https://api.garrettstimpson.ca/mcp` with a workspace key. If your work needs Advanced tooling, email [info@garrettstimpson.ca](mailto:info@garrettstimpson.ca) with your use case.

*This describes the system as implemented on 4 November 2026. Some sources and providers depend on configuration, and observations are always last-known evidence rather than a guarantee.*
