---
layout: post
title: "I had some time on my lunch break so i k*lled ARTEX"
date: 2026-11-14 12:30:00 -0500
categories: [projects, security]
tags: [intrusion-detection, cloudflare-workers, python, d1, agent-garrett, sentinel, artex]
excerpt: "The FBI put out a FLASH on agentic intrusion frameworks, so I built a host intrusion sentinel that ends an attacking program on the spot. Here is how Agent Garrett Sentinel Service works and how to deploy it into your own workflow in about ten minutes."
permalink: /posts/2026/11/14/i-had-some-time-on-my-lunch-break-so-i-killed-artex/
---

The FBI's FLASH-20261113-001 on agentic intrusion frameworks landed recently, and it reads like a product announcement for the other side: ARTEX and friends, web shells, loaders, implants, Kerberoasting at machine pace. The thing those tools have in common is that once they are on a machine, they move in minutes and they never get tired.

So I built the answer on my lunch break (okay, a few lunch breaks): [Agent Garrett Sentinel Service](https://github.com/gary23w/agent-garrett-sentinel-service), a host intrusion sentinel you run yourself. A small agent on each machine watches running programs and their network connections, scores what it sees in plain code, and reports the cases that look like an attack to a service you deploy in your own Cloudflare account. By default it also ends a hostile program, and everything that program started, on the spot. No single vendor holds your telemetry. No packet capture, no file contents read, no listening port.

## How it works

The architecture is deliberately boring, which is why it holds up:

- **The agent** (one Python file, `sentinel_agent.py`) reads the operating system's own process and connection tables. It opens no port, captures no packets, and reads no file contents. It scores everything locally with weighted signals grouped into categories: scripts started by mail or document programs, reverse shells, loaders like `mshta` and `rundll32`, credential dumping, Kerberoasting, fan-out scanning, Tor and Chisel by name, web shells appearing in web folders, bursts on SSH and RDP, and the addresses from the FBI FLASH itself as a scored signal. A case is called HOSTILE only when the evidence spans at least three categories, so no single rule decides it.
- **Only cases leave the machine.** A command line never leaves: the agent reports which pattern matched, not the text. The service re-scores every signal itself, stores the case encrypted (AES-256-GCM), and raises an alert.
- **It acts, within limits.** It never touches OS processes, security software, `sshd`, the web server, or the browser or mail program a person is working in: it ends the harmful thing those programs started, not the programs.
- **One network, not separate machines.** When a program is stopped or an operator confirms an attack, the addresses it called out to are shared with every other enrolled machine for a week, so an attacker's server stopped on one box is a scored signal everywhere else. Turn on `FLEET_BLOCK` and those addresses become unreachable across the whole fleet.
- **The AI part is optional.** Detection, scoring, stopping and learning are all plain code and work with no model at all. If you want a second opinion, one optional model adds a two-sentence analyst summary to every case, and in `decide` mode it settles what happens to a frozen program: stop, release, or hold. It never changes a score and never teaches the policy.

You pick a response mode per deployment or per machine: `kill` (end it at once), `decide` (freeze it, let the model settle it in eight seconds), `pause` (freeze and wait for an operator), or `report` (watch only). The default is `kill`, because an automated intruder works in minutes and a person reading cases does not.

## Deploying it into your workflow

This is the part I care about most, because a defense tool nobody deploys is a blog post. The whole thing fits one Cloudflare Worker and one D1 database in your own account.

**1. The service, about five minutes.** Copy `server/wrangler.example.jsonc` to `server/wrangler.jsonc`, then:

```bash
npx wrangler d1 create sentinel
npx wrangler d1 execute sentinel --remote --file=schema.sql
npx wrangler secret put DATA_KEY      # 32+ random chars, encrypts case evidence at rest
npx wrangler secret put ENROLL_KEY    # 32+ random chars, lets machines enrol
npx wrangler secret put ADMIN_TOKEN   # 32+ random chars, lets operators read cases
npx wrangler deploy
```

That is the entire server. Optional: `ALERT_WEBHOOK_URL` gets a JSON alert for each new case, and `AI_PROVIDER` (Workers AI, any OpenAI-compatible endpoint, or your own analyst service) if you want the model in the loop.

**2. The agents, one line each.** The agent is called `garrett`:

| Machine | Install |
|---|---|
| Linux, macOS | `curl -fsSL https://gary23w.github.io/agent-garrett-sentinel-service/install.sh \| sudo sh` |
| ...joining your fleet | `... \| sudo sh -s -- --server https://your-service --key <enrolment key>` |
| Windows | download `garrett-windows.zip` from the [releases](https://github.com/gary23w/agent-garrett-sentinel-service/releases), unpack, double-click `Install garrett.cmd` |
| Windows, scripted | elevated PowerShell: `irm https://gary23w.github.io/agent-garrett-sentinel-service/install.ps1 \| iex` |
| Kubernetes | apply `deploy/kubernetes-daemonset.yaml`; every node enrols itself as it joins |

Installed with nothing else, garrett already protects the machine it is on and keeps its cases locally (`garrett cases`). Give it a server address and enrolment key and it joins the fleet. On Debian and Ubuntu the installer adds a signed apt repository, so `apt upgrade` keeps it current.

**3. Try it first, no Cloudflare account.** Node 22.5+ and Python 3.9+:

```bash
cd server
export SENTINEL_ENROLL_KEY=$(python3 -c "import secrets;print(secrets.token_hex(24))")
export SENTINEL_ADMIN_TOKEN=$(python3 -c "import secrets;print(secrets.token_hex(24))")
node local.mjs   # in-memory database, for evaluation only
```

Then in a second terminal, enrol an agent against `http://127.0.0.1:8787`, run it, and read `/v1/devices` and `/v1/cases?state=open` with the admin token.

**4. Roll it out sanely.** Start in `report` mode and read what it would have done (`garrett cases`), then move to `decide` or `kill` where a wrong stop is cheap. Run the agent with root or administrator rights where you can: without them it sees only the current user's programs and, on Windows, cannot read the Security log. One service carries roughly 90,000 machines at the default pace; past a few hundred thousand, run one service per region and let `POST /v1/fleet/add` carry attacker addresses between them.

## The honest part

The default is `kill`, and kill is not reversible: a false alarm in kill mode is a stopped program. That is exactly why `decide` exists, why the three-category rule exists, why a program an operator marks "ours" is never touched again, and why you should spend a week in `report` mode first. The status is still draft: the Linux installs, the Kubernetes DaemonSet and the Windows agent have been run; the Windows install as SYSTEM and anything on a Mac have not. Read the "What has and has not been tested" section of the README before you trust it with production.

But the shape of the thing is right: detection happens on the machine and never waits for the network, the service is five commands in your own account, the agent is one line per host, and what one machine learns arms all the others. ARTEX got itself measured against a lunch-break project. It did not go well for ARTEX.
