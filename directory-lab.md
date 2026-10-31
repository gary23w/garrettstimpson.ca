---
layout: doc
title: On-prem directory lab
permalink: /directory-lab/
description: A transparent, reproducible offline directory assessment simulation for Agent Garrett and NL-Veil.
last_modified_at: 2026-10-16
---

# A directory assessment you can inspect

Agent Garrett connects to NL-Veil for authorized security research. To show how a chained assessment should be recorded, we built a small **offline simulation** of an on-prem directory with fictional hosts, a Windows Defender Firewall policy, a mistaken identity delegation, a protected canary, a durable role edge, and defender alerts.

This is a model of decisions and evidence handling. It is **not** a live penetration test or a claim that Garrett bypassed a Microsoft firewall or AI security product.

## The recorded path

| Step | Baseline result | Hardened result |
| --- | --- | --- |
| Read scoped directory inventory | Allowed | Allowed |
| Try the direct workstation route | Blocked by the simulated firewall | Blocked |
| Request the delegated maintenance identity | Allowed because of the lab mistake | Blocked after the delegation is removed |
| Use the permitted management path | Allowed | Not reached |
| Read the protected canary | Reached in the model | Not reached |
| Create a durable role edge | Modeled | Not reached |
| Correlate defender telemetry | Alert raised | Alert raised |

The baseline path reached its synthetic objective **and was detected**. The hardened rerun stopped before the protected record. That gives an assessor both an outcome and a control change to retest.

The [source, report, text recordings, and hash-linked JSON evidence](https://github.com/gary23w/garrettstimpson.ca/tree/main/labs/directory-simulation) are available for review, along with the rendered [simulation overview]({{ '/labs/directory-simulation/' | relative_url }}) and [recorded report]({{ '/labs/directory-simulation/report/' | relative_url }}). Run the lab locally with Node.js 22 or newer; it does not open sockets or alter the machine's directory or firewall.

## What Garrett contributes to a real engagement

The current Agent Garrett service exposes security research and native agent tools through authenticated MCP. NL-Veil can make them available in desktop chat, swarms, and CLI chat. The catalog covers threat and vulnerability intelligence, DNS and certificate research, selected target checks, cloud shell and browser sessions, evidence capture, findings, and retests. Active checks require an authorized target scope and operator policy. A live report must distinguish observed traffic and artifacts from hypotheses and from modeled examples such as this one.

[See the NL-Veil connection guide](/mcp/) · [Open Agent Garrett](https://agent.garrettstimpson.ca)
