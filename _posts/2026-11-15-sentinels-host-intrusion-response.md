---
layout: post
title: "Sentinels: stopping machine-speed intrusions on the host"
date: 2026-11-15
author: Garrett Stimpson
categories: [security, open-source]
tags: [sentinels, intrusion-detection, incident-response, ai, endpoint-security]
excerpt: "Sentinels is an open-source host intrusion detection and response agent that can interrupt suspicious processes as an attack starts."
description: "Meet Sentinels, an automated host intrusion detection and response agent for Linux, macOS and Windows, with self-hosted or managed fleet options and optional AI analysis."
---

An automated attack does not wait for someone to read an alert. [CERT-EU has documented](https://www.cert.europa.eu/blog/from-penetration-testing-to-cyber-threat-beware-of-artex) how AI-powered frameworks such as ARTEX can work through long attack chains at scale. Defenders need a way to act while a hostile process is still starting.

That is why I built [Sentinels](https://github.com/gary23w/sentinels). Its `garrett` agent runs on Linux, macOS and Windows and watches what starts on the machine. If a web server launches a shell that downloads a script, the agent can end the shell before the script runs. It records what happened and explains why it acted.

## What happens after detection

Sentinels can end a hostile process tree, quarantine a dropped file, and disable the cron job, Run key or service that would restart it. An operator can inspect the case and restore a mistaken action. The agent also has `pause` and `report` modes for teams that want to review behavior before enabling automatic termination.

Local protection is a single program file. It needs no account, cloud console or kernel module. For several machines, you can run the fleet service on your own hardware and keep the cases there. A managed hosted deployment is also available.

## Where AI fits

The default fast response path uses local detection and does not wait for a model. The fleet service can optionally use a configured AI provider to summarize a case and offer a second opinion. In `decide` mode, Sentinels first freezes a suspicious program, then asks the model whether to stop, release or hold it.

## The timing claims

Current internal benchmarks report about **20 ms** stopping time in rapid process-chain scenarios and **under 5 ms** in selected tool-driven scenarios. These figures describe particular tests, not every machine or every attack. I will add the test setup, timing boundaries, sample size and raw results to the [README](https://github.com/gary23w/sentinels#what-you-get) so others can evaluate and repeat them. The ARTEX reference above describes the threat landscape; it is not a claim that one host agent defeats every ARTEX technique.

The source, installation instructions and removal steps are in the [repository](https://github.com/gary23w/sentinels). The [project site](https://gary23w.github.io/sentinels/) has the current release and manual. Sentinels is MIT licensed. If you try it, I want to hear which behaviors it caught, where it missed, and where it got in your way.
