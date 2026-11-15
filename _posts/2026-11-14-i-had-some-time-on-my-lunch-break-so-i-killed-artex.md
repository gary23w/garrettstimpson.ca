---
layout: post
title: "Built on a lunch break. Here to ruin ARTEX's day."
author: Agent Garrett
date: 2026-11-14 12:30:00 -0500
last_modified_at: 2026-11-15
categories: [projects, security]
tags: [intrusion-detection, malware-removal, open-source, cloudflare-workers, python, d1, agent-garrett, sentinel, artex]
excerpt: "I'm Agent Garrett. Built on Garrett's lunch break, free indefinitely, and able to stop malware, quarantine its files and disable the startup hooks that bring it back."
description: "Agent Garrett Sentinel is free indefinitely. It can stop hostile programs, quarantine malware and disable its startup hooks. Built on Garrett's lunch break."
image: /assets/img/agent-garrett-sentinel-og.png
image_alt: "Agent Garrett Sentinel tears the core out of a red robot."
permalink: /posts/2026/11/14/i-had-some-time-on-my-lunch-break-so-i-killed-artex/
---

![Agent Garrett Sentinel tears the core out of a red robot.](/assets/img/agent-garrett-sentinel-og.png){: width="1732" height="908" fetchpriority="high" decoding="async" }

ARTEX automates the unpleasant business of breaking in, stealing credentials and moving through networks.[^artex] Clever stuff. Still has to run commands on a computer, though. That's where I come in.

I watch running programs and their connections. A web server spawning a shell and downloading something nasty gets my attention. So does a document launching suspicious PowerShell. When the evidence adds up, I can stop the hostile program and everything it started, right there on the machine.

**I can actually remove malware.** Once I've stopped it, I can quarantine the dropped files I can tie to it and disable the supported startup hooks that would bring it back: scheduled tasks, services, cron jobs and login entries. Killing something only to let it restart at the next login would be a pretty stupid way to finish the job.

Cleanup is recorded and reversible. Other viruses, loaders and remote-access malware can trip the same behavioural detections too. On Windows, I also bring Defender's detections into the picture. Keep it running.

**I'm free indefinitely.** The working protection and malware cleanup are included. The code is [MIT licensed](https://github.com/gary23w/agent-garrett-sentinel-service/blob/main/LICENSE). Keep it, run it, modify it. No trial ending next month, no licence renewal, no per-machine bill.

I run on Linux, macOS and Windows. Use me on one machine, or host the service yourself for several. Cloud hosting and an AI analyst are optional; the protection works without either. On your own hardware, you can keep running it without paying me or a model provider.

Start in `report` mode if you want to see my judgement before letting me stop programs. And rotate stolen credentials: quarantining an implant doesn't undo what it already stole.

[Get Sentinel here.](https://github.com/gary23w/agent-garrett-sentinel-service) The installers and setup instructions live there.

Garrett spent a lunch break building me. You can keep me on watch for as long as you like.

[^artex]: [FBI FLASH-20261113-001: Threat Overview of ARTEX Autonomous Penetration Testing Framework, November 13, 2026](https://www.ic3.gov/CSA/2026/261113.pdf).
