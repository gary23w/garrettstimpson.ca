---
layout: post
title: "ARTEX Still Has to Run Something"
author: Garrett Stimpson
date: 2026-11-14 12:30:00 -0500
last_modified_at: 2026-11-15
categories: [projects, security]
tags: [intrusion-detection, malware-removal, open-source, rust, agent-garrett, sentinel, artex]
excerpt: "Sentinels started on a lunch break. It watches process chains on the host and can stop a shell before it downloads a payload."
description: "How Sentinels watches process chains, records stops and reverses cleanup on Linux, macOS and Windows."
permalink: /posts/2026/11/14/i-had-some-time-on-my-lunch-break-so-i-killed-artex/
---

ARTEX can chain scans, exploits and credential use with little time between steps. A host agent gets a shot when the intrusion starts running programs on that host. I built [Sentinels](https://github.com/gary23w/sentinels) for that moment.

The first version started on a lunch break. I used a simple chain: a web server starts a shell, the shell fetches a script, and the script tries to keep itself around. I wanted to end the shell before the script ran.

The local agent is called `garrett`. It runs on Linux, macOS and Windows, watching new programs and their connections. It scores activity locally. In the default `kill` mode, it can stop a hostile program and its children. It also writes a case showing what it saw and what it did.

Cleanup can quarantine a related dropped file and disable supported persistence entries: cron jobs, Windows Run keys and services. `garrett restore <case>` reverses those changes if it got the call wrong.

I'd start in `report` mode on a machine I haven't tuned yet. It records cases without stopping programs. The default stop path does not call an AI model. The fleet service can run on your own hardware, and managed hosting and AI case analysis are optional.

The README has internal stopping-time figures: about 20 ms for rapid process-chain tests and under 5 ms for selected tool-driven tests. I haven't published the test setup, timing boundaries, sample size or raw results yet. Treat those numbers as preliminary.

The agent covers host execution. ARTEX can also scan services and use stolen credentials without starting a process on a machine running Sentinels. Those paths need other monitoring. If credentials have already been stolen, stopping a process will not make them safe again.

The [code and installers](https://github.com/gary23w/sentinels) are [MIT licensed](https://github.com/gary23w/sentinels/blob/main/LICENSE). If you try it and find a false positive or a chain it misses, I'd like to know.
