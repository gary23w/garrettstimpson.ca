---
layout: post
title: "Sentinels"
author: Garrett Stimpson
date: 2026-11-14 12:30:00 -0500
last_modified_at: 2026-11-15
categories: [projects, security]
tags: [intrusion-detection, malware-removal, open-source, rust, agent-garrett, sentinel, artex]
excerpt: "I started Sentinels on a lunch break. It's a host intrusion detector for Linux, macOS and Windows, built to stop automated attacks from tools such as ARTEX."
description: "Sentinels is a host intrusion detector for Linux, macOS and Windows. The source and installers are available under the MIT license."
permalink: /posts/2026/11/14/i-had-some-time-on-my-lunch-break-so-i-killed-artex/
---

I started [Sentinels](https://github.com/gary23w/sentinels) on a lunch break. It's a host intrusion detector for Linux, macOS and Windows, written in Rust and released under the [MIT license](https://github.com/gary23w/sentinels/blob/main/LICENSE).

It's meant to deal with automated attacks from tools such as ARTEX. The agent watches processes and connections on the machine and can stop a malicious process and its children. It can also quarantine files and disable supported startup entries associated with the attack. Those cleanup changes can be reversed.

The stopping times I'm seeing in internal tests are about 20 ms for rapid process chains and under 5 ms for selected tooling tests. I'll add the benchmark setup and results to the README.

You can use it on a single machine or run the fleet service yourself. Managed hosting is available too. AI analysis is optional; the default stop decision happens locally.

The [repository](https://github.com/gary23w/sentinels) has the source and installers. The [manual](https://gary23w.github.io/sentinels/manual.html) covers setup and the response modes.

GitHub: <https://github.com/gary23w/sentinels>
