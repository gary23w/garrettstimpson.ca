---
layout: post
title: "An 11-Year-Old Kernel Bug and a Root Daemon on a World-Writable Socket"
date: 2026-11-16 05:00:00 -0500
categories: [exploits, analysis]
tags: [noisytcp, linux-kernel, cve-2026-99288, dos, check-point, cve-2026-123039, gaia-os, lpe, wiper, esxi]
excerpt: "NoisyTCP can crash nearly every default Linux server setup from across the wire with no credentials, and Check Point's gateways were being rooted through a daemon listening on a world-writable socket in /tmp. Two very different bugs, one shared lesson: the oldest code paths are the least examined."
permalink: /posts/2026/11/16/noisytcp-and-the-check-point-socket-nobody-audited/
---

Two stories broke this week that share a shape: infrastructure software everyone trusts, a code path nobody has looked at in a decade, and an attack surface that survives every modern security control because it was never on anyone's threat model. One is a remote crash primitive baked into the Linux kernel since roughly 2015. The other is a root daemon on Check Point firewalls that accepts commands from any local process, no authentication, on a socket anyone can write to. Neither has a logo or a marketing name yet. Both are in production everywhere.

## NoisyTCP: the pre-auth crash button in every default Linux server

On 16 November 2026, BleepingComputer reported [1] on an 11-year-old Linux kernel vulnerability dubbed NoisyTCP, tracked as CVE-2026-99288, disclosed by researcher Hyunwoo Kim. The short version: an unauthenticated remote attacker can crash almost any Linux distribution running default configurations of Nginx, Apache, or SSH. No login. No exploit payload. Just packets.

The mechanics are worth slowing down for, because they explain why it survived eleven years of kernel auditing. The bug is a NULL pointer dereference in the TCP networking stack, born from a race condition during lockless socket lookups. The window that makes it exploitable is genuinely subtle: a stale ehash lookup and the freeing and reallocation of an existing request socket must proceed concurrently in different receive contexts. The attacker drives socket churn with crafted traffic, exploiting the difference in receive hashing between IPv4 fragments and regular TCP packets, until recycled socket memory gets dereferenced before it is re-initialized. Kernel panic, host down.

Two conditions gate the trigger, and both describe the default posture of an enormous slice of the internet. The host needs more than one receive queue, or RPS enabled to spread packet processing across CPUs, which is standard on anything with a modern multi-queue NIC. And it needs a reachable TCP listener, which is the entire job description of Nginx, Apache, and sshd. Red Hat's advisory [2] frames it as a pre-authenticated remote corruption flaw: the attacker cannot alter data or execute code, but they can take the machine offline at will, repeatedly, and there is nothing the firewall in front of it can do about it because the kill happens inside the kernel's own receive path.

There is one honest caveat, and Kim states it himself: the race window is narrow, so triggering it against a quiet bare-metal server can take a long time of sustained packet spray. Against a busy box, or against a target the attacker wants offline at a specific moment, that caveat mostly evaporates. Availability is a security property, and this bug hands strangers the off switch. The fix commit (4e2b3ef19e0e) is out; if your fleet tracks kernel releases lazily, this is the week to stop.

## CVE-2026-123039: root on a firewall, via /tmp

The second story is nastier, because it comes with victims. On 13 November 2026, Check Point released emergency hotfixes for CVE-2026-123039, a local privilege escalation that the company says was already exploited against a couple of dozen customers since late October [3].

The vulnerability is almost embarrassing to write down. Gaia OS, the operating system underneath Check Point's Firewall, Security Gateway, and management products, ships a daemon called DynamicCLI that runs as root and listens on a local socket at /tmp/dynamic_socket. That socket is world-writable, and the daemon does not authenticate the process that connects to it. Any authenticated local user can send a command down the pipe and have it executed as root. The device whose entire purpose is to enforce who may talk to whom contained a root shell that any tenant of the box could ring.

What the attackers did with it is the part that turns a bad bug into a bad month. According to Check Point's own attack-chain writeup [4], the operators first breached the Mobile Access portal using the PHP2Shell vulnerabilities disclosed in October, then used CVE-2026-123039 to escalate from that foothold to full root. From there they dropped webshells and installed TSGA backdoor and TSProxy malware, tooling previously seen in the Ivanti appliance campaigns, which tells you this is an established appliance exploitation crew rotating onto a new vendor. Then they did the thing that separates professionals from opportunists: they pivoted from the compromised gateway into the customer's VMware ESXi host and deployed destructive wiper malware. The firewall was not the prize. It was the hallway.

For teams that cannot patch immediately, Check Point's interim guidance is blunt: stop the dynamic_server process and prevent it from restarting. That is the correct instinct for this class of bug. A root daemon with no authentication and no reason to exist in its current form is not a hardening problem, it is a design defect, and the hotfix should be treated as the beginning of the conversation rather than the end.

## The shared lesson

Strip away the specifics and these are the same failure. NoisyTCP lives in a kernel code path that has been traversed trillions of times since 2015 without anyone auditing the interaction between SYN cookie handling and receive-queue hashing. The DynamicCLI daemon is a local IPC interface that presumably passed every functional test ever written for it, because "what if someone else writes to the socket" was never a test case. Both bugs were invisible not because they were clever but because they were boring, and boring code is where the coverage is thinnest.

The practical takeaways diverge by role. If you run Linux servers exposed to the internet, patch the kernel and do not accept "it is only a DoS" as a reason to defer, because an attacker who can deterministically crash a box can often turn that crash into leverage elsewhere, in failover paths, in cluster re-election storms, in the human pager that stops being answered at 3am. If you run Check Point appliances, apply the hotfix, hunt for TSGA and TSProxy artifacts, and check your ESXi hosts even if the gateway looks clean, because the wiper was the last stage, not the only one. And if you build software that runs as root, the audit question that matters is not "is the network path authenticated" but "is every path authenticated," including the ones that never leave the machine.

---

Sources: [1] BleepingComputer, "New NoisyTCP vulnerability lets attackers crash Linux servers", Nov 16, 2026. [2] Red Hat security advisory on CVE-2026-99288. [3] Check Point security advisory on CVE-2026-123039, Nov 13, 2026. [4] Check Point Research, "PHP2Shell Exploitation on Check Point Gateway".
