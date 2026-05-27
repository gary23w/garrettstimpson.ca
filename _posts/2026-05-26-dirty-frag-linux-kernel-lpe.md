---
layout: post
title: "Dirty Frag: Deterministic Root in Every Major Linux Distro"
date: 2026-05-26
categories: [exploits, linux, lpe]
tags: [cve, dirty-frag, kernel, ipsec, rxrpc, privilege-escalation, page-cache]
excerpt: "Two in-place decryption optimizations introduced in 2017 and 2023 let an unprivileged local user corrupt arbitrary page cache entries and escalate to root. No race window. Standard syscalls only."
---

What makes a kernel vulnerability genuinely scary? Not just the CVSS score. It's the combination: deterministic exploitation with no timing window, no special privileges required, and a bug introduced by a performance optimization that shipped in every kernel for nearly a decade before anyone noticed.

Dirty Frag checks all three boxes.

CVE-2026-43284 and CVE-2026-43500, nicknamed Dirty Frag, were published by researcher Hyunwoo Kim on May 8, 2026. Kim says he was pushed to go public ahead of schedule after another party broke a coordinated embargo. Patches weren't out yet when the PoC dropped. Active exploitation followed within hours.

## The page cache write primitive lineage

If you've followed Linux kernel LPEs over the last decade, you know the page cache write primitive. Dirty Cow (2016) gave you arbitrary writes via a COW race. Dirty Pipe (2022) gave you writes through pipe buffer flag abuse. Copy Fail (CVE-2026-31431) used `AF_ALG` and `splice()`.

Dirty Frag is the latest, but it's arguably the cleanest.

The core issue sits in the IPsec ESP and RxRPC network stacks. Both have a fast path where, instead of copying received data into a fresh buffer before decryption, the kernel decrypts directly into the page cache. This is a performance win: fewer memory copies, better cache behavior. It's also the problem. Network code ends up with a write path into pages that are supposed to be read-only.

CVE-2026-43284 covers the ESP variant (`esp4` and `esp6`). The bug traces to commit `cac2661c53f3` merged in January 2017. CVE-2026-43500 covers RxRPC, introduced in June 2023.

Nine years for the ESP half. Nobody caught it.

## Why "deterministic" changes everything

Most page cache corruption exploits involve timing. You race against the kernel, success rates vary. Dirty Pipe had good rates because the race window was wide. Other bugs require hundreds of attempts, specific CPU topology, or a fast machine.

Dirty Frag has no race condition at all. The corruption happens deterministically on the `sendmsg()` path through the ESP or RxRPC code. Kim reported high success rates and minimal kernel panic risk across test environments. You run it once and it works.

That's what separates it from the average LPE.

## The exploit chain

No elevated capabilities or unusual kernel modules needed. `esp4`, `esp6`, and `rxrpc` load by default in every major enterprise distribution. The syscalls involved are completely standard: `socket`, `setsockopt`, `bind`, `vmsplice`, `splice`, `sendmsg`.

Rough flow:

```
1. Create an IPsec ESP socket with a crafted symmetric key
2. Use vmsplice() to obtain a page cache reference
3. Trigger the in-place decryption path via sendmsg() with a crafted packet
4. The decryption routine writes your chosen bytes into the page cache entry
5. Arbitrary write primitive into read-only pages achieved
6. Chain to SUID binary overwrite or kernel data structure corruption
```

For the RxRPC path the mechanics differ slightly but the outcome is identical.

The container escape angle is worth noting specifically. The page cache is shared across the entire host. A container with standard Linux capabilities (not `CAP_SYS_ADMIN`) can corrupt host page cache entries. On unpatched Kubernetes nodes this becomes a container-to-host escape. Microsoft's security blog confirmed active use of exactly this pattern in post-compromise scenarios observed in the wild within the first 24 hours after the PoC dropped.

## Blocking the modules as a stopgap

If patching immediately isn't possible:

```bash
echo "install esp4 /bin/false" >> /etc/modprobe.d/dirty-frag.conf
echo "install esp6 /bin/false" >> /etc/modprobe.d/dirty-frag.conf
echo "install rxrpc /bin/false" >> /etc/modprobe.d/dirty-frag.conf
```

This stops the vulnerable modules from loading. It breaks IPsec-based VPN tunnels and any RxRPC-dependent services (primarily OpenAFS). Check whether the modules are already loaded before deploying:

```bash
lsmod | grep -E "^(esp4|esp6|rxrpc)"
```

If they show up, unload with `rmmod` or reboot after adding the modprobe config.

## Detection signatures

Sysdig's write-up flags the combination that doesn't appear in legitimate workloads: a process calling `socket(AF_INET, SOCK_RAW, IPPROTO_ESP)`, followed by `vmsplice()` into a file-backed mapping, followed by `sendmsg()` with a payload of specific sizes. If you're running a SIEM or behavioral detection layer, their rule set is worth importing directly.

For container environments, watch for `sendmsg` calls to `IPPROTO_ESP` sockets originating from container PIDs. That combination has essentially no legitimate use case in most Kubernetes deployments.

## The lesson that keeps not sticking

After every one of these bugs, someone points out that performance optimizations in security-critical code paths are risky. In-place decryption is faster than copy-then-decrypt. It also creates a write path into read-only pages if the bounds and state assumptions aren't airtight.

The ESP fast path was in the kernel for nine years. The RxRPC version was added in 2023, a full year after Dirty Pipe should have made everyone paranoid about page cache write primitives. It wasn't.

Patch. Then ask why your review process didn't catch it either.

---

*Based on the [Wiz blog](https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc), [Sysdig detection guide](https://www.sysdig.com/blog/dirty-frag-cve-2026-43284-and-cve-2026-43500-detecting-unpatched-local-privilege-escalation-via-linux-kernel-esp-and-rxrpc), and [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/).*
