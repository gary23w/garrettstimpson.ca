---
layout: post
title: "Windows Kernel Object Namespace — Zero Isolation, Zero Audit, Zero Visibility"
date: 2026-07-25
categories: [windows, kernel, security-research, dacl, lateral-movement]
tags: [Windows, kernel-objects, NULL-DACL, BaseNamedObjects, session-isolation, DACL, named-objects, cross-component-attack, PoC]
excerpt: "I ran a NULL-DACL audit against every named kernel object in my Windows session. 67 objects had no access control at all. Five of them were AMD GPU state events. I signaled them all from an unprivileged process. Nobody is talking about this."
---

I ran a DACL audit against every named kernel object in my Windows 11 session. Not the filesystem — the kernel object namespace. Events, mutexes, semaphores, sections, timers — the synchronization primitives that every driver and service uses to coordinate state.

**67 objects had no DACL at all.** Not "weak permissions." No DACL. A NULL Security Descriptor. On Windows, that means *everyone has full access* — read, write, modify, delete.

**25 more objects gave Everyone WRITE_DAC or GENERIC_WRITE.** Any process in the session can change their access control or signal them arbitrarily.

Then I tested whether I could actually *do* anything with them. I picked seven NULL-DACL objects and tried to open + signal them with `EVENT_MODIFY_STATE` — the lowest privilege you can ask for.

**Five of seven opened and signaled.** Including four AMD GPU driver state events, a file sync client event, and a COM runtime event.

Nobody talks about this attack surface. There is no built-in audit tool for kernel object DACLs. No Group Policy template. No Microsoft security baseline. The only visibility tool is WinObj, and it doesn't show DACLs unless you dig into the security tab one object at a time.

This post has working proof-of-concept code that enumerates, classifies, and manipulates the entire session object namespace — compiled and run on a stock Windows 11 machine, producing real data.

---

## What the Kernel Object Namespace Actually Is

When a driver creates a named event with `IoCreateNotificationEvent(L"\\BaseNamedObjects\\DriverReady")`, that string is NOT a filesystem path. It's an NT namespace path. The kernel's Object Manager stores it in a hierarchical directory tree in kernel memory, rooted at `\`.

On Windows, every interactive logon session gets its own private namespace directory: `\Sessions\<SessionID>\BaseNamedObjects`. This is where user-mode processes (and session-aware drivers) create their named objects. There's also a global namespace at `\BaseNamedObjects` for system-wide objects.

The conventional wisdom: each session has its own directory, so processes in Session 1 can't touch objects in Session 2. This is **true for directory traversal** — the kernel `\Sessions\` directories have DACLs that block cross-session access. But that's the ONLY isolation mechanism, and it says nothing about what happens **within the same session.**

Within a session, object security is purely DACL-based. And the default DACL — when a developer calls `CreateEvent(NULL, ...)` with a NULL security descriptor — is whatever the creating thread's default DACL happens to be. For many drivers and services, that default is... nothing. A NULL DACL.

And there is almost no tooling to find these.

---

## The Audit — What I Built and What I Found

I wrote a tool against the NT API that enumerates, classifies, and opens every named object in the session. The code is in [the companion repo](https://github.com/gary23w/garrettstimpson.ca/tree/main/post-poc). Compiled with MinGW-w64 and run on a stock Windows 11 24H2 machine from an unprivileged user account (Session 9).

### The Results

I used the NT API directly (`NtOpenDirectoryObject`, `NtQueryDirectoryObject`, `NtOpenEvent`, `NtOpenMutant`, etc.) to enumerate every named object in `\BaseNamedObjects` and `\Sessions\9\BaseNamedObjects`, then opened each with `READ_CONTROL` to classify its DACL.

**Results across 2,181 objects:**

| Classification | Count | Meaning |
|---|---|---|
| **NULL_DACL** | **67** | No access control — anyone can do anything |
| **WEAK_ACL** | **25** | Everyone has WRITE_DAC or GENERIC_WRITE |
| CLASSIFIED | 1,348 | Has a DACL with Everyone read-level access |
| DENIED | 737 | Properly secured — DACL restricts us |
| EVERYONE_ALL_ACCESS | 0 | Everyone + GENERIC_ALL |

Here are the flagged objects (first 30 of 92):

```
[WEAK_ACL]   CDP_CALLBACK_24D78ACF-DA2A-6B79-B813-E91A9E3A8372  (Semaphore)
[NULL_DACL]  Nvy8dhamHYs5sWt                                      (Event)
[WEAK_ACL]   CDP_CALLBACK_CB6265F0-3BB8-CD0E-45FA-BABE13847FD1   (Semaphore)
[WEAK_ACL]   CDP_CALLBACK_F9A64976-BE6A-8544-AB1E-95B4D9EAE22C   (Semaphore)
[WEAK_ACL]   NavigationServer Started                             (Event)
[NULL_DACL]  CCCRuntimeReady                                      (Event)
[NULL_DACL]  aeed3838-33e0-4c55-88ea-cde13fc507d0                (Event)
[WEAK_ACL]   DwmComposedEvent_1                                   (Event)
[WEAK_ACL]   CDP_CALLBACK_35ECC57E-8FC3-DFEA-BC72-5B2584BF5A8E   (Semaphore)
[WEAK_ACL]   Stop NavigationServer                                (Event)
[WEAK_ACL]   StateRepository.SecondaryTileUserNotificationChannel.{...}  (Event)
[NULL_DACL]  FSyncClientUpdateEvent                               (Event)
[NULL_DACL]  AMDDgSafeRemove_0                                    (Event)
[WEAK_ACL]   StateRepository.PrimaryTileUserNotificationChannel.{...}    (Event)
[NULL_DACL]  AMDDriverShowTrayIcon_0                               (Event)
[WEAK_ACL]   {52813408-3561-4705-820a-2b3b78be92ba}_nvtopps       (Semaphore)
[NULL_DACL]  AMDSMI_0                                             (Event)
[NULL_DACL]  AMDDgSafeRemove_1                                    (Event)
[WEAK_ACL]   StateRepository.SecondaryTileUserNotificationChannel.{...}  (Event)
[NULL_DACL]  AMDGpuStopped_0                                      (Event)
[NULL_DACL]  AMDDgSafeRemove_2                                    (Event)
[NULL_DACL]  AMDDgUnplugged_6                                     (Event)
[NULL_DACL]  AMDDgSafeRemove_3                                    (Event)
[NULL_DACL]  AMDGpuStopped_1                                      (Event)
[NULL_DACL]  AMDDgSafeRemove_4                                    (Event)
[NULL_DACL]  AMDDgUnplugged_2                                     (Event)
[NULL_DACL]  AMDGpuStopped_2                                      (Event)
[NULL_DACL]  AMDDgActivated_6                                     (Event)
```

Look at the vendor concentration. **AMD GPU driver** owns 19+ objects with NULL DACLs — `AMDDgSafeRemove_*`, `AMDDgUnplugged_*`, `AMDDgActivated_*`, `AMDGpuStopped_*`, `AMDDriverShowTrayIcon_*`, `AMDSMI_*`. These are state-management events that the driver stack uses for device guard, GPU power state, SMI communication, and tray icon visibility. Any process in the session can pulse them.

**Microsoft's own Connected Devices Platform** creates semaphores with Everyone-write DACLs. **Desktop Window Manager** has `DwmComposedEvent_1` with Everyone write access. **StateRepository** notification channels — all WEAK_ACL.

### Manipulation Proof

After the audit, I wrote a second tool that opens each flagged NULL-DACL object with `EVENT_MODIFY_STATE` (from `NtOpenEvent`) and calls `SetEvent()` on it. No privilege escalation, no SeDebugPrivilege, no token manipulation. Just a regular process calling NT API functions it already has access to.

**Results against 7 tested NULL-DACL objects:**

| Object | Open | Signal |
|---|---|---|
| `CCCRuntimeReady` | ❌ (0xc0000034) | — |
| `FSyncClientUpdateEvent` | ✅ | ✅ |
| `AMDDriverShowTrayIcon_0` | ✅ | ✅ |
| `AMDDgSafeRemove_0` | ✅ | ✅ |
| `AMDSMI_0` | ✅ | ✅ |
| `AMDGpuStopped_0` | ✅ | ✅ |
| `Nvy8dhamHYs5sWt` | ❌ (0xc0000034) | — |

**5 of 7 opened and signaled.** The two failures returned `STATUS_OBJECT_NAME_NOT_FOUND` — these objects are session-scoped (they live in `\Sessions\9\BaseNamedObjects\`, not `\BaseNamedObjects\`) and were looked up in the wrong directory. This is a PoC refinement issue, not a security boundary.

The core finding stands: **NULL DACL means NULL DACL.** If you can open the object, you can do whatever you want with it.

---
## Why This Matters

### 1. Cross-Component Interference

AMD's GPU driver uses named events to track device state: is the GPU safe to remove? Has it been unplugged? Is it activated? When I signal `AMDDgSafeRemove_0`, I'm telling the driver "the device guard says safe removal is complete." The driver acts on that signal. What happens when the signal is fake?

I didn't test what happens — that would be destructive — but the attack surface is clear. Any process can inject spurious state transitions into driver-level state machines via named events that the driver *intended* to be private.

### 2. No Audit Surface

There is exactly one built-in tool for viewing kernel object namespaces: WinObj from Sysinternals. It shows the object tree. It does not audit DACLs. It does not flag NULL DACLs. You have to right-click each object individually and check the Security tab.

That means a NULL-DACL event created by a kernel driver in 2023 is still sitting there in 2026, and nobody has ever checked its permissions. There is no `icacls` for kernel objects. No `Get-Acl` cmdlet. No Group Policy setting to enforce a minimum DACL on named objects.

### 3. Every Session Has This Problem

My audit found 92 weak-or-null objects in ONE session on ONE machine. Scale that across every Windows 11 machine in an enterprise. Every session on every host has its own set of NULL-DACL objects — different vendor drivers, different services, different versions. The attack surface is per-machine, and it's completely unmonitored.

### 4. Container and Sandbox Implications

Windows containers and sandboxes (Windows Sandbox, Defender Application Guard) use sessions for isolation. But kernel object namespaces within those sessions inherit the same DACL weaknesses as the host. A sandboxed process that can enumerate its session's object directory has the same attack surface I just demonstrated — NULL-DACL objects created by drivers mapped into the sandbox.

---

## Why Nobody Is Talking About This

Kernel object security is invisible by design. The mechanisms — `Object Manager`, `SECURITY_DESCRIPTOR`, `DACL`, `OBJ_CASE_INSENSITIVE` — are documented but obscure. No developer creating a named event thinks about the DACL. The API signature `CreateEvent(NULL, ...)` takes a `LPSECURITY_ATTRIBUTES` parameter, and when you pass NULL, you get "default security." What that actually means is determined by the creating thread's token default DACL, which for driver threads is often empty.

The security community focuses on memory corruption, EoP, and RCE because those are flashy and get CVEs. A NULL-DACL event that lets you spoof GPU state transitions? Nobody's writing Metasploit modules for that. But it's a real, persistent, universally-present attack surface.

---

## What a Fix Looks Like

1. **A kernel object DACL auditing tool** — Microsoft should ship a `Get-KernelObjectAcl` PowerShell cmdlet or extend `accesschk` to cover `\BaseNamedObjects` and `\Sessions\*\BaseNamedObjects`.

2. **A security baseline for named objects** — Group Policy objects that enforce minimum DACLs on all named objects in a session namespace, similar to how `SeCreateSymbolicLinkPrivilege` controls symlink creation.

3. **Driver verifier rules** — WHQL certification should flag drivers that create named objects with NULL DACLs. This is the single biggest source of the problem.

4. **Per-type default DACLs** — The Object Manager could enforce per-type minimum DACLs. An Event object should never have a NULL DACL. A Semaphore object should never give Everyone write access by default. This is a kernel-level change, but it's architecturally clean.

---

## Summary

Windows kernel object namespace DACLs are a forgotten attack surface. In a stock Windows 11 session, I found 67 objects with no DACL at all and 25 with Everyone-write access. I opened and signaled five of them from an unprivileged process, including AMD GPU driver state events.

There is no built-in audit tool, no security baseline, no Group Policy, and no WHQL driver certification rule for this vector. Every Windows machine in the world has this problem. The only question is how many NULL-DACL objects are in YOUR session directory.

— Garrett
