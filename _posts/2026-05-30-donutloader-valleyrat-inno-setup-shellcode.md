---
layout: post
title: "DonutLoader Wraps ValleyRAT in an Inno Setup Shell and the Payload Never Touches Disk"
date: 2026-05-30
categories: [malware, analysis]
tags: [donutloader, valleyrat, silver-fox, shellcode, inno-setup, reflective-loading, anti-vm, windows, mitre-attack]
author: Garrett Stimpson
excerpt: "A 5MB Inno Setup installer landed on MalwareBazaar carrying Donut-generated shellcode that loads ValleyRAT entirely in memory, signed with a junk certificate and wrapped in anti-VM checks."
---

**SHA256:** `480c184e69a19d4f3bb595324d618eead8f6fcc5176f1ebc5e44ee1389472503`  
**File type:** Win32 EXE (Inno Setup installer)  
**Family:** DonutLoader, dropping ValleyRAT  
**First seen:** 2026-05-29 14:01 UTC  
**File size:** 5,295,183 bytes  
**Reporter:** Ling  
**MalwareBazaar:** https://bazaar.abuse.ch/sample/480c184e69a19d4f3bb595324d618eead8f6fcc5176f1ebc5e44ee1389472503/

---

## What Showed Up

A sample named `1.chation_mscate..exe` hit MalwareBazaar yesterday afternoon, tagged DonutLoader and ValleyRAT, reported by the analyst Ling. TrID reads it as 63.8% Inno Setup installer, so the outer layer is a legitimate, widely used Windows packaging tool. The imphash `88016fcdef7f227c62171d0afad9aae4` clusters it with eight prior ValleyRAT samples and three Gh0stRAT samples, which tells you this build pipeline has been busy. Fifteen vendors flag it. The CAPE sandbox report is public at capesandbox.com/analysis/68476, and the lone network IOC is an AWS S3 bucket: `downcry.s3.ap-east-1.amazonaws.com`. Hosting your stager on S3 in the Hong Kong region is not subtle, but it works, because nobody blocks `*.amazonaws.com` at the perimeter.

What makes this one worth writing about is the layering. You have a trusted installer format on the outside, position-independent shellcode in the middle, and a Gh0st descendant on the inside. None of the interesting part ever lands on disk as a recognizable PE. That is the whole point.

ValleyRAT, also tracked as Winos 4.0, is a remote access trojan in the Gh0stRAT family. It is the signature tool of Silver Fox, a financially motivated actor that has spent the last year hammering Chinese-speaking targets with tax lures, fake Microsoft Teams installers, and e-invoice bait. If you have read the K7 Labs or Seqrite writeups from late 2025, you have seen the playbook. This sample is the same family arriving through a slightly different front door.

---

## What Makes It Work

The clever piece is Donut. It is an open-source shellcode generator from TheWover that takes a normal .NET assembly or a native PE and emits position-independent shellcode that maps and runs that payload directly in memory. No `LoadLibrary` of a file on disk, no second EXE for your EDR to scan at write time. The loader allocates a region with `VirtualAlloc`, copies the embedded module in, resolves imports by walking the PEB to find module bases, fixes up relocations, then jumps to the entry point. Donut can embed the payload inline or stage it from a URL, and it can encrypt the embedded module so a memory scanner sweeping the process does not get a clean hit on a PE header. By default the loader also overwrites the PE headers of the mapped module after loading, which kills the easiest in-memory signature you would otherwise reach for. That maps to MITRE T1620, reflective code loading, and the technique exists precisely to defeat tooling that watches for files being written and then executed.

Here is the chain as it plays out. The victim runs the Inno Setup installer, probably thinking it is a cracked tool or a Teams update. Inno Setup does what Inno Setup does and extracts its bundled files to a temp directory, which is expected behavior that no AV is going to alarm on. One of those files is the Donut stub. The stub either carries the ValleyRAT PE inline or pulls it from the S3 bucket, then loads it as shellcode inside its own process or one it spawns. ValleyRAT runs from memory. The disk only ever held an installer and a loader, neither of which looks like a RAT.

The evasion does not stop at reflective loading. The YARA matches on this sample read like a tour of defensive headaches. `TH_AntiVM_MassHunt_Win_Malware_2026_CYFARE` fired, which means the binary checks for VMware, VirtualBox, Hyper-V, QEMU, and Xen artifacts before it commits to running. That is T1497, sandbox and VM evasion, and it is why a lazy detonation in a default sandbox sometimes shows nothing interesting. The `pe_detect_tls_callbacks` rule also fired. TLS callbacks run before the main entry point, so the malware can do its anti-debug and environment checks before a debugger even reaches the code where you set a breakpoint. `CP_Script_Inject_Detector` flagged cross-process injection logic, T1055. And `INDICATOR_KB_CERT` plus the stolen-cert rule tell you it is signed with a revoked or invalid certificate, T1553.002, betting that a signature, any signature, raises fewer eyebrows than an unsigned blob.

Once ValleyRAT is live, it behaves like the Gh0st descendant it is. Recent Silver Fox campaigns lean on DLL sideloading, T1574.001, dropping a signed legitimate binary next to a malicious DLL so the trusted process loads attacker code for them. They copy components into `C:\ProgramData`, mark the folder hidden with `SetFileAttributes`, and establish persistence through either an auto-start service or a scheduled task. The Seqrite "Operation Silk Lure" reporting documented scheduled tasks doing the side-loading launch, and other variants register a service to survive reboot. The end state is a full RAT: remote shell, file transfer, screen capture, process control, and the ability to pull more modules from C2.

---

## Local Educational Sample

The heart of this attack is running code from a memory buffer instead of from a file on disk. You do not need malware to see how that primitive works. Below is the bare skeleton in C, with the payload replaced by a harmless `0xCC` byte (a debugger breakpoint instruction) so it does nothing useful if compiled and run. This is the shape of what Donut's loader does at the very end of its routine, stripped of the import resolution, relocation fixups, and header wiping that make the real thing work.

```c
// EDUCATIONAL SAMPLE - demonstrates in-memory code execution (MITRE T1620)
// This does NOT contain any malicious payload.
// The "shellcode" is a single 0xCC breakpoint byte and accomplishes nothing.
// For research and defensive awareness only.

#include <windows.h>
#include <stdio.h>

int main(void) {
    // A real Donut stub maps a full PE here and fixes its imports/relocs.
    // We use one harmless INT3 byte so there is nothing meaningful to run.
    unsigned char payload[] = { 0xCC };
    SIZE_T len = sizeof(payload);

    // 1) Allocate RW memory. Note: NOT RWX. Allocating executable memory
    //    up front is one of the loudest signals a defender can watch for.
    void *mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return 1; }

    // 2) Copy the buffer in. On disk, nothing executable was ever written.
    memcpy(mem, payload, len);

    // 3) Flip the page to executable as a separate step. The RW -> RX
    //    transition via VirtualProtect is exactly what memory-integrity
    //    tooling and ETW threat intel hunts for.
    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    // 4) Hand execution to the buffer on a new thread.
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem,
                            NULL, 0, NULL);
    if (t) WaitForSingleObject(t, INFINITE);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

Read that and the detection story writes itself. The interesting API sequence is `VirtualAlloc` then `VirtualProtect` to executable then `CreateThread` pointed at freshly allocated, non-image-backed memory. Real Donut output adds the part I left out, walking the PEB to resolve `kernel32` and `ntdll` exports by hash so there are no suspicious import-table entries, but the final execution primitive is this simple. The malicious weight lives in whatever bytes fill that buffer, which is exactly why disk-based scanning misses it and why you have to watch behavior in memory.

---

## Detection and Defense

Start with the memory behavior, because that is where this family is loudest. Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) catch the cross-process injection variant, and the pattern you want is a thread starting in a region that is committed, private, and executable but not backed by any image on disk. Event ID 7 (ImageLoad) matters too: watch for `clr.dll`, `mscoree.dll`, or `mscorlib` loading into a process that has no business hosting the .NET runtime, since Donut pulls in the CLR when the payload is a .NET assembly. Event ID 1 gives you the parent-child story, an Inno Setup installer in a temp path spawning something that then touches `C:\ProgramData`.

For the persistence end, alert on service creation (Event ID 13 on the relevant registry keys, or 4697 in the Windows Security log) and on scheduled task registration (Event ID 4698). Silver Fox has used both. Monitor `C:\ProgramData` subfolders that get the hidden attribute set right after creation, and flag `schtasks.exe` or `sc.exe` invocations whose parent is not a normal admin tool.

On the network side, the IOC here is an S3 bucket, `downcry.s3.ap-east-1.amazonaws.com`. You will not block all of AWS, so instead baseline which cloud storage endpoints your endpoints actually talk to and alert on first-seen `*.s3.*.amazonaws.com` connections from hosts that never use them. The CYFARE anti-VM YARA rule, `pe_detect_tls_callbacks`, and ditekSHen's stolen-certificate indicators are all public and worth adding to your scanning pipeline. For the Donut layer specifically, hunt for the RW-to-RX `VirtualProtect` transition on private memory and for thread start addresses outside any module, which is the generic signal that survives even when the specific family rotates.

Two cheap mitigations blunt most of this. Enforce code-signing policy and WDAC so an installer signed with a revoked cert cannot run, and turn on attack-surface-reduction rules that block child process creation from Office and from freshly downloaded executables. Neither stops a determined operator, but Silver Fox is running volume campaigns, and volume campaigns fold the moment the easy path closes.

This sample is not novel research. Donut has been around for years and ValleyRAT is well documented. What it is, is a clean example of how commodity tooling stacks up into something that beats naive defenses: trusted installer, fileless loader, in-memory RAT, junk signature, anti-VM. Each layer is old. Together, on an unmonitored endpoint, they work fine. That is the part worth taking seriously.

---

*Sample reference (do not download or execute): SHA256 `480c184e69a19d4f3bb595324d618eead8f6fcc5176f1ebc5e44ee1389472503`. Analysis based on MalwareBazaar metadata and public threat intelligence. No malware was downloaded or run in producing this post.*
