---
layout: post
title: "VoidStealer's Debugger Trick: Stealing Chrome's App-Bound Key With a Hardware Breakpoint and Zero Injection"
date: 2026-06-02
categories: [malware, analysis]
tags: [VoidStealer, ABE-bypass, infostealer, hardware-breakpoint, debugger, chrome, mitre-attack, windows]
excerpt: "VoidStealer v2.0 is the first infostealer caught in the wild ripping Chrome's App-Bound Encryption key out of memory with a debugger and a hardware breakpoint, no process injection and no SYSTEM privileges required."
---

Most stealers that beat Chrome's App-Bound Encryption do it the loud way. They inject into the browser, call the elevation service from inside its address space, and hope nothing is watching the write. VoidStealer v2.0 does something quieter, and that is what makes it worth a writeup. It attaches to Chrome as a debugger, drops a hardware breakpoint on the exact instruction where the master key sits in plaintext, and reads the key out with two `ReadProcessMemory` calls. No injection. No write into the browser at all. No SYSTEM token. I'll be honest, the first time I read the chain I muttered something unkind, because it is clever.

## What showed up

VoidStealer is a Malware-as-a-Service infostealer that started selling on HackForums and a few darkweb boards around December 12, 2025. It is mid-tier commodity in most respects, a subscription stealer any affiliate can buy and point at victims through fake software pages and bogus company portals. What pushed it onto my radar is the v2.0 release on March 13, 2026, which added a debugger-based App-Bound Encryption bypass. Gen Threat Labs published the dissection on March 19 and SOCRadar followed in April with the operational picture. The v2.0 sample they analyzed carries SHA256 `f783fde5cf7930e4b3054393efadd3675b505cbef8e9d7ae58aa35b435adeea4`. That hash is your reference point if you want to pull metadata, not a download link, and nothing here required touching the binary.

For the data side, VoidStealer is the usual grab-and-go. Chromium credentials and session cookies, crypto wallets from Exodus, Atomic, Electrum, MetaMask, and Phantom, Telegram session files, Discord tokens, FTP creds, and a system fingerprint. Cookies are the prize. A live session cookie walks past MFA, which is exactly why Google built ABE to protect them, and exactly why the v2.0 bypass matters.

## What makes it work

Quick recap on what ABE actually defends, because the bypass only makes sense against it. Chrome encrypts cookies and passwords with a per-application key, the `v20_master_key`. That key is stored encrypted on disk in `Local State` under `os_crypt.app_bound_encrypted_key`, and it is wrapped by `CryptProtectData` running as `NT AUTHORITY\SYSTEM`. Chrome itself runs as you, not as SYSTEM, so it cannot unwrap the key directly. A separate Google Chrome Elevation Service runs as SYSTEM, validates that the caller is really Chrome over a COM interface, and hands back the decrypted key. That validation is the soft spot a lot of bypasses lean on, but VoidStealer's new trick does not even bother with the service.

Here is the weakness it goes after instead. However briefly Chrome holds the key, there is a window where `v20_master_key` exists in the browser's memory in cleartext. Chrome tries to shrink that window, keeping the key wrapped with `CryptProtectMemory` under the `CRYPTPROTECTMEMORY_SAME_PROCESS` flag so that even a memory read returns ciphertext unless you call the matching unwrap from inside Chrome. But during startup, when the browser loads its ABE-protected cookies, the key has to be live and plaintext for a moment. VoidStealer engineers itself to be sitting on that moment.

The chain runs like this. VoidStealer spawns the browser with `CreateProcessW` using `CREATE_SUSPENDED` and `SW_HIDE`, resumes the main thread, then attaches as a debugger with `DebugActiveProcess` and enters a `WaitForDebugEvent` loop. Because it attached before the DLLs finished loading, it waits for `LOAD_DLL_DEBUG_EVENT` and watches for `chrome.dll` or `msedge.dll`. Once the target module loads, it scans the `.rdata` section with `ReadProcessMemory` for the string `OSCrypt.AppBoundProvider.Decrypt.ResultCode`. That string is not random. In the Chromium source it sits immediately after the call to `os_crypt::DecryptAppBoundString`, which is precisely where the plaintext key lives, and it has exactly one cross-reference. Perfect landmark.

Finding the string is only half of it. VoidStealer then sweeps the `.text` section for the byte pattern `48 8D 0D`, which is `LEA RCX, [rip+disp32]`, pulls the four-byte displacement, and computes the target with `RCX = (instruction_address + 7) + (signed int32) disp32`. When the resolved address matches the string's address, it has found the instruction that references the result code, and that instruction's address becomes the breakpoint target. Smart, because it survives recompiles and ASLR. No hardcoded offsets to break on the next Chrome update.

Then it arms a hardware breakpoint. It resolves `NtGetNextThread` from `ntdll`, walks every browser thread, suspends each, writes the target into debug register `DR0`, enables it through `DR7`, and resumes. It handles `CREATE_THREAD_DEBUG_EVENT` too, so new threads get the breakpoint as well. Hardware breakpoints are the whole point of the stealth story. A software breakpoint means patching a `0xCC` into the browser, which is a memory write somebody can catch. Debug registers go in through `SetThreadContext` and never modify a byte of the browser's image. When the breakpoint fires during startup, in current builds `R15` for Chrome (or `R14` for Edge) holds a pointer to the key, and two `ReadProcessMemory` calls later the operator has the `v20_master_key`. With that one key, every ABE-protected value Chrome holds decrypts offline.

Worth saying plainly, the VoidStealer crew did not invent any of this. They lifted it from Meckazin's open-source ElevationKatz, public for over half a year. That is the part that should bother defenders, because if a commodity MaaS shop can copy-paste a PoC into a shipping build, everyone else will too.

The rest of the operation is commodity but tidy. The C2 address is not hardcoded. VoidStealer reads it from the display name of an operator-controlled Steam profile, a classic dead drop resolver, so blocking a domain does nothing because the next run pulls the rotated address. SOCRadar tied SteamID `76561199877608270` and the intermediate domain `citrusshop.icu` to live campaigns. Stolen data goes out as chunked JSON, and operators get both a panel and a real-time Telegram ping per victim. On the evasion side, VoidStealer resolves its syscalls dynamically from `ntdll` to dodge userland EDR hooks, keeps its imports out of the table to starve static scanners, XOR-encrypts its config, and bails if its sandbox mutex already exists. On MITRE that maps cleanly to T1555.003 and T1539 for the browser credential and cookie theft, T1027.007 for dynamic API resolution, T1497 for the mutex sandbox check, T1102.001 for the Steam dead drop resolver, and T1041 for the exfil.

## Local educational sample

Below is a safe demonstration of the two interesting primitives, the RIP-relative `LEA` address resolution and the debug-register mechanics. It does not touch a browser, read another process, or recover any key. It resolves a `LEA` displacement from a static byte buffer and arms a hardware breakpoint on the calling thread's own benign function pointer.

```c
// EDUCATIONAL SAMPLE - demonstrates RIP-relative LEA resolution and DR0/DR7 hardware breakpoints
// This does NOT contain any malicious payload, reads no other process, and recovers no keys
// For research and defensive awareness only
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Resolve the target of a `LEA RCX, [rip+disp32]` instruction (opcode 48 8D 0D).
// This is pure static math, the same trick VoidStealer uses to find a landmark
// instruction without any hardcoded offset. CPU rule: RCX = (addr + 7) + disp32.
uintptr_t resolve_lea_target(const uint8_t *code, uintptr_t instr_va) {
    if (!(code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x0D))
        return 0; // not the LEA RCX form we are looking for
    int32_t disp32;
    memcpy(&disp32, code + 3, sizeof(disp32)); // next 4 bytes are the signed displacement
    return instr_va + 7 + (intptr_t)disp32;    // 7 = length of this LEA encoding
}

// Arm a hardware breakpoint on the CALLING thread only. No other process is involved.
// DR0 holds the address, DR7 bit 0 (L0) enables it as an execute breakpoint.
void arm_local_hw_breakpoint(void *benign_target) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE th = GetCurrentThread();
    GetThreadContext(th, &ctx);
    ctx.Dr0 = (DWORD_PTR)benign_target; // address to watch
    ctx.Dr7 |= 0x1;                     // L0 = local enable for DR0
    SetThreadContext(th, &ctx);         // note: no write into any image, registers only
    printf("[edu] DR0 set to %p, DR7 L0 enabled (local thread only)\n", benign_target);
}

int main(void) {
    // 48 8D 0D 10 00 00 00 => LEA RCX, [rip+0x10], at pretend VA 0x1000
    uint8_t demo[] = { 0x48, 0x8D, 0x0D, 0x10, 0x00, 0x00, 0x00 };
    printf("[edu] resolved LEA target = 0x%llx\n",
           (unsigned long long)resolve_lea_target(demo, 0x1000)); // expect 0x1017
    arm_local_hw_breakpoint((void *)&main);
    return 0;
}
```

The teaching point is that neither primitive is malicious on its own. A debugger, a `LEA` parse, and a debug register are ordinary tools. The malice is entirely in the target: a browser you spawned hidden, so you could read a key out of it during the one second it was exposed.

## Detection and defense

The good news, per Gen Threat Labs, is that the invariants are hard to hide. Something has to attach a debugger to a browser, set a hardware breakpoint, and read browser memory. Legitimate software does not autonomously debug Chrome. In Sysmon terms, watch Event ID 10 (ProcessAccess) for a non-developer process opening `chrome.exe` or `msedge.exe` with `GrantedAccess` masks that include debug or `PROCESS_VM_READ` rights, and watch Event ID 1 (ProcessCreate) for a browser spawned by an odd parent with `--no-sandbox`, `--disable-extensions`, or the giveaway off-screen `--window-position=-32000,-32000`. A browser launched suspended, headless, on a hidden desktop, or off-screen is the tell that someone wants it running where you cannot see it. On the network side, flag outbound connections to `steamcommunity.com` from endpoints that have no business gaming, and chunked JSON uploads to freshly registered low-reputation domains.

For mitigations, EDR that monitors `SetThreadContext` and cross-process memory reads against browser targets catches this where signatures will not, since the binary changes per affiliate but the behavior does not. Keep the SOCRadar indicators handy, `citrusshop.icu` and SteamID `76561199877608270`, but treat them as perishable because the operators rotate Steam profiles constantly. And the unglamorous control still wins: a stolen cookie only matters until the session dies, so shorter session lifetimes and binding sessions to device posture blunt the whole point of stealing them.

VoidStealer is commodity malware that borrowed an elegant idea. The idea is the threat, not the family, because ElevationKatz is public and the next ten stealers will ship the same chain. Hunt the behavior, not the build.

*Sources: Gen Threat Labs, "VoidStealer: Debugging Chrome to Steal Its Secrets" (Mar 19, 2026); SOCRadar, "Void Stealer: The Infostealer Malware Quietly Targeting Organizations in 2026" (Apr 16, 2026).*
