---
layout: post
title: "Evelyn Stealer Ships Inside VS Code Extensions and Hollows grpconv.exe to Steal Your Dev Creds"
date: 2026-05-31
categories: [malware, analysis]
tags: [evelyn-stealer, vscode, supply-chain, process-hollowing, infostealer, windows, mitre-attack]
excerpt: "A stealer campaign weaponizes the VS Code marketplace: a trojan extension drops a downloader DLL, fires hidden PowerShell, and hollows grpconv.exe to run entirely in memory while it strips browser creds and crypto wallets. The injection target alone is the tell."
---

This one bothers me more than your average stealer, because it goes straight at developers. Not the marketing intern who clicks a fake invoice. The person with a signed commit history, a cloud token in their environment, and push access to production. Evelyn Stealer rides in through the Visual Studio Code extension marketplace, runs its final payload inside a Windows process that basically never executes on a modern machine, and walks out with browser credentials, cookies, and crypto wallets. Trend Micro published a full breakdown in January after Koi Security first flagged the extensions in December, and the chain is clean enough to be worth picking apart.

It is not novel because it is loud. It is interesting because it is quiet, and because it chose a target that tells you everything if you know where to look.

---

## What Showed Up

The campaign starts with three malicious VS Code extensions: `BigBlack.bitcoin-black`, `BigBlack.codo-ai`, and `BigBlack.mrbigblacktheme`. They look like the usual marketplace filler, a theme and a couple of crypto/AI helpers. On install they drop a downloader DLL named `Lightshot.dll`, which is the first stage.

Reference hash for that downloader, per Trend Micro's IOC table, SHA256: `369479bd9a248c9448705c222d81ff1a0143343a138fc38fc0ea00f54fcc1598`. Do not go fetch it. You do not need the binary to understand the chain, and the analysis below is built entirely from published metadata and reporting.

`Lightshot.dll` launches a hidden PowerShell command (T1059.001) that pulls down a second stage called `runtime.exe`. That executable is the injector. It decrypts the real stealer with AES-256-CBC and injects it directly into the memory of a legitimate Windows process, `grpconv.exe`. From there the stealer collects clipboard contents, installed apps, running processes, desktop screenshots, stored Wi-Fi credentials, system info, and the good stuff, saved cookies and credentials out of Chrome and Edge, plus crypto wallets. It zips the haul and ships it over FTP to `server09.mentality[.]cloud`. Trend Micro tracks the final payload as Evelyn Stealer; some later samples added WhatsApp and Telegram session theft and Epic Games tokens.

There is also a second delivery path. A ClickFix-style variant uses malvertising to trick the victim into pasting PowerShell, which stages GuLoader out of a JPG and loads Evelyn into memory with MSBuild. Same destination, different front door.

---

## What Makes It Work

The piece worth your attention is the injection target. `grpconv.exe` is the Program Group Converter, a signed Microsoft binary left over from the Windows 9x to NT migration. On a normal box it runs approximately never. So when Evelyn picks it as the host for process hollowing (T1055.012), the attacker gets a payload running under a trusted, signed image name. The cost is that anything spawning or writing into `grpconv.exe` is, by itself, an anomaly. The malware traded stealth on the image name for a giant tell on the behavior. I will take that trade as a defender every single time.

Process hollowing works like this. The injector calls `CreateProcessW` with the `CREATE_SUSPENDED` flag so the target launches but never runs a single instruction. It reads the target's PEB to find the image base, unmaps the original executable image with `NtUnmapViewOfSection` (sometimes called `ZwUnmapViewOfSection`), allocates fresh memory with `VirtualAllocEx`, writes the decrypted payload in with `WriteProcessMemory`, repoints the thread's entry via `SetThreadContext`, and finally calls `ResumeThread`. The process that the OS, the EDR, and the analyst all see is `grpconv.exe`. The code actually running is Evelyn. Nothing ever touches disk as the real payload, which is the entire point of doing it in memory.

The downloader stage earns its keep too. It creates a named mutex so only one instance runs per host, the kind of housekeeping that keeps the operation from tripping over itself and generating noise.

Then there is the browser theft, and this is the detail I actually liked, in a grudging professional way. To read cookies and saved credentials cleanly, Evelyn relaunches the victim's browser itself from the command line in a locked-down headless configuration. It passes `--headless=new`, `--disable-gpu`, `--no-sandbox`, `--disable-extensions` to keep your security extensions from interfering, `--disable-logging` to kill the audit trail, `--silent-launch` and `--no-first-run` to skip dialogs, `--disable-popup-blocking`, and then the two that give it away, `--window-position=-10000,-10000` to throw the window off-screen and `--window-size=1,1` to shrink it to a single pixel. It first terminates any running browser processes so it has clean access to the credential and cookie stores (T1555.003). That browser relaunch with that flag combination is a fingerprint you can hunt on.

Layered under all of it is a sandbox and analysis evasion stack (T1497): VM detection, debugger checks, and specific tests for RDP sessions and Hyper-V. The goal is the same as every stealer, run on a real victim, go dark in a researcher's box.

Mapped to ATT&CK the chain reads cleanly. Initial access through a trojanized software extension (T1195.002), execution and download via PowerShell (T1059.001), defense evasion and execution through process hollowing (T1055.012), discovery across system info and processes (T1082, T1057), collection from the clipboard and screen (T1115, T1113), credential access from browsers (T1555.003), and exfiltration over an unencrypted protocol, FTP (T1048.003).

---

## Local Educational Sample

Here is the process hollowing skeleton in C, the same primitive Evelyn uses to get into `grpconv.exe`. There is no shellcode, no payload, no decryption routine. The buffer is zeroed. It will launch a suspended process and do nothing useful, which is exactly the point. This is to show the API sequence so you can reason about what to detect.

```c
// EDUCATIONAL SAMPLE - demonstrates the process hollowing API sequence (T1055.012)
// This does NOT contain any malicious payload. The injected buffer is all zeros.
// For research and defensive awareness only.

#include <windows.h>
#include <stdio.h>

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 1. Launch the host process SUSPENDED so it never executes its own code.
    //    Real malware picks an unusual signed target like grpconv.exe.
    if (!CreateProcessA("C:\\Windows\\System32\\grpconv.exe",
                        NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // 2. A real injector would now read the remote PEB to find the image base,
    //    then unmap the original image:  NtUnmapViewOfSection(pi.hProcess, base);
    //    We deliberately skip that. Nothing gets unmapped here.

    // 3. Allocate memory in the remote process. In real samples this holds the
    //    decrypted stealer. Here it is a harmless zeroed buffer.
    SIZE_T size = 0x1000;
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    unsigned char benign[0x1000] = { 0 };   // all zeros - no code
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remote, benign, size, &written);
    printf("Wrote %llu zero bytes to remote process (PID %lu)\n",
           (unsigned long long)written, pi.dwProcessId);

    // 4. A real injector would repoint the thread entry with SetThreadContext()
    //    and then ResumeThread(). We do NOT resume into the buffer. Instead we
    //    terminate the harmless suspended host so nothing executes.
    TerminateProcess(pi.hProcess, 0);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

The detection lesson is in the call graph, not the bytes. `CreateProcess` with `CREATE_SUSPENDED`, followed by a cross-process `VirtualAllocEx` and `WriteProcessMemory`, followed by `SetThreadContext` and `ResumeThread` against a process that has no business running, is process hollowing whether the payload is Evelyn or anything else.

---

## Detection and Defense

Start with the injection target because it is the cheapest, highest-signal catch you have. Alert on `grpconv.exe` running at all. Sysmon Event ID 1 with `Image` ending in `grpconv.exe` should be near zero in any normal environment, and a parent process of `runtime.exe` or PowerShell makes it an instant pivot. Pair that with Sysmon Event ID 10, ProcessAccess, where the source process opens `grpconv.exe` with `GrantedAccess` containing `0x0820` or similar masks that include `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` and `PROCESS_SET_INFORMATION`. That access pattern into a dormant signed binary is the hollowing handprint.

Watch the extension origin. The dropped `Lightshot.dll` will load into the Code/node process tree, so Sysmon Event ID 7, ImageLoad, for an unsigned or odd DLL loading under `Code.exe` or the extension host is worth flagging. Inventory installed extensions and hunt for the `BigBlack.*` publisher and anything pulled from outside your approved list under `%USERPROFILE%\.vscode\extensions`.

Hunt the browser relaunch. A Chrome or Edge process started with `--headless=new` combined with `--disable-logging` and an off-screen `--window-position=-10000,-10000` or a `--window-size=1,1` is not something a human does. That command line in Sysmon Event ID 1 is one of the strongest behavioral indicators in this whole chain.

Cover the network and the staging. Sysmon Event ID 3 or your egress logs flagging FTP to `server09.mentality[.]cloud`, plus Event ID 22 DNS for that domain, catches the exfil. Event ID 11 file-create events showing a ZIP being assembled in a temp path right before that FTP burst ties the collection and exfiltration stages together.

For a YARA starting point, the headless-launch flag strings plus the unusual injection target make a reasonable hunting rule. Treat this as illustrative, not the vendor signature.

```
rule Evelyn_Stealer_Behavioral_Strings {
    meta:
        description = "Illustrative hunt for Evelyn Stealer host artifacts - not a vendor rule"
        author = "Garrett Stimpson"
        reference = "Trend Micro Evelyn Stealer analysis, Jan 2026"
    strings:
        $h1 = "--headless=new" ascii wide
        $h2 = "--window-position=-10000,-10000" ascii wide
        $h3 = "--disable-logging" ascii wide
        $t1 = "grpconv.exe" ascii wide
        $c2 = "mentality.cloud" ascii wide
    condition:
        2 of ($h*) and ($t1 or $c2)
}
```

On the prevention side, the boring controls are the ones that bite here. Lock VS Code extension installs to an allowlist and block sideloaded VSIX. Application control that denies `grpconv.exe` execution outright costs you nothing and removes the host. Constrained Language Mode and PowerShell script-block logging turn the downloader stage loud. And tell your developers, plainly, that their workstation is part of the software supply chain now. A theme extension is an executable with their cloud tokens in reach.

Commodity stealer, clever delivery. The part that should stick with you is the audience. Attackers are spending real effort to land on developer machines specifically, and the marketplace you trust for tooling is now an initial-access vector. Treat it like one.
