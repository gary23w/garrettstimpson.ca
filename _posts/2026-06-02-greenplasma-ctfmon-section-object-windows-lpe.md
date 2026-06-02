---
layout: post
title: "GreenPlasma: a SYSTEM shell hiding inside CTFMON, and the half a PoC that ships it"
date: 2026-06-02
categories: [exploits, windows]
tags: [greenplasma, ctfmon, lpe, windows, section-objects, nightmare-eclipse]
excerpt: "An unprivileged user plants a section object where CTFMON trusts it, and the SYSTEM text-input service walks itself into your payload. The PoC stops one step short on purpose."
---

Here's the part that gets me about GreenPlasma. There is no kernel bug. No heap groom, no use-after-free, no race against a one-shot window you have to win on the first try. The whole thing is a standard user politely asking the object manager for a section, putting it somewhere a SYSTEM process already looks, and waiting. Windows does the rest to itself.

GreenPlasma is one of two zero-days that Nightmare-Eclipse (the same person posting as Chaotic Eclipse) dropped on GitHub on May 13, 2026, alongside YellowKey, the BitLocker/WinRE bypass I wrote up the other day as CVE-2026-45585. GreenPlasma is the local privilege escalation half. As of June 2 there is still no CVE assigned and no patch from Microsoft. It affects Windows 10, Windows 11, and Windows Server wherever an interactive session is running ctfmon.exe, which in practice is almost everywhere a human logs in.

## What CTFMON actually is, and why it's a problem

ctfmon.exe is the Collaborative Translation Framework monitor. It's the plumbing behind the Text Services Framework: alternate keyboard layouts, IMEs, handwriting, the on-screen keyboard, speech input. Boring, ancient, and on by default. The thing nobody thinks about is that in an interactive logon it runs as SYSTEM, and it brokers shared state through named kernel objects so that per-user input components and the privileged service can talk to each other.

Shared state plus a privilege boundary is the oldest trap in Windows local exploitation. CTFMON reaches into the object manager namespace to find and map section objects (shared memory, created through NtCreateSection and friends) that the input stack uses to pass data around. The trust assumption baked in is that whatever lives at the expected name was placed there by something at least as privileged as CTFMON. That assumption is wrong, and GreenPlasma is the proof.

## The primitive

What James Ballantyne's team at SpiderLabs documented, and what the public PoC demonstrates, is arbitrary section creation in a namespace location a standard user has no business writing to. The exploit, running as a plain unprivileged user, creates a named section object and gets it to land where CTFMON expects a trusted one. Then a chain of registry edits and ACL boundary abuse nudges CTFMON into opening and mapping the attacker's section instead of the legitimate one.

Once SYSTEM maps your section, you own a region of memory that a SYSTEM process treats as its own. You write the bytes. CTFMON reads them back believing they came from the input subsystem. That's the whole ballgame: shellcode or a fake DLL mapping sitting in a region the OS fully trusts, executed in SYSTEM context, with no UAC prompt and no admin rights anywhere in the path.

If you've done Windows privesc work, you know the shape of this. It's a planting-and-trust problem, cousin to the classic DLL search-order and named-pipe impersonation tricks, except the trusted resource here is a section object in the object manager namespace rather than a file on disk. File integrity monitoring will not see it. The on-disk ctfmon.exe never changes. AIDE, Tripwire, anything hashing binaries, all blind. The malicious artifact is a memory section that exists only at runtime.

## The half a PoC

This is the genuinely annoying bit, and also the clever bit. Nightmare-Eclipse shipped the section-creation primitive and then stopped. The final stage, the part that converts "I control a section CTFMON maps" into "I have a SYSTEM shell," is missing. He left a note framing it as a capture-the-flag: if you're smart enough, you can turn this into a full privilege escalation because you can influence the newly created section to manipulate data.

Do not let the word "partial" lull anyone. Releasing the hard, novel part (the boundary abuse that gets your section trusted) while withholding the mechanical last step is not a mitigation. It's a speed bump for skids and a free starting block for anyone competent. The conceptual gap between a controlled SYSTEM-mapped section and code execution is small. You're picking how CTFMON interprets data it already trusts. A skilled person closes that in an afternoon, and ransomware crews and APT operators have repeatedly folded public LPE code into live intrusions inside the same week a drop lands.

For context on how fast this turns operational: SpiderLabs and SecurityWeek both tie earlier Nightmare-Eclipse tools (BlueHammer, patched as CVE-2026-33825, plus the still-unpatched RedSun and UnDefend) to hands-on-keyboard intrusions within days of release, staged behind compromised FortiGate SSL VPN credentials from Russia-geolocated source IPs. GreenPlasma slots into that same kill chain as a third independent path to SYSTEM, used when Defender-targeting routes like BlueHammer and RedSun don't apply.

## A rough sketch of the chain

I'm not going to publish the missing weaponization, but the public shape looks like this:

```c
// 1. Run as a standard, unprivileged user. No admin, no UAC.
// 2. Create a named section in the object-manager namespace where
//    CTFMON will resolve it as trusted input-framework shared memory.
HANDLE hSection;
NtCreateSection(&hSection,
                SECTION_ALL_ACCESS,
                &objAttr,        // OBJECT_ATTRIBUTES naming the planted path
                &maxSize,
                PAGE_READWRITE,
                SEC_COMMIT,
                NULL);

// 3. Registry + ACL manipulation steers ctfmon (SYSTEM) to open
//    THIS section instead of the legitimate one.
// 4. Map it, write attacker-controlled bytes.
PVOID base = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &base, 0, 0,
                   NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);

// 5. CTFMON maps and trusts the same section in SYSTEM context.
//    The CTF gap: shape the contents so CTFMON's use of them
//    yields SYSTEM code execution.
```

The interesting research question is what exactly CTFMON does with that mapped data that becomes a control-flow primitive. That's the flag Nightmare-Eclipse is dangling, and I'd bet the answer is something dull like a function pointer or a length field that should never have been writable from a low box.

## What to do before Microsoft ships a fix

There's no patch, so this is detection and hardening, not remediation. Baseline the SHA-256 of C:\Windows\System32\ctfmon.exe now and alert on any deviation, even though the realistic attack leaves the binary alone. The signal you actually want is behavioral: ctfmon.exe spawning unexpected child processes, ctfmon interacting with or creating section objects it doesn't normally touch, or ctfmon crashing, which is a classic tell of a botched section swap. Feed object-manager telemetry into your EDR and write a rule for arbitrary section creation in non-user namespaces by a standard-user token, because that is the load-bearing step here.

Block execution from user-writable staging directories with ASR rules, since every confirmed Nightmare-Eclipse intrusion staged payloads out of Pictures and Downloads subfolders. Alert on a process literally named GreenPlasma.exe and its obvious renames. Audit your FortiGate and other SSL VPN logs for off-hours or geographically improbable logins, because that has been the front door for this crew every time. And set a calendar reminder to watch Microsoft's out-of-band channel ahead of June's Update Tuesday, plus the Nightmare-Eclipse GitHub account, since he has been explicit that more drops are coming on a Patch Tuesday cadence.

Treat GreenPlasma as live. The dangerous half is already public, and the other half is a weekend project for the wrong person.
