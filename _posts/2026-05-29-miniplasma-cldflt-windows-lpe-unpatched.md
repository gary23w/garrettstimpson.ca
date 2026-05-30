---
layout: post
title: "MiniPlasma: The 2020 Windows Bug That Never Actually Died"
date: 2026-05-29
categories: [exploits, windows]
tags: [windows, lpe, zero-day, cldflt, privilege-escalation, nightmare-eclipse, unpatched]
excerpt: "A Windows LPE 'fixed' in December 2020 still hands out SYSTEM on fully patched Windows 11 in May 2026 — and the person who proved it is threatening to drop RCEs on July 14."
---

Here's something that should bother you. In September 2020, Google Project Zero researcher James Forshaw reported a local privilege escalation bug in the Windows Cloud Files Mini Filter Driver, `cldflt.sys`. Microsoft patched it that December as CVE-2020-17103. The advisory went up, the KB shipped, the CVE closed. Done.

Six years later, a researcher going by Nightmare-Eclipse published working PoC code on May 13, 2026, got SYSTEM on fully patched Windows 11, and posted the proof. Will Dormann verified it. ThreatLocker verified it. The bug was never actually fixed. The same routine, the same vulnerable code path, the same primitive. Closed ticket, live exploit.

This is MiniPlasma.

## What cldflt.sys Does and Why It Matters

The Windows Cloud Files Mini Filter Driver ships on every modern Windows installation by default. It's the layer that makes OneDrive placeholder files work — those ghost files that show up in Explorer before you've actually synced anything. Because it has to manage the relationship between local placeholder metadata and remote cloud content, it runs with kernel-level privileges and mediates file system operations on behalf of user-mode processes.

The specific function at fault is `HsmOsBlockPlaceholderAccess`. The bug is a race condition in how that routine handles an undocumented API call. By hitting it with an unexpected command at the right moment, a standard (unprivileged) user process can force a structured error path that bypasses the access checks that should be protecting the operation. That bypassed check then allows the process to create arbitrary registry keys inside the `.DEFAULT` user hive — the profile used by `SYSTEM` services — without any elevated privileges.

From there, you pivot to SYSTEM. The path isn't short, but it's reliable enough. Researchers at ThreatLocker confirmed it works consistently on current Windows 11, and the PoC was validated across Windows 10, Windows Server 2022, and Windows Server 2025 as well.

No admin rights. No special hardware. Standard user account, fully patched OS, working SYSTEM shell.

```
C:\> whoami
desktop-lab\user

[miniplasma.exe running]

C:\> whoami
nt authority\system
```

## The CVE-2020-17103 Problem

What makes this interesting beyond the typical "new LPE" post is the history. This isn't a new discovery that Microsoft missed. James Forshaw found it and Microsoft "fixed" it. The fix just didn't fix the right thing.

Nightmare-Eclipse's write-up claims the patch addressed a surface symptom rather than the root cause in `HsmOsBlockPlaceholderAccess`. When they went looking, the actual race window was still there. The undocumented API call still accepted the triggering command. The check was still bypassable.

This happens more than people want to admit. A vendor patches the reported variant of a bug, ships the update, closes the case, and the researcher moves on. Nobody goes back to check whether the primitive itself is gone. CVE-2020-17103 gets marked "fixed" in every scanner in the industry, so nobody looks. Six years pass. A different researcher finds the same underlying issue and exploits it fresh.

Microsoft has not assigned a new CVE to MiniPlasma as of today, May 29. No patch exists. Their advisory for CVE-2026-45585 (YellowKey, a different bug from the same researcher) lists exploitation as "more likely" given the public PoC — but MiniPlasma doesn't even have an advisory yet.

## Who Is Nightmare-Eclipse and Why Do You Need to Know

MiniPlasma is the sixth zero-day released by a researcher operating under the name Nightmare-Eclipse (also Chaotic Eclipse, Dead Eclipse) since early April 2026. The other five, in order: BlueHammer (CVE-2026-33825, a Defender TOCTOU+oplock LPE, patched April 14), RedSun (CVE-2026-41091, a second Defender link-following EoP, patched May 21), UnDefend (CVE-2026-45498, a Defender disruption primitive, patched May 21), YellowKey (CVE-2026-45585, a BitLocker bypass, unpatched), and GreenPlasma (a partial Windows LPE through a different subsystem, unpatched).

Three of those six — BlueHammer, RedSun, and UnDefend — are confirmed actively exploited in the wild. Huntress Labs documented intrusions using the BlueHammer SYSTEM escalation as early as April 10, ten days after the PoC dropped. Activity was tracked to Russian-geolocated infrastructure. By the time Microsoft patched RedSun and UnDefend on May 21, attackers had already been chaining them with ransomware deployment for weeks.

The researcher's stated motivation is personal. Their blog describes an agreement they say Microsoft violated. The posts are specific: their MSRC account was deleted, reports were credited to other researchers, they received no payment. "Someone violated our agreement and left me homeless with nothing." Whether that's accurate, embellished, or entirely fabricated, the exploit code works regardless of the backstory.

GitHub banned the account around May 23. GitLab followed on May 26. On May 28, Microsoft published a blog invoking their Digital Crimes Unit and threatening legal action against anyone who releases uncoordinated PoC code for unpatched vulnerabilities — a position that security community veterans like Katie Moussouris and Kevin Beaumont both called tone-deaf, given that Microsoft's own statement simultaneously claims researchers "are compensated and publicly acknowledged" while responding to one who says they got neither.

Nightmare-Eclipse responded with a promise: something described as a "bone shattering drop" on July 14, which is the next Patch Tuesday. Their exact words: "Mark this date July 14th, I will make sure your bones are shattered that day."

They have also stated they possess RCE vulnerabilities they haven't released yet.

## The Actual Risk Right Now

MiniPlasma is a local privilege escalation. It needs an existing foothold — someone has to be logged in, or an attacker has to already have code execution as a low-privileged user. It doesn't help with initial access.

What it does help with is everything that comes after initial access. A phishing payload running as a standard user gets SYSTEM. A contractor account with minimal rights gets SYSTEM. An EDR evasion payload that needs kernel interaction gets SYSTEM first. In a post-exploitation context, this is precisely what attackers need and exactly why Huntress saw BlueHammer integrated into ransomware chains within days of release.

The scale matters too. Every Windows 10 and 11 machine, every Server 2022 and 2025 box, with no exceptions for patch level. OneDrive integration is on by default. `cldflt.sys` is loaded. The attack surface is essentially the entire Windows installed base.

## What You Can Do Right Now

There is no patch. That's the honest answer. Microsoft hasn't shipped a fix and hasn't committed to a timeline.

What you can actually do:

First, audit who has local interactive access to sensitive systems. MiniPlasma is a local privilege escalation, so reducing local foothold opportunities reduces your exposure. Shared workstations, developer machines with broad network access, systems where contractors authenticate locally — these are your highest-risk endpoints.

Second, look at your OneDrive deployment. If you've disabled OneDrive and the Cloud Files driver isn't loaded, `cldflt.sys` won't be running. This is verifiable: `sc query cldflt` will tell you the driver state. Disabling OneDrive via Group Policy (`Computer Configuration > Administrative Templates > Windows Components > OneDrive > Prevent the usage of OneDrive for file storage`) should prevent the driver from loading on workstations that don't need it.

Third, watch for the exploitation pattern. The MiniPlasma PoC creates registry keys under `HKEY_USERS\.DEFAULT`. Unexpected writes to that hive from user-mode processes are not normal behavior. Your EDR should be able to surface that. If it can't, that's a gap worth addressing before July 14.

Fourth, stay current on Microsoft's patch release cycle. Whatever drops on July 14 may or may not include a MiniPlasma fix — but the threat of additional RCE disclosure makes that Patch Tuesday worth watching more closely than most. Apply updates fast when they arrive.

The gap between Forshaw's 2020 report and today is a good reminder that "patched" on an advisory doesn't always mean what it says. Patch the variant, miss the primitive, close the ticket. Six years later, someone checks.

---

**References:** [Bleeping Computer - MiniPlasma](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/) | [ThreatLocker Analysis](https://www.threatlocker.com/blog/miniplasma-windows-privilege-escalation-zero-day-affects-fully-patched-systems) | [The Register - July 14 threat](https://www.theregister.com/security/2026/05/28/microsoft-0-day-feud-escalates-as-researcher-threatens-another-windows-exploit-dump/5248085) | [Barracuda - Nightmare-Eclipse profile](https://blog.barracuda.com/2026/05/19/nightmare-eclipse-zero-days-grudge) | [CSO Online - 2020 resurface](https://www.csoonline.com/article/4172320/patched-windows-bug-resurfaces-6-years-later-as-working-system-level-exploit.html)
