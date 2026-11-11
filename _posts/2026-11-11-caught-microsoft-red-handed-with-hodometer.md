---
layout: post
title: "Caught Microsoft Red-Handed with Hodometer"
date: 2026-11-11 11:33:00 -0500
author: Garrett Stimpson
categories: [security, privacy, windows]
tags: [windows-11, microsoft-defender, telemetry, copilot, hodometer, sentinel, network-monitoring, blue-team]
excerpt: "Defender logged 217 file uploads from my PC, including unreleased builds. I also found that sample submission had been switched back on less than two hours after I disabled it. I haven't established what changed it."
description: "Defender's logs showed uploads of my own builds, a sample submission setting that changed back, and full command lines in local reporting records. How I found them with Hodometer and what the evidence shows."
---

Microsoft Defender uploaded programs I'd written and hadn't released. Its event log recorded 217 sample submissions from my PC over three months. I hadn't seen a prompt for any of them.

I found them while investigating a lagging connection with [Hodometer](https://github.com/gary23w/hodometer), a Windows tray tool I built to track traffic by process and destination.

Microsoft's programs accounted for 4.7 percent of downloads and 4.5 percent of uploads across about 100 hours. Most of the traffic was my browser, development tools and game patches. Defender's uploads stood out when I looked at the individual processes.

## What Defender uploaded

`MpCmdRun.exe`, Defender's command-line utility, sent 224 MB to Azure storage in one day. The uploads came in bursts of around 28 MB a minute, with very little coming back.

The traffic was encrypted. To identify the files, I checked Defender's Operational log. [Event 2050](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus#event-id-2050) records sample submissions with a file name and SHA-256 hash. The message on my machine read:

> Microsoft Defender Antivirus has uploaded a file for further analysis

Of the 217 entries, 201 were builds of the same Go test program. Most of the other 16 were programs I'd built and hadn't released. There were 216 different hashes across the submissions; these were mostly fresh binaries, not repeated uploads of an unchanged file. On the busiest day, Defender logged 75 submissions.

Defender's support log explained the sequence for the uploads it covered. The test binary triggered a low-confidence signature, Defender queried the cloud, and the response supplied an upload address on `blob.core.windows.net`.

Windows' per-app data usage records put `MpCmdRun.exe` at 2.8 GB uploaded over the last 30 days, about 80 percent of this PC's uploads to Microsoft in that period. That's the process's total traffic. I don't have a byte count for each submitted file.

## What Microsoft means by safe samples

[Microsoft documents this behaviour](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission). The default is "Send safe samples automatically." Its examples include `.bat`, `.scr`, `.dll` and `.exe` files. Safe, in this context, means unlikely to contain personally identifiable information. Files judged likely to contain personal data are supposed to require a prompt.

I object to uploading my unreleased builds under that default. The absence of personal information doesn't tell Microsoft whether I'm willing to share the program.

New binaries are a normal part of development. In my case, running tests kept producing new builds of one program, and those builds made up almost all the submissions. I only learned about them after checking the traffic and the logs.

## Sample submission changed back after I disabled it

On October 28, I ran `Set-MpPreference -SubmitSamplesConsent 2` to disable sample submission. At 17:56, Event 5007 recorded the change from value `1`, send safe samples automatically, to `2`, never send.

At 19:53 that evening, another entry recorded the reverse: `2` back to `1`.

I don't know what changed it back. I couldn't find anything I'd run that would reset it, and the logs needed to identify the responsible process had already rotated out. A quick scan started under my account nine seconds after the change, so a click in Windows Security is one possible explanation.

There were no sample uploads logged during the nearly two hours it was disabled, and 25 after it was enabled again. I'd turned submission off and hadn't realised the setting had changed back.

## Other files in the logs

The submissions also included a Python script from my Recycle Bin, uploaded in August.

In November, Microsoft's cloud supplied an upload address for a `.tmp` data file belonging to a local development database. That attempt failed; it wasn't a completed upload. I hadn't seen a consent prompt for either file.

The extensions in Microsoft's documentation are examples, so a Python script being selected doesn't by itself contradict the policy. Check scripts and data files as well as compiled programs when you review the logs.

## Full command lines in the support log

Over four days, Defender's support log contained 85 entries marked "command line reported as lowfi." They included full `curl` and PowerShell command lines. Seventy-eight contained my user folder and project folder names. An older detection record also held a command line containing text I'd typed into another program.

Microsoft's cloud-protection documentation says the metadata contains no personal data and that file names are hashed. My local logs contained the full paths. I couldn't determine whether those strings were hashed or otherwise changed before transmission, so those records don't establish that Microsoft received the command lines exactly as I saw them.

Defender also made 1,802 cloud requests during those four days. That is a request count, separate from the 217 file submissions across three months.

## Copilot and the other connections

The Windows connection audit showed Copilot activity at each of the three sign-ins in a 22-hour period. Each time, it made between 41 and 54 connections to Microsoft. I hadn't opened the app and couldn't find an enabled startup entry for it. I haven't identified what launched it.

The monthly traffic was small: 31 MB down and 6 MB up. I still wanted to know why an app I wasn't using was making connections when I signed in.

I'd already disabled the main Windows telemetry service on this PC. Its records showed no upload for three months. Other components continued to connect: `devicecensus.exe` ran twice in one morning, and Defender's core service made 104 connections in 22 hours to `ecs.office.com` and `mobile.events.data.microsoft.com`. Office and OneDrive helpers also connected to the latter host. The queued error-reporting task ran that morning too.

The connection records identify programs and destinations, not the contents of encrypted requests. And this wasn't a large share of my bandwidth: in a separate 15-minute capture, Microsoft destinations accounted for 0.9 MB out of 343 MB. Disabling that one telemetry service hadn't stopped the other components from communicating.

## How I used Hodometer

An AI agent did most of the digging. I gave it access to Hodometer's local socket, which requires my approval before a client can connect. It used the process history to identify Defender's upload, then read the Windows logs to find the files involved.

I built that interface because I wanted an agent to investigate traffic directly. It can inspect connections and handshakes, capture one process's packets, and issue kill or firewall-block commands. The [Sentinel design](https://github.com/gary23w/hodometer/blob/main/SENTINEL.md) in the same repository describes using the interface for continuous monitoring and investigation.

## Check the logs on your PC

You can check Defender's submissions without installing Hodometer. This shows Event 2050 entries from the last 90 days:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 2050
    StartTime = (Get-Date).AddDays(-90)
} | Select-Object TimeCreated, Message | Format-List
```

Check the file paths in those messages. To look for changes to sample submission in the same period:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 5007
    StartTime = (Get-Date).AddDays(-90)
} | Where-Object Message -match 'SubmitSamplesConsent' |
    Select-Object TimeCreated, Message | Format-List
```

[Value `1` means send safe samples automatically; `2` means never send.](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference#-submitsamplesconsent) These queries can only show events still retained in the log.

To watch the traffic, download `Hodometer.exe` from the [releases page](https://github.com/gary23w/hodometer/releases) and run it as administrator. Find `MpCmdRun.exe` in the process table and double-click it to inspect its connections. You can export that process's packets as pcapng for Wireshark. A connection to Azure storage alone doesn't identify a sample upload; check it against the Defender records.

The setting is **Automatic sample submission**, under **Windows Security → Virus & threat protection → Manage settings**. Microsoft says disabling it also disables block at first sight based on sample analysis. Detection metadata is still sent. On a development machine, I want control over which builds leave the PC, but changing this setting does give up part of Defender's protection.

If you build software on Windows, check your build paths in the submission log and the history of that setting.
