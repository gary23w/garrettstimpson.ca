---
layout: post
title: "Microsoft Defender was uploading my unreleased programs"
date: 2026-11-11 11:33:00 -0500
author: Garrett Stimpson
categories: [security, privacy, windows]
tags: [windows-11, microsoft-defender, telemetry, copilot, hodometer, sentinel, network-monitoring, blue-team]
excerpt: "Defender logged 217 file uploads from my PC in three months. Most were a Go test binary I kept rebuilding; others were programs I hadn't released. I found them while investigating network traffic with Hodometer."
description: "Hodometer led me to 217 Microsoft Defender sample uploads, including my own test binaries and unreleased programs. The event log, the default setting behind it, and how to check your PC."
---

Microsoft Defender's event log recorded 217 file uploads from my PC over three months. Of those, 201 entries were for a Go test binary I kept rebuilding. Most of the other 16 were programs I'd written and hadn't released. I hadn't seen a prompt for any of them.

I found this while trying to work out why my connection was lagging. I used [Hodometer](https://github.com/gary23w/hodometer), a Windows tray tool I built to track traffic by process and destination.

Microsoft's programs accounted for 4.7 percent of downloads and 4.5 percent of uploads across about 100 hours. Most of the traffic was my browser, development tools and game patches. But Defender's uploads needed a closer look.

## Following the Defender uploads

`MpCmdRun.exe`, Defender's command-line utility, sent 224 MB to Azure storage in one day. The uploads came in bursts of around 28 MB a minute, with very little traffic coming back.

The traffic was encrypted, so the network capture couldn't tell me which files were being sent. Defender's own Operational log could. Event 2050 reports:

> Microsoft Defender Antivirus has uploaded a file for further analysis

The entries included file names and hashes. That's where the 217 uploads came from, and how I identified my own builds among them. On the busiest day, Defender logged 75 submissions.

Windows' per-app data usage records put `MpCmdRun.exe` at 2.8 GB uploaded over the last 30 days, about 80 percent of this PC's uploads to Microsoft in that period. That's the process's total traffic; I can't assign all 2.8 GB to the files listed in those events.

## The default includes executable files

[Microsoft documents automatic sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission). The default is "Send safe samples automatically." Its examples of safe samples include `.bat`, `.scr`, `.dll` and `.exe` files. Here, safe means unlikely to contain personally identifiable information.

I don't consider an unreleased program a safe thing to upload just because it probably lacks personal information. I wrote it, I haven't published it, and I want to decide whether Microsoft gets a copy.

New, unsigned binaries are a normal part of working on software. In my case, repeated builds of one test program made up almost all the submissions. I only learned about them after checking network traffic and an event log.

## Copilot and the remaining telemetry

The connection audit also showed Copilot activity around sign-in. Across 22 hours of records, it made connections during three hours, each corresponding to a sign-in, with 41 to 54 connections each time. I hadn't opened the app, and I couldn't find an enabled startup entry for it. I haven't established what launched it.

Copilot's monthly traffic was small: 31 MB down and 6 MB up. What bothered me was that an app I wasn't using was making connections when I signed in.

I'd already disabled the main Windows telemetry service on this PC. Its records showed no upload for three months. That hadn't stopped `devicecensus.exe` from running twice in one morning, or Defender's core service from making 104 connections in 22 hours to `ecs.office.com` and `mobile.events.data.microsoft.com`. Office and OneDrive helpers also connected to the latter host, and the queued error-reporting task ran that morning.

Those records show which programs connected and where. They don't reveal the contents of encrypted requests. The traffic was also a tiny part of the total: in a separate 15-minute capture, Microsoft destinations accounted for 0.9 MB out of 343 MB. Disabling that one service clearly hadn't stopped the other components from communicating.

## How I used Hodometer

An AI agent did most of the digging. I approved it as a client on Hodometer's local socket, where it could read process history, inspect connections and capture packets. It picked out Defender's upload, then read the Windows event log to identify the files.

That's why I built the socket interface: I wanted an agent to have access to the traffic data instead of needing me to copy it out of a window. The [Sentinel design](https://github.com/gary23w/hodometer/blob/main/SENTINEL.md) in the same repository describes using it for continuous monitoring.

## Check your own machine

You can check Defender's upload log without installing Hodometer. This PowerShell command shows Event 2050 entries from the last 90 days:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 2050
    StartTime = (Get-Date).AddDays(-90)
} | Select-Object TimeCreated, Message | Format-List
```

Check the file paths in those messages. That's how I found my builds.

To watch the traffic, download `Hodometer.exe` from the [releases page](https://github.com/gary23w/hodometer/releases) and run it as administrator. Find `MpCmdRun.exe` in the process table and double-click it to inspect its connections. You can export a capture of that process's packets as pcapng for Wireshark. An Azure storage connection alone doesn't identify a sample upload; check it against the Defender events.

The relevant setting is **Automatic sample submission**, under **Windows Security → Virus & threat protection → Manage settings**. Microsoft's documentation says disabling it also disables block at first sight based on sample analysis. Detection metadata is still sent, so turning it off doesn't stop all communication with Microsoft, and you lose that part of Defender's protection.

On a machine where I'm building unreleased software, I want a prompt before those files leave the PC.
