---
layout: post
title: "Caught Microsoft Red-Handed with Hodometer"
date: 2026-11-11 11:33:00 -0500
author: Garrett Stimpson
categories: [security, privacy, windows]
tags: [windows-11, microsoft-defender, telemetry, copilot, hodometer, sentinel, network-monitoring, blue-team]
excerpt: "Microsoft Defender uploaded my unreleased programs to Microsoft 217 times in three months. I only know because I built a tool that lets an AI watch the wire. If you compile anything on Windows, go and check yours."
description: "Garrett Stimpson used Hodometer to catch Microsoft Defender uploading his own compiled programs to Microsoft, and a Copilot app starting itself at every sign-in. What was taken, how it was found, and how to check your own machine."
---

A while back my connection started lagging for no reason I could see, with the router getting hammered by something I couldn't name. I got tired of guessing which program to blame.

So I pointed [Hodometer](https://github.com/gary23w/hodometer) at it.

Hodometer is a Windows tray tool I built that shows exactly which program is sending and receiving bytes, and where they're going. I left it running for a few days and went looking for a culprit.

The first thing it told me was not what I wanted to hear. Across about 100 hours, Microsoft's programs were 4.7 percent of my download and 4.5 percent of my upload. The rest was me. Browser, dev tools, game patches. Fine. Guilty.

Then I looked at what was actually inside that 4.5 percent, and I stopped feeling guilty pretty quickly.

## The upload that had no business being there

One row didn't belong. `MpCmdRun.exe`, which is Microsoft Defender, had pushed 224 MB up to Azure storage in a single day. It went in bursts of about 28 MB a minute, scattered across the day, and almost nothing came back down.

Think about that for a second. Antivirus definitions are a download. This was an upload, and every burst was roughly the size of a file.

This is the bit other tools can't give you. Wireshark will happily show you ten thousand packets and not one word about which program sent them. Hodometer reads the packets off the wire and pins each one to a process, picks up the real host names from the DNS lookups and the handshakes, and will dump one program's traffic, and only that program's, to a pcapng you can keep.

So now I had Defender, by name, shoving file-sized uploads at named Microsoft storage hosts, logged minute by minute. The contents were encrypted on the way out, which is true for any tool on earth that isn't holding Microsoft's keys. One question left: which files?

Turns out Defender keeps a diary. Event 2050 in its own log reads, word for word, "Microsoft Defender Antivirus has uploaded a file for further analysis" and then gives you the file name and the hash.

I had 217 of them in three months.

201 of them were the same Go test binary, rebuilt and sent again every time my tests ran. The other 16 were mostly programs I built and haven't released. On the worst day it uploaded 75 times.

Windows keeps its own per-app data ledger, so I could put a size on it. In the last 30 days `MpCmdRun.exe` uploaded 2.8 GB. By my adding up that's around 80 percent of everything this PC sent to Microsoft that month.

The single biggest thing Microsoft got from my computer was my own work.

## They wrote it down. I'm still calling it stealing.

I have to be fair here, and I don't enjoy it.

Microsoft documents this. It's called automatic sample submission, the default is "Send safe samples automatically", and their own page defines safe samples as ones "considered to not commonly contain PII data". The examples it gives are `.bat`, `.scr`, `.dll` and `.exe`. [The full table is on Microsoft Learn.](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission)

If you write software, read that list twice. An `.exe` is a "safe sample." To Microsoft that means there's probably no personal data in it. To me it means the thing I've been building all month.

Nobody asked me. I never saw a prompt. The only record I could find is an event log that practically nobody opens. And the worst part is how well it fits: a brand new unsigned binary is exactly what a cloud antivirus is hungry for, and a compiler spits one out every few minutes. For most people that default is harmless. For a developer it's a hose pointed straight at the build folder.

You can call that whatever you like. I call it taking my work without asking, and the switch that did it is the Windows default, so if you build anything on a Windows machine, it's very likely doing it to you as well.

## Copilot let itself in

The second catch came from the Windows connection audit log, which Hodometer keeps switched on for you. Every connection, stamped with the program that made it.

Over 22 hours the Copilot desktop app was awake in exactly three of them. Those were the three hours I signed in. Each time it made between 41 and 54 connections to Microsoft before I'd touched a thing. I never opened it, and when I went looking for an enabled startup entry I couldn't find one.

It hardly moved any data, 31 MB down and 6 MB up over a month. I don't care about the megabytes. An app I don't use was getting up every time I sat down and phoning home, and I'd never have known.

## "Telemetry off" turns off one thing

I'd already killed the main Windows telemetry service on this box. Its own records say the last upload was three months ago. Job done, I thought.

Not even close. With that service dead, `devicecensus.exe` still ran twice in one morning. Defender's core service made 104 connections in 22 hours to `ecs.office.com` and `mobile.events.data.microsoft.com`, which is a telemetry intake. Office and OneDrive helpers were hitting the same intake. The task that uploads queued error reports ran that morning too.

None of it is big. In a 15 minute live recording, everything headed to Microsoft came to 0.9 MB out of 343 MB. But I turned off the thing with "telemetry" in its name and found four more doing a version of the same job. That's the game.

## Why Hodometer exists: so an AI can see

Here's the part I care about most.

I didn't catch any of this by squinting at a table all week. Hodometer has a local socket that streams everything it sees as JSON, to programs I've explicitly allowed and nothing else, and it takes orders back: list the processes, inspect this one, watch its handshakes, capture its packets, kill it, block it.

That socket is the whole reason the tool exists. I wanted an AI to be able to truly see what Microsoft is up to on my own machine, with the same view I've got.

So for this one I put an AI agent on the socket and told it to work out what was eating my bandwidth. It pulled the per-process history, picked out the Defender upload, and went and read the event log. I got the answer handed to me.

Sentinel is the always-on version of that, and the design ships in the same repo. A plain daemon follows the entire stream and scores every process. A coordinator reviews every program that reaches the internet. Investigators hook the suspicious ones, dig through their packets, and can block or kill a harmful process tree under hard limits.

Hodometer is the eyes and Sentinel is the thing behind them that never looks away. Put the two together and Windows doesn't get to do things quietly on your machine any more.

## Go catch them yourself

Don't take my word for it. Run it.

Grab `Hodometer.exe` from the [releases page](https://github.com/gary23w/hodometer/releases). It's one native executable, and the source is a single C file in the same repo if you'd rather read it before you run it. It needs admin, because it reads the kernel's own network events.

Leave it in the tray and get on with your day. Build something, run your tests. Then open the window and find `MpCmdRun.exe` in the process table. If it's showing megabytes going out to a `blob.core.windows.net` host, you're looking at exactly what I was looking at.

You don't have to babysit it either. It throws a tray alert when upload spikes past a threshold you set, and logs which programs did it.

Double-click the row for the Inspector. Every connection that one process has made, the host on the other end, how much went each way, and its packets decoded live as they go by: TLS hellos with the server name, DNS lookups, plain HTTP requests, QUIC. One button captures 30 seconds of just that program's traffic to a pcapng, so you've got evidence you can open in Wireshark and put in front of someone. And if you find a program you don't want talking at all, you can kill it or block it at the Windows Firewall right there.

Once Hodometer has shown you the upload, make Defender tell you which files it took:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 2050
} | Select-Object TimeCreated, Message
```

If file names you recognise scroll past, it has your work too.

The switch is in Windows Security under Virus & threat protection settings, and it's called Automatic sample submission. Know what it costs before you flip it: Microsoft says turning it off also turns off block at first sight, and that metadata about detections gets sent regardless. On a machine that builds unreleased software I think that's a trade worth making. On the family laptop I'd probably leave it.

Then leave Hodometer running. I only found any of this because one number in a table looked wrong.

Garrett
