---
layout: post
title: "I had some time on my lunch break, so I killed ARTEX"
date: 2026-11-14 12:30:00 -0500
last_modified_at: 2026-11-15
categories: [projects, security]
tags: [intrusion-detection, malware-removal, open-source, cloudflare-workers, python, d1, agent-garrett, sentinel, artex]
excerpt: "I spent my lunch break building something to get an AI intruder off your machine. Sentinel can stop hostile programs, quarantine implants and disable their startup hooks. It's free, MIT licensed, and you can keep running it indefinitely."
description: "Built on my lunch break: free intrusion protection that stops hostile programs, quarantines implants and disables their startup hooks. Run it on your own hardware."
permalink: /posts/2026/11/14/i-had-some-time-on-my-lunch-break-so-i-killed-artex/
---

I read the FBI's warning about ARTEX and other agentic intrusion frameworks, got annoyed, and built [Agent Garrett Sentinel Service](https://github.com/gary23w/agent-garrett-sentinel-service) on my lunch break.

Yes, my lunch break. Apparently this is how I relax now.

The warning describes intruders using AI to work through a compromised network: run a command, inspect the result, try something else, steal credentials, move to the next machine. That is a miserable thing to leave running while an alert waits for somebody to open it.

I wanted something that could catch the activity and kick the attacking program off the machine immediately. The current release, [v0.3.0](https://github.com/gary23w/agent-garrett-sentinel-service/releases/tag/v0.3.0), also cleans up the files and startup hooks it can tie to that program, so it has a harder time coming back.

You can install it today, run it on your own hardware, and keep using it indefinitely for free. The code is MIT licensed. You don't need an account with me or a paid AI model to make the protection work.

## ARTEX still has to do things on a computer

An AI intruder can change its approach. It still needs processes, connections and tools to get anything done.

A web server suddenly launching a shell, downloading a payload and calling out to another machine gives you something to work with. So does a document starting encoded PowerShell. So does a foothold firing off a stream of different commands, retrying nearly the same thing over and over, or running commands in parallel at machine speed.

Sentinel watches those behaviours and scores the evidence locally. A HOSTILE verdict requires signals across at least three categories. An address from the FBI advisory is one clue; it doesn't get to convict a program by itself.

In the default `kill` mode, Sentinel ends the hostile program and the processes it started. It has safeguards around system processes, security software and the applications you're using, so it targets the attacking children rather than casually taking out your browser or web server along with them.

The detection and response happen on the machine. Losing contact with the service doesn't send the agent home for the day.

## Kill it, then deal with what brings it back

Stopping malware feels great until the scheduled task starts it again thirty seconds later.

Version 0.3.0 deals with that. After Sentinel stops an attacking program, it can:

- **Quarantine its dropped file** in the locations the cleaner handles, including temporary folders, user folders and web roots, and end other running copies of that file.
- **Disable the persistence pointing at it:** systemd services, cron jobs, login items, LaunchDaemons and shell startup lines; on Windows, `Run` and `RunOnce` entries, scheduled tasks, services and Startup items.
- **Disable startup entries calling known attacker addresses**, including cases where the attacker never dropped a separate executable.
- **Flag changed sign-in keys, accounts and administrator settings on Linux and macOS** for you to review.

For an implant it catches in those locations, that's real removal: stop it, quarantine the payload and pull out the supported startup hooks. The same cleanup works whether an AI or a person put it there.

Cleanup is recorded under the case and is reversible. Files go into quarantine rather than being permanently deleted. On Linux and macOS, `sudo garrett restore <case>` puts the quarantined files and disabled entries back if you need to undo it. Ending the process itself is still final; restoring its files won't recover unsaved work.

There are limits to what that cleanup can establish. It won't tell you what an intruder already copied, repair every file they edited, or automatically remove accounts and keys. A renamed payload can escape the link to the stopped program. If credentials were exposed, rotate them. Getting the implant off the box is useful work; checking the rest of the compromise is still your job.

## It catches ordinary malware, too

An attacker doesn't need an AI subscription to launch a reverse shell. Sentinel watches for the activity either way.

A conventional virus, loader or remote-access implant can trip the same behavioural detections. ARTEX doesn't get special treatment.

Its detections cover suspicious email and document launches, loaders abusing tools such as `mshta` and `rundll32`, implants calling home, credential theft, Kerberoasting, DCSync patterns, remote execution and movement between Windows machines. It also watches for tunnelling tools, bursts against remote-access services, and web shells appearing in watched web folders. With access logs configured, it can flag attacks against the web application as well.

On Windows, new Microsoft Defender detections become Sentinel cases too. Keep your antivirus running: Defender contributes its malware detections, and Sentinel adds the process activity, response and cleanup described above. Sentinel's own detection is based on behaviour; it isn't a full-disk virus scanner.

The useful part is that a malware author can change a name or rebuild a binary and still leave the same ugly sequence of actions behind. Sentinel gives you a way to catch that sequence without waiting for a signature for that exact file.

## Free, for as long as you want to run it

I mean the working protection, including stopping programs and cleanup. The released code has no trial clock, licence expiry or per-machine fee. You can keep it, inspect it, change it and run it indefinitely under the [MIT licence](https://github.com/gary23w/agent-garrett-sentinel-service/blob/main/LICENSE).

For one machine, install the agent and leave it running. It protects that machine and keeps the cases locally. You can read them with `garrett cases`.

For several machines, you can run the service on your own Linux or Windows machine. It uses Node.js and a local SQLite database. The installer generates the keys and HTTPS certificate and gives you the commands to join the other machines. Your existing hardware is enough to get started; there is no mandatory hosting or model bill attached to it.

Cloudflare Workers and D1 are another deployment option. An AI analyst is optional too, if you want case summaries or a model helping decide what to do with a paused program. Those services can have their own costs. Detection, stopping and cleanup work without them.

Free indefinitely means you can keep running the software. You still need to install updates and review what it's doing as your machines and the threats change.

## Put it on a machine

On Linux or macOS, this installs the agent in its default mode, which **can stop programs and clean up after them immediately**:

```bash
curl -fsSL https://gary23w.github.io/agent-garrett-sentinel-service/install.sh | sudo sh
```

On a work machine or server, I'd watch its decisions first. Install in `report` mode:

```bash
curl -fsSL https://gary23w.github.io/agent-garrett-sentinel-service/install.sh | sudo sh -s -- --mode report
```

Then read `garrett cases` and decide where you're comfortable enabling a response. `report` only watches; `pause` freezes a hostile program for an operator; `decide` freezes it while the optional model considers it; `kill` stops it at once. Cleanup runs after a stop, with cleaning enabled by default.

On Windows, grab `garrett-windows.zip` from the [latest release](https://github.com/gary23w/agent-garrett-sentinel-service/releases/latest), unpack it and run `Install garrett.cmd`. It includes Python. The bundle isn't code-signed yet, so expect a Windows warning. Run with administrator or root rights for the full view of the machine.

If you want your own fleet service, the Linux installer is:

```bash
curl -fsSL https://gary23w.github.io/agent-garrett-sentinel-service/service.sh | sudo sh
```

The [README](https://github.com/gary23w/agent-garrett-sentinel-service#your-own-service-in-one-line) has the Windows service installer and enrolment instructions. Once agents are joined, a stopped or confirmed attack can teach the other machines about its public destinations. Enable `FLEET_BLOCK` to block those shared addresses across eligible agents. The coverage map also shows which neighbouring machines are missing an agent, so you know where the gaps are.

## What has actually been run

The project is released and still young. The current version has a [passing verification workflow](https://github.com/gary23w/agent-garrett-sentinel-service/actions/runs/43665930348) covering hosted Ubuntu, macOS and Windows Server machines.

The checks exercise installation, a stand-in attack being stopped and recorded, fleet blocking, the self-hosted service, and removal. Cleanup checks use harmless files with real startup entries, then verify quarantine, disabling and restoration. A staged Linux implant was also stopped, quarantined and stripped of its cron job and startup service using the published package.

Those are controlled tests. I haven't demonstrated a live ARTEX takedown or a production fleet deployment, and the Windows and macOS cleanup checks haven't yet gone through a full staged attack from detection to cleanup. Desktop Windows editions and Macs outside the hosted test image still need their own testing. The [release notes](https://github.com/gary23w/agent-garrett-sentinel-service/releases/tag/v0.3.0) spell that out.

What you can get right now is a working, free tool that watches for intrusion activity, can stop the attacking processes, and can quarantine their files and disable the startup entries it recognises. You can use it on one box or join machines to a service you control.

I built it on my lunch break. You can spend yours putting it between your machines and somebody else's AI.
