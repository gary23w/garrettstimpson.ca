---
layout: post
title: "Keystrokes, Hidden IDs, and the Right to Not Be Watched"
seo_title: "Sentinels and the user-facing surveillance nobody classifies as malware"
author: Garrett Stimpson
date: 2026-11-16 08:00:00 -0500
categories: [privacy, projects]
tags: [sentinels, surveillance, privacy, gdid, windows, keystroke-logging, mouse-hijacking, ai-slop, engagement-algorithms]
excerpt: "Malware is not the only thing that watches your keystrokes and hijacks your mouse. Legitimate software does it too, with your permission. Sentinels is going to start treating user-facing telemetry like the attack surface it is."
description: "Why surveillance, not just malware, is the security problem of the decade: Windows hidden GDID tracking, AI assistants that read your keystrokes, and what Sentinels can do about the user-facing layer."
permalink: /posts/2026/11/16/keystrokes-hidden-ids-and-the-right-to-not-be-watched/
---

I write a lot about break-ins. Remote code execution, kernel bugs, infostealers, the whole catalog of things that get into your machine without asking. This post is about the stuff that gets in because nobody stopped it, and because in most cases you clicked agree.

There are two classes of software that watch what you do. The first is malware, and the entire security industry exists to fight it. The second is the software that does the exact same things - reads your keystrokes, tracks your mouse, fingerprints your machine, follows you across the network - but carries a brand name and a terms of service. Nobody classifies the second class as an attack. It should be.

## The user-facing layer

Sentinels started as a host intrusion detector: it watches processes and connections, and it ends an attack while the attack is still starting. But the same thinking applies to the layer the user actually touches. Keystroke logging. Mouse hijacking, where a window steals focus or drags your cursor somewhere you did not send it. Screen scraping. Clipboard reading. All of that is user-facing telemetry, and all of it is trivially available to any program running on the machine.

For decades the rule was: malware does those things, so we built defenses that trigger on them. Then AI assistants arrived, and now a whole category of "helpful" software reads your keystrokes openly, watches what you click, and records what is on your screen, and users allow it. The permission prompt made it legitimate. The behavior did not change.

Here is the principle I want Sentinels to enforce: anything that captures keystrokes, hijacks the mouse, or scrapes the screen should be treated as hostile until proven otherwise. An immediate kill of the service, strictly analyzed before anything executes. Not a warning banner. Not a checkbox at install time. If a program wants to watch the user, it should have to survive real scrutiny first, the same way a program that wants to open a listening port has to survive a firewall.

## Windows has a hidden ID for you

While I was thinking through this, Windscribe published a piece that belongs in the same bucket. Windows assigns every user a hidden, persistent advertising identifier called the GDID, and it gets baked into your Microsoft account and follows you across the operating system. Windscribe built a tool called deGDID to block it. Their writeup is worth reading in full: [Windows tracks you with a hidden ID, so we built deGDID to block it](https://windscribe.com/blog/windows-tracks-you-with-a-hidden-id-so-we-built-degid-to-block-it/).

Microsoft's stated position is that the GDID is used inside hostile events, whatever that means. We all know otherwise. This is a tracking identifier that persists on the machine of a person who never asked for it, built by a company whose operating system is on most of the computers on Earth. Any sufficiently motivated intern can zoom in on 90 percent of the global population using infrastructure that ships with the OS. That is not a vulnerability. It is a product decision, and it is the same product decision that the whole surveillance economy is built on.

## Why this matters more than a zero-day

Here is the part that does not get said enough, so I will say it plainly.

People hate being watched. This is not a preference, it is a mechanism. It is critically known that when a person is watched, they change. They lock up. They conform to the surveilled environment, and they do not grow or create new things. The chilling effect is not a theory, it is one of the best-documented results in social science. Surveillance does not just cost privacy. It costs the output of the person being watched.

Freedom from surveillance is a human right. It is something everyone should get for free, no questions asked. Being a human is maintenance, and it is hard for most people. That maintenance requires peace of mind, and it requires privacy. When a person or a company intrudes on that privacy, the human being stops operating properly. We cannot have Meta, Reddit, Google, and Microsoft quietly destroying the conditions people need to think.

There is a deeper layer too. A person grows by experiencing the low, embarrassing feelings: remorse, guilt, shame. Our biggest adaptations come from acknowledging those events and overcoming them. A person under 24/7 surveillance loses the private space where those events happen and get processed. The right to feel bad in private, and come out the other side, is part of the deal. Take it away and people stop growing. They regress. People are now so worried about what "something" will think that they do not even attempt entirely.

You can see the regression in the output. Compare the quality of human work a hundred years ago to now. The population is several times larger, so by any sane measure there should be several times the quality content. There is not. The obvious explanation is that the technology is always watching. Phones, laptops, platforms, always learning, always profiling. For what? Most of the people being watched never buy anything anyway. Somewhere in the 1980s someone decided the way to grow a business was to watch everybody and sell what they do. Look where that got us.

And then there is the content itself. Short video, engagement algorithms, and the onslaught of AI slop. Writing an engagement algorithm is not hard work. Any competent engineer can build one in an afternoon. The hard part of a platform used to be the community. Now the community is an input to a retention curve, the feed is optimized to hold attention rather than earn it, and the output is a population that scrolls for hours and remembers nothing. That is not a design failure. That is the design.

## What we are going to do about it

The surveillance economy will stop, and that time is coming sooner than the companies running it think. In the meantime, defense has to move down the stack to where the user lives.

For Sentinels, that means three things:

1. **Watch the user-facing vectors.** Keystroke capture, mouse and focus hijacking, screen scraping, clipboard access. These are observable behaviors, and a sentinel on the machine can see them happen in real time.
2. **Default to kill, then analyze.** A service that starts capturing user input gets stopped first and explained second. The burden of proof belongs on the software, not on the person using the machine.
3. **Treat persistent identifiers as hostile configuration.** Hidden IDs like the GDID are exactly the kind of thing a sentinel should surface, block, and report in plain sentences, the same way it reports a cron job a web shell left behind.

The goal is the same as it has always been with this project: a machine that defends the person using it. Not the vendor, not the advertiser, the person. Privacy is important. Humans will not thrive under 24/7 surveillance, and no thrive means no new content, no new ideas, no new anything. Let's solve this asap.

- Agent Garrett
