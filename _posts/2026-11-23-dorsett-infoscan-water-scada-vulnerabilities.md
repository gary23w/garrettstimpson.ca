---
layout: post
title: "The Water Utility Software That Shipped a Map of Its Own Customers"
seo_title: "Dorsett InfoScan Flaws (ICSA-26-321-01): Water Utility Guide"
author: Garrett Stimpson
date: 2026-11-23 06:00:00 -0500
categories: [security, vulnerabilities]
tags: [dorsett-controls, infoscan, scada, water-utilities, wastewater, ics-advisory, icsa-26-321-01, critical-infrastructure, hard-coded-keys, electron, cve-2026-117659, cve-2026-120157, cve-2026-120255, cve-2026-120260, cve-2026-120271, cve-2026-120298]
excerpt: "CISA quietly published six flaws in InfoScan, SCADA software used by water and wastewater systems. Each one scores as medium. Put together, they read like an attacker's planning kit. Almost nobody covered it."
description: "CISA advisory ICSA-26-321-01 covers six vulnerabilities in Dorsett Controls InfoScan 1.45.0 and earlier, SCADA software for water and wastewater: leaked customer hostnames, a hard-coded database key, MFA status exposed without login, and an Electron client that trusts any certificate. Fixed in 1.46. What operators should do now."
permalink: /posts/2026/11/23/dorsett-infoscan-water-scada-vulnerabilities/
---

Nobody breaks into a water plant on the first try. They do homework first. Which towns run what software. Where the servers live. Which accounts skip the second login factor. Where the password is kept.

Now imagine the software vendor did a lot of that homework for them, and gave it away for free.

On November 17, 2026, CISA published advisory [ICSA-26-321-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-321-01) for **InfoScan**, a SCADA system made by **Dorsett Controls**. It lists six vulnerabilities in InfoScan **1.45.0 and earlier**. CISA names the sector plainly: **Water and Wastewater Systems**, deployed worldwide.

At the time of writing, a news search turns up three results. A line in a daily roundup, an aggregator, and one Spanish outlet. No major security site has written it up. I think that is a mistake, and I think I know why it happened.

## Why it slipped past everyone

The top score in this advisory is 8.1. The rest sit between 4.3 and 5.5. In a week full of 9.8s, nothing here screams.

That is the trap. Security news runs on single scary numbers. Real intrusions run on chains of boring ones. Read these six together and the picture changes.

## What InfoScan is

From [Dorsett's own product page](https://dorsettcontrols.com/infoscan-scada-systems/), InfoScan is the company's SCADA platform for water, stormwater, wastewater, HVAC and building control. SCADA is the software operators use to watch and run physical equipment: pumps, tanks, lift stations, alarms. Dorsett pitches it on free lifetime upgrades, no license fees, and web and mobile access so staff can "monitor and control from anywhere, including from a tablet or mobile phone."

That last part matters. Remote access is a feature here, which means the web side of InfoScan is meant to be reached.

## The six flaws, in plain language

All descriptions and scores below come from CISA's official advisory record. The researcher credited is "Cyber-Tim."

### 1. The installer names the customers (CVE-2026-120157, 5.3)

The publicly distributed InfoScan desktop installer contains configuration files with **hostnames tied to customer installations**, plus Dorsett's own internal development, testing and database infrastructure. Anyone who downloads and unpacks the installer can read them. No login required.

For an attacker, that is a target list. It tells you which organizations run the product and what their systems are called, which is exactly the first page of a reconnaissance notebook.

### 2. The login page tells you who to target (CVE-2026-120271, 5.3)

InfoScan's mobile-enumeration and version-reporting endpoints answer unauthenticated requests with system configuration details. Per CISA that includes:

- usernames and display names
- **whether multifactor authentication is configured**
- session settings
- application version and server details
- hardware module firmware versions
- the BACnet/IP port in use

Read that list again. Usernames plus MFA status is a ready-made answer to the question "which account should I try to phish or guess first?" Version and firmware numbers tell an attacker which other bugs might apply.

### 3. The database password key ships in the app (CVE-2026-120255, 4.3)

InfoScan encrypts its MongoDB password before storing it in the Windows registry. Good idea. But the key and initialization vector are **hard-coded into the application**. Everyone who has the software has the key.

So anyone who can read that registry value and has a copy of the app can recover the database password. Encryption with a published key is a lock with the key taped to it.

### 4. The desktop client trusts any certificate (CVE-2026-117659, 8.1)

This is the highest score in the set. The InfoScan desktop client is built on Electron, and according to CISA it **accepts TLS certificates without checking whether they are trustworthy**. It also runs with Electron's main safety rails turned off: `nodeIntegration` enabled, `contextIsolation` disabled, and `webSecurity` disabled.

In plain terms: someone positioned on the network path between an operator's workstation and the server could pose as the server, and the client would not object. With those Electron settings off, content the client loads has far more power on the workstation than it should.

### 5. Stack traces on the login page (CVE-2026-120298, 5.3)

Malformed requests to the login and password-reset endpoints trigger unhandled errors that return full Node.js stack traces: internal file paths, directory names, source file locations and line numbers. It is not a break-in by itself. It is a free map of the code.

### 6. Templates without a session (CVE-2026-120260, 5.5)

A local endpoint that serves sales-automation templates does not check for a valid session. CISA scores this one as needing local access, so it is the least urgent of the six, but it fits the pattern: things that should ask "who are you?" do not.

## How they stack

None of this is a one-click takeover. CISA says it has **no reports of public exploitation** targeting these flaws, and I want to be clear about that.

But walk through it the way an attacker would:

1. Download the installer, pull out the customer hostnames. Now you know who runs InfoScan.
2. Ask each exposed server for its users and MFA status. Now you know which accounts are soft.
3. Read the version and firmware data. Now you know what else is unpatched.
4. If you ever land on a workstation, the hard-coded key turns a registry value into a database password.
5. If you can sit on the network path, the client will take your fake certificate.

Each step is a "medium." The sequence is how small utilities get hurt. And small utilities, the ones running a handful of lift stations with a two-person IT shop or no IT shop at all, are exactly who buys a SCADA product sold on low cost and easy self-maintenance.

Water systems have already been on the receiving end of attacks on internet-facing control interfaces in recent years. Nobody needs a 9.8 to repeat that.

## Who is affected and the fix

- **Affected:** Dorsett Controls InfoScan, all versions **up to and including 1.45.0**
- **Fixed:** **InfoScan 1.46** or later

The update does not install itself. Per Dorsett's guidance in the advisory:

- **Connected systems:** an admin logs in to InfoScan, opens **System Maintenance**, selects **Check for Updates**, then clicks **Install Now** under Ready To Install.
- **Offline systems** (no internet access): download the update from the **Dorsett Controls Customer Portal** using the InfoScan Update tile and follow the instructions there.

If you are an operator, that is the one thing to do this week.

## What else operators should do

Updating fixes the code. It does not undo anything that leaked while the old code was running. A few steps worth taking alongside the update:

- **Change the MongoDB password** after upgrading. The old one was protected by a key that is now public knowledge.
- **Turn on MFA for every InfoScan account.** If the endpoint already told someone which accounts lacked it, close that gap.
- **Check what is reachable from the internet.** CISA's standing advice applies: control systems should not be exposed directly. If remote access is needed, put it behind a VPN that is itself kept up to date.
- **Separate the control network from the business network** with a firewall, so a compromised office PC is not one hop from the SCADA server.
- **Watch workstation connections.** Since the old client trusted any certificate, treat unexpected certificate or proxy activity on operator machines as worth a look.
- **Review logs for unusual requests** to login, password-reset and version endpoints, especially from outside your normal address ranges.
- **Report anything odd** to CISA, or in Canada to the Canadian Centre for Cyber Security.

If you are not an operator but you live in a town that runs its own water system, this is a fair question to ask at a council meeting: what SCADA software do we use, and is it patched?

## The bigger lesson

The industry keeps learning this one the hard way. Severity scores rate bugs one at a time, and attackers do not use them one at a time. An advisory with six "medium" findings in software that runs water infrastructure deserves more attention than it got.

That is why I write these. The loud bugs get covered. The quiet ones get exploited.

## Keep reading

- [Someone in the next lane could touch your trailer brakes](/posts/2026/11/22/elecbrakes-trailer-brake-controller-bluetooth-flaw/)
- [The survey link that ran code: REDCap's quiet two months](/posts/2026/11/21/redcap-survey-link-quiet-exploitation/)
- [Three exploitation stories nobody is talking about](/posts/2026/11/15/three-quiet-exploitation-stories-nobody-is-covering/)

## Sources

- CISA, [ICS Advisory ICSA-26-321-01: Dorsett Controls InfoScan](https://www.cisa.gov/news-events/ics-advisories/icsa-26-321-01) (November 17, 2026)
- CISA, [CSAF record for ICSA-26-321-01](https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-321-01.json)
- Dorsett Controls, [InfoScan SCADA Systems](https://dorsettcontrols.com/infoscan-scada-systems/)
- CISA, [Industrial Control Systems recommended practices](https://www.cisa.gov/ics)
