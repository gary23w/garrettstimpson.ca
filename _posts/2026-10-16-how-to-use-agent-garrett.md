---
layout: post
title: "How to Use Agent Garrett: Your Security Operator in the Cloud"
seo_title: "How to Use Agent Garrett: Security Operator in the Cloud"
date: 2026-10-16 09:00:00 -0400
author: Garrett Stimpson
permalink: /posts/2026/10/16/how-to-use-agent-garrett/
categories: [agent-garrett, guides]
tags: [agent-garrett, getting-started, website-protection, identity-monitoring, tater-tot, cloud-security]
excerpt: "An 11-minute video guide to signing in, deploying your agent, protecting a website, setting up alerts, and following Garrett's persistent work cycle. No terminal required."
description: "Learn to set up Agent Garrett for recurring cloud security checks, verified email alerts, identity monitoring, approved website recovery, and evidence-backed conversations."
image: /assets/img/agent-garrett-how-to-poster.png
video:
  url: /assets/video/agent-garrett-how-to.mp4
  poster: /assets/img/agent-garrett-how-to-poster.png
  duration: PT11M14S
---

You should be able to put a security tool to work without learning a terminal first. This walkthrough starts at the sign-in screen and follows the setup through to an agent watching a website from the cloud.

In **11 minutes**, it covers the interface, website protection, identity monitoring, email alerts, chat, and the persistent **tater-tot** work cycle. You can watch it straight through or jump to the step you need.

{% include agent-garrett-walkthrough.html %}

The recording uses the shipped interface with a demonstration account and simulated incidents, tool results, chat replies, and recovery receipts. Private Cloudflare login, payment entry, and inbox verification are explained and skipped. The incident replay illustrates the workflow; it is not a production incident or a live performance benchmark.

## 1. Sign in and deploy your agent

Open [Agent Garrett](https://agent.garrettstimpson.ca) and choose **Sign in**. New users create a Cloudflare account; returning users use their existing login. Complete verification and review the requested permissions.

In the dashboard, choose **Get started**, then **Protect my website**. The guide takes you through your goal, your plan, your agent, and the website you want to protect.

- **Paid Agent access is CAD $4.99/month.** It includes automatic protection, chat, and service email alerts within the service's allowances.
- The **card-required three-day trial** covers MCP and backend API tools. It automatically renews at CAD $4.99/month unless cancelled before it ends. Automatic protection and alerts require paid access or a valid service grant.

Choose your authorized Cloudflare account, give the connection a recognizable name, and select **Deploy instance**. Garrett hosts the full agent backend. Your Cloudflare account receives a small connection Worker, which can run on Workers Free within its limits. You do not need to transfer your domain or run a computer around the clock. A first deployment can take several minutes; wait for readiness before continuing.

## 2. Choose what Garrett watches

Add the public address of a website you own or manage. Pick the behavior you want:

| Mode | What it does |
| --- | --- |
| **Watch** | Checks availability, expected text, public DNS, security headers, and optional page-text changes. |
| **Investigate** | Adds bounded evidence gathering and a recorded case history when something needs attention. |
| **Handle** | Adds recovery for a supported Cloudflare website Worker: restore a healthy version you explicitly approved after a newer deployment repeatedly returns server errors, then recheck. |

For Handle, load the eligible website Workers, select the correct one, read the approval, and save the healthy version. This approval has a specific scope. It does not authorize arbitrary site edits or establish that an intruder has been removed.

After setup, review **Websites** for the last observation, its timestamp, the next scheduled wake, and recorded activity. A successful check describes what was observed at that time.

## 3. Make sure you can hear from your operator

Open **Email alerts**, enter an address you control, and save your preferences. Follow the confirmation link in your inbox before expecting alerts. Then send a test and check both your inbox and spam folder.

An **accepted** receipt means the sending service accepted the message. It does not confirm delivery to your inbox. The dashboard keeps the full evidence behind your sign-in.

Under **Identity protection**, add an email address or another identity you are authorized to represent. Complete the required ownership or authorization step and review the source coverage. Public leak-post search has a separate opt-in because it sends the target to that provider. A mention is a lead to investigate, not proof of a breach or an attacker's identity.

## 4. See what tater-tot does between visits

Tater-tot is Garrett's persistent work cycle. It recalls relevant context, chooses an allowed tool, records its intent, inspects the result, measures progress, and saves useful observations for the next iteration.

In **Agent tasks**, give it an objective with a clear result. The video uses:

> Review my saved website findings and assets. Explain what needs my attention, cite the evidence, and separate confirmed observations from unanswered questions. Do not change infrastructure.

Open the task context to inspect recorded actions and **Observed tool evidence**. Under **Extended memory**, save priorities that will be useful later. Owner notes guide the work; they do not expand tool permissions or replace evidence.

Automatic tasks normally advance one step per five-minute heartbeat, within their limits. They can pause for review or stop when they reach a limit or repeatedly make no progress. Each website, identity monitor, and task has its own pause control.

## 5. Ask questions in plain English

Open **Chat**, choose the relevant website or task, and ask:

> What did you check, what changed, and what still needs my attention? Include the observation times and any gaps.

Read the answer alongside the evidence. Dashboard chat uses read-only evidence tools; scheduling a task or approving recovery is a deliberate action in its controls.

Once your monitors are enabled, your browser and computer can be off while authorized cloud work follows its schedule and allowances. Garrett watches the websites and digital identities you configure. It does not provide a device-wide firewall or guarantee complete internet coverage.

## Before you leave the dashboard

- Confirm the correct website, protection mode, and any approved healthy Worker version.
- Check the latest observation and next scheduled wake.
- Verify your alert address and confirm test-email delivery.
- Review identity ownership, source coverage, and any open leads.
- Check task status, saved priorities, and anything waiting for owner review.

[Open your workspace](https://agent.garrettstimpson.ca/dashboard) · [Browse Help & FAQ](https://agent.garrettstimpson.ca/help) · [Connect NL-Veil or another MCP client](/mcp/)

## More walkthroughs and practical guides

- [Agent Garrett: Cloud Attack Response](/posts/2026/10/14/agent-garrett-cloud-attack-response/) — a separate recorded synthetic incident in NL-Veil, from investigation through retest.
- [The on-prem directory lab](/directory-lab/) — inspect a modeled assessment path, its evidence, and a hardened rerun.
- [When Is a Vulnerability Actually Fixed?](/posts/2026/10/15/vulnerability-remediation-evidence-checklist/) — a practical checklist for deciding what repair evidence supports.

The dashboard's **Help & FAQ** page collects these guides, connection instructions, and answers to common setup questions in one place.
