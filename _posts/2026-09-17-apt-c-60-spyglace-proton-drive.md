---
layout: post
title: "APT-C-60's 2026 Update: SpyGlace Through Proton Drive, mshta, and a Chain Built on Trusted Services"
date: 2026-09-17
categories: [malware, analysis, windows]
tags: [apt-c-60, spyglace, japan, spear-phishing, proton-drive, lnk, mshta, living-off-the-land, jsdelivr, codeberg, github, gitlab, threat-intel, mitre-attack, defense]
excerpt: "JPCERT's July 2026 update on APT-C-60 shows the espionage group still working Japanese targets, now staging SpyGlace through Proton Drive and hiding its traffic among GitHub, GitLab, jsDelivr, and Codeberg. No CVE, no exploit kit. Just phishing and trust in services everyone already uses."
---

JPCERT/CC published its third write-up on APT-C-60 in July 2026, and the picture is almost boring in the way that matters: no zero-day, no custom exploit framework, just spearphishing, a cloud storage link, and a backdoor that moves through infrastructure nobody wants to block. [JPCERT's post](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html) documents a chain that runs Proton Drive, a RAR archive, an LNK file, mshta.exe, and then GitHub, GitLab, jsDelivr, and Codeberg.

That combination is the story. Every individual technique is old. Put together, they make a campaign that is genuinely hard to detect with the controls most organizations run, and it has been running since at least 2024 with barely a ripple outside the vendor blog ecosystem. This one got trade coverage and almost no mainstream attention, which is exactly why it deserves a closer look here.

## The chain at a glance

[JPCERT describes](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html) two delivery variants:

- A spearphishing email containing a Proton Drive link. The victim downloads a RAR archive from Proton Drive. Extracting it yields, among other files, an LNK shortcut. Opening the LNK starts the infection.
- A variant where the malicious file is attached to the email directly, with no Proton Drive in the middle.

From the LNK onward the chain lives off the land: the LNK copies itself and invokes mshta.exe to run embedded JavaScript. mshta is a signed Microsoft binary that executes script, so the first code execution happens inside a process every Windows box already trusts.

What JPCERT confirmed in this campaign, in their own words: Proton Drive for file distribution, an LNK file contained in a RAR archive, JavaScript execution via mshta.exe, and abuse of legitimate services such as GitHub, GitLab, jsDelivr, and Codeberg. The IoCs, including C2 servers and file hashes, are in the post's appendix.

## Why Proton Drive is a smart staging choice

This part is my analysis, not JPCERT's claim. Proton Drive is end-to-end encrypted cloud storage run by a company whose entire brand is privacy. As malware staging it offers three things at once:

- No reputation problem. The domain is not a known-bad host, and blocking it outright would break legitimate users.
- Encryption in transit and at rest, so network inspection sees a normal TLS session to a file host and nothing more.
- Link-based delivery that looks like any other file share a colleague might send.

The only thing JPCERT's text confirms is that the group used Proton Drive for distribution. The operational advantages above are inference. Treat them as such.

## The developer-platform camouflage

The abuse of developer platforms is not new for this group. The 2024 campaign [used StatCounter and Bitbucket](https://thehackernews.com/2024/11/apt-c-60-exploits-wps-office.html) as part of its delivery chain, back when the group's headline was the WPS Office zero-day (CVE-2024-7262). The 2026 refresh swaps in GitHub, GitLab, jsDelivr, and Codeberg.

The reason this works has not changed: these domains sit on every corporate allowlist, jsDelivr is a CDN that fronts open source package content so its traffic looks like ordinary page assets, and blocking any of them breaks builds, updates, and half the modern web. An attacker who routes staging or C2 through them inherits that blanket of legitimacy.

One precision note: JPCERT's text confirms abuse of these services but does not spell out, in the portion I worked from, exactly which stage each service serves. The full post and its appendix carry that detail. I am not going to guess the topology.

## What SpyGlace is, and what I am not claiming

JPCERT tracks the backdoor as SpyGlace. Here is what I verified against the primary source for this post: the name, the delivery chain, the mshta execution, the service abuse, and the existence of an appendix with C2 servers and file hashes.

Here is what I deliberately did not do: reproduce hashes or C2 indicators secondhand. Aggregator posts and OTX pulses are already circulating, and loading unverified IOC lists into detection is how teams end up blocking a CDN on a Friday. Pull the appendix from JPCERT's post directly. Likewise, deep capability detail (persistence mechanics, command set, exfiltration behavior) lives in JPCERT's full write-up, and I am not going to summarize it secondhand when the primary is one click away.

## Mapping to MITRE ATT&CK

Only the techniques JPCERT's text actually supports:

- T1566.002 Spearphishing Link: the Proton Drive link in the email
- T1566.001 Spearphishing Attachment: the direct-attachment variant
- T1204.002 User Execution: Malicious File: the victim opens the LNK
- T1218.005 Mshta: JavaScript execution via mshta.exe
- T1102 Web Service: abuse of GitHub, GitLab, jsDelivr, and Codeberg

## Detection worth doing anyway

mshta spawning from explorer after an LNK open is not, by itself, an alarm. mshta running a script scheme is. A sketch, illustrative and untested, tune before you ship:

```yaml
# Illustrative only. Untested. Tune before deploying.
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains|any:
            - 'javascript:'
            - 'vbscript:'
    condition: selection
```

Two more signals that survive the trust problem:

- Network egress from mshta.exe to codeberg, jsdelivr, github, or gitlab endpoints. Legitimate mshta traffic is rare enough that this is worth a look, not a block.
- Any archive attachment containing an LNK file, flagged at the mail gateway. The LNK-in-RAR pattern is the constant across all three years of this campaign.

## What to do Monday

JPCERT's own guidance is the right baseline: avoid opening cloud storage links in suspicious emails, and do not open LNK files contained in archives such as RAR files. On top of that:

- Block or sandbox LNK files arriving inside archives at the mail gateway.
- Alert on mshta executing script schemes, and on mshta making outbound TLS to developer platforms.
- Pull the C2 servers and file hashes from [JPCERT's appendix](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html) yourself, from the primary source.

## What I could not verify

In the spirit of the honesty this blog tries to keep:

- I did not independently confirm attribution beyond JPCERT's tracking name APT-C-60. Attribution chatter exists elsewhere; none of it is load-bearing for this post.
- I did not confirm when the SpyGlace name first appeared. It is confirmed in the July 2026 post; whether the November 2025 update already used it, I did not check.
- JPCERT's text describes "the case we observed" and one similar case. I found no victim count or scope figure, so I am not asserting one.
- The exact role each abused service plays (staging versus C2) is not spelled out in the portion of the post I worked from.

## Sources

- [JPCERT/CC Eyes: Update on Attacks by Threat Group APT-C-60 in 2026](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html) - the primary source for every factual claim above
- [JPCERT/CC Eyes: APT-C-60, December 2024](https://blogs.jpcert.or.jp/en/2024/12/APT-C-60.html) - the first write-up in the series
- [JPCERT/CC Eyes: APT-C-60 update, November 2025](https://blogs.jpcert.or.jp/en/2025/11/APT-C-60_update.html) - the second write-up
- [Cyble: APT-C-60 deploys updated SpyGlace malware in Japan](https://cyble.com/blog/apt-c-60-deploys-updated-spyglace-malware-in-japan/) - independent analysis, September 7, 2026
- [Cyber Press: APT-C-60 hackers abuse Proton Drive and developer platforms](https://cyberpress.org/apt-c-60-deploys-spyglace-malware/) - trade coverage, July 13, 2026
- [Positive Technologies PT ESC: APT-C-60 / SpyGlace profile](https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/apt-c-60-spyglace/)
- [The Hacker News: APT-C-60 StatCounter and Bitbucket campaign, November 2024](https://thehackernews.com/2024/11/apt-c-60-exploits-wps-office.html) - for the 2024 precedent only

No CVE. No patch coming. The fix is deciding, in advance, how much you trust the services your whole network already trusts.
