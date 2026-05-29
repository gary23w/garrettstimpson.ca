---
layout: post
title: "Lumma Stealer Is Back, and Now It's Using Windows Terminal Against You"
date: 2026-05-29
categories: [malware, analysis]
tags: [lumma-stealer, clickfix, infostealer, windows-terminal, mitre-attack, castleloader]
excerpt: "Twelve months after a global law enforcement operation seized 2,300 of its C2 domains, Lumma Stealer is back at scale, now weaponizing Windows Terminal and ClickFix social engineering to bypass the exact defenses that caught it last time."
---

A year ago, the DOJ, FBI, and Microsoft jointly dismantled the LummaC2 infrastructure. They seized 2,300 command-and-control domains, filed civil actions, and called it a significant blow to the infostealer-as-a-service ecosystem. It was impressive work. And yet, here we are.

Lumma Stealer is back. Not quietly either. CastleLoader campaigns are pushing it at scale, and the February 2026 variant spotted by Microsoft Defender Experts introduced something worth paying attention to: the delivery chain now instructs victims to open Windows Terminal rather than the classic Run dialog, using it as a gateway into a multi-stage, in-memory attack that ends with your Chrome passwords on an attacker's server.

---

## What Showed Up

This post draws on Microsoft Defender Experts' published analysis from early 2026, Trend Micro's threat intelligence on the post-takedown resurgence, and Bitdefender's CastleLoader research. A reference PowerShell dropper from one documented campaign carries SHA256 `909ed8a1351f9a21ebdd5d8efb4147145f12d5d24225dbd44cd2800a1f94a596`. Active Lumma samples are tracked on MalwareBazaar at [https://bazaar.abuse.ch/browse/yara/Lumma_Stealer_Detection/](https://bazaar.abuse.ch/browse/yara/Lumma_Stealer_Detection/).

The family: Lumma Stealer (LummaC2), a malware-as-a-service infostealer platform with origins around 2022, classified under MITRE ATT&CK as software S1213. File type in current campaigns: dynamically assembled MSI files with ZIP and 7-Zip intermediate stages. The specific ClickFix-plus-Terminal variant was first observed in February 2026. The takedown happened in May 2025. That's nine months of recovery time, and the rebuilt infrastructure is already more resilient than what was seized.

---

## What Makes It Work

The cleverness of the new delivery chain is that it abuses trust in a specific, targeted way. Older ClickFix attacks told users to press Win+R and paste a command into the Run dialog. Security tools caught up. EDRs started flagging PowerShell processes spawned from explorer.exe's Run child processes. SOCs wrote detections. The run-dialog vector got noisy.

The 2026 variant changed the execution context entirely. The fake CAPTCHA page now instructs the user to press **Win+X, then I** to open Windows Terminal (wt.exe) directly. That's a legitimate administrative shortcut every Windows 11 user has. The page then presents text telling the user to paste "the verification command" into the terminal to prove they're human. The user pastes a hex-encoded, XOR-compressed command that someone already placed in their clipboard. From a process tree perspective, this looks like a human opening a terminal and running a command. No suspicious Run dialog. No wscript.exe intermediate. Nothing obviously wrong.

PowerShell spawned from Windows Terminal decodes the XOR layer in memory, decompresses the payload, and begins the download stage. It fetches a renamed 7-Zip binary and a ZIP archive. The ZIP contents are extracted, combined, and written to disk as a single MSI file with a timestamp-based name following the scheme `HHmmss_yyyyMMdd.msi`. That file is then executed silently:

```
msiexec.exe /i 143022_20260213.msi /qn ALLUSERS=2 MSIINSTALLPERUSER=1
```

The `/qn` flag suppresses all UI. `MSIINSTALLPERUSER=1` keeps installation in the current user context, so no UAC prompt fires. To anyone watching the screen, nothing is happening.

Inside the MSI is CastleLoader. This is where the real engineering lives. CastleLoader does not write a traditional DLL or executable to disk at this stage. It resolves Windows APIs at runtime using function hash lookups rather than an import address table, which means static analysis tools that scan IAT entries for suspicious capabilities find almost nothing. It then performs sandbox evasion checks consistent with MITRE T1497.002: it looks for recent mouse movement, process counts typical of a live user session, and timing signatures that suggest a real machine rather than an analysis sandbox. If those checks fail, CastleLoader exits cleanly. No crash, no error, no artifact.

Assuming it decides the environment is real, CastleLoader decrypts the Lumma payload in memory and injects it using QueueUserAPC injection (T1055.004) into a running `chrome.exe` or `msedge.exe` process. QueueUserAPC works by queuing an asynchronous procedure call onto a thread in the target process. When that thread enters an alertable wait state, the queued function executes inside the browser's address space. The payload never touches disk as a separate executable. The payload is a region of memory inside a browser you already trust.

Once resident inside the browser process, Lumma goes to work. It reads Chrome's `Local State` file from `%LOCALAPPDATA%\Google\Chrome\User Data\Local State`. This JSON file contains an AES-256 key that Chrome uses to encrypt credentials at rest, but the key itself is protected with Windows DPAPI. Lumma calls `CryptUnprotectData` from `crypt32.dll` to unwrap it. Because the call originates from a process running as the logged-in user, Windows decrypts it automatically. No elevated privileges required. No credential prompts. That is how DPAPI works: it ties encryption to the user context, and any code running as that user can call it.

With the master key, Lumma opens `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`, `Cookies`, and `Web Data`. It decrypts stored passwords, session cookies, autofill data, and payment card details, then exfiltrates them over HTTPS to attacker-controlled infrastructure. The same logic hits Edge (identical Chromium architecture) and Firefox (using NSS3 instead of DPAPI). Persistence arrives via a scheduled task written at restart, pointing to the staging component dropped under `C:\ProgramData\app_config\ctjb`.

---

## Educational Sample: DPAPI Chrome Key Decryption

The code below demonstrates the DPAPI technique without any payload, C2 communication, or credential exfiltration. It is stripped to show the API calls and file paths involved.

```python
# EDUCATIONAL SAMPLE -- demonstrates DPAPI browser master key decryption
# This does NOT contain any malicious payload
# For research and defensive awareness only

import json, os, ctypes, sqlite3, base64

LOCAL_STATE = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "Google", "Chrome", "User Data", "Local State"
)
LOGIN_DATA = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "Google", "Chrome", "User Data", "Default", "Login Data"
)

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]

def get_master_key(local_state_path: str) -> bytes | None:
    """
    Reads Chrome's encrypted AES master key and unwraps it with DPAPI.
    Requires no elevated privileges -- any user-context process can do this.
    """
    with open(local_state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    encrypted_key = base64.b64decode(
        state["os_crypt"]["encrypted_key"]
    )[5:]  # strip the 5-byte "DPAPI" literal prefix

    buf = ctypes.create_string_buffer(encrypted_key, len(encrypted_key))
    blob_in = DATA_BLOB(ctypes.sizeof(buf), buf)
    blob_out = DATA_BLOB()

    # CryptUnprotectData -- Windows decrypts automatically if called as the user
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        return None

    key = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    print(f"[demo] master key length: {len(key)} bytes")
    return key

def list_origins(login_data_path: str):
    """Lists stored credential origins -- no password decryption performed."""
    conn = sqlite3.connect(login_data_path)
    for origin, user in conn.execute(
        "SELECT origin_url, username_value FROM logins"
    ):
        print(f"  {origin}  =>  {user}")
    conn.close()

if __name__ == "__main__":
    key = get_master_key(LOCAL_STATE)
    list_origins(LOGIN_DATA)
```

The critical detail: `CryptUnprotectData` requires no admin rights. Any user-level process can call it. Chrome's App-Bound Encryption (Chrome 127+) adds a layer for out-of-process attackers, which is exactly why Lumma pivoted to QueueUserAPC injection. Once inside `chrome.exe`, the stealer inherits Chrome's own decryption context and App-Bound Encryption provides no protection.

---

## Detection and Defense

**YARA (adapted from bgd-cirt LummaStealer ruleset):**

```yara
rule LummaStealer_2026_CastleLoader_Chain {
    meta:
        description = "Detects Lumma Stealer or CastleLoader delivery artifacts"
        reference   = "https://github.com/bgd-cirt/LummaStealer-YARA-Rules"
    strings:
        $path1 = "app_config" ascii wide
        $path2 = "ctjb"       ascii wide
        $api1  = "CryptUnprotectData" ascii wide
        $api2  = "QueueUserAPC"       ascii wide
        $dpapi = { 44 50 41 50 49 }   // "DPAPI" literal prefix in Local State key
        $msi   = "msiexec"   ascii wide nocase
    condition:
        3 of them
}
```

**Sysmon events that catch this chain:**

Event ID 1 (Process Create): `WindowsTerminal.exe` spawning `powershell.exe` with `-e` or `-EncodedCommand` in the command line is the first chokepoint. Legitimate terminal sessions rarely kick off encoded PowerShell immediately at launch.

Event ID 1: `msiexec.exe /i *.msi /qn` where the MSI filename matches a timestamp pattern like `\d{6}_\d{8}\.msi`. Legitimate enterprise MSI deployments use descriptive names, not epoch timestamps.

Event ID 10 (Process Access): Any non-browser process requesting `PROCESS_VM_WRITE` on `chrome.exe` or `msedge.exe` is worth alerting on. The QueueUserAPC injection path requires these access rights and shows up in Sysmon's `GrantedAccess` field as `0x001FFFFF` or similar full-access handles.

Event ID 11 (File Create): Directory creation under `C:\ProgramData\app_config\` is a documented Lumma staging indicator across multiple 2025-2026 campaigns.

Event ID 7 (Image Load): Flag any DLL loaded into a browser process from `%TEMP%` or `%ProgramData%` paths. Browsers do not normally load modules from those locations.

**Sigma references:** `proc_creation_win_wt_susp_child_process` and `proc_creation_win_msiexec_install_quiet` in the SigmaHQ community ruleset cover the major chokepoints.

**Mitigations worth actually deploying:** A Windows Defender Application Control (WDAC) policy restricting MSI execution to signed, trusted publishers blocks the msiexec stage cold. For credential theft, the practical answer is deploying Chrome's App-Bound Encryption organization-wide and monitoring for processes touching `Login Data` outside the browser itself. The clipboard pre-staging for ClickFix is harder to block at the OS level, but browser extension policies can restrict JavaScript clipboard write access on non-allowlisted origins.

The bigger picture: according to Microsoft's 2025 Digital Defense Report, ClickFix now accounts for 47% of initial access events tracked by Microsoft Defender Experts. It beat out traditional phishing at 35%. The lure text will keep changing. The execution vehicle will keep rotating. The behavioral indicators on the process creation and injection side are more durable than any signature against the social engineering layer, so that is where detection engineering effort is best spent right now.
