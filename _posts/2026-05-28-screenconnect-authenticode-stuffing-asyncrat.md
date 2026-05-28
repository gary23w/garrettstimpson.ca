---
layout: post
title: "Signed and Delivered: How Threat Actors Weaponize Legitimate ScreenConnect Installers"
date: 2026-05-28
categories: [malware, analysis]
tags: [connectwise, screenconnect, asyncrat, authenticode, lolbas, rmm-abuse, mitre-attack]
excerpt: "Attackers are shipping validly signed ConnectWise installers modified to phone home to attacker infrastructure, then using ScreenConnect's own automation features to drop AsyncRAT in memory."
---

Two fresh ConnectWise samples landed on MalwareBazaar this morning. File names: `ScreenConnect.ClientSetup.exe` (SHA256: `aa116a6279aebc383ed7a9321d580f998436e34f06d07f2cb8ac2d7fd876ba60`) and `support.client.exe` (SHA256: `007872e9454fa9ea6c3ea27ed2fd345428297c02e64e9e516145ccc12d66af5e`). Both PE executables, both tagged ConnectWise family, both submitted by reporter BlinkzSec within seconds of each other at 15:09 UTC. Not a coincidence.

This isn't a vulnerability exploit. No CVE required. The attack works because of a quirk in how Windows validates Authenticode signatures, combined with a feature ConnectWise built into ScreenConnect that lets anyone configure where the client connects. The result is a legitimately signed, vendor-issued executable that quietly installs a remote access channel straight to the attacker.

MalwareBazaar sample page: [https://bazaar.abuse.ch/sample/aa116a6279aebc383ed7a9321d580f998436e34f06d07f2cb8ac2d7fd876ba60/](https://bazaar.abuse.ch/sample/aa116a6279aebc383ed7a9321d580f998436e34f06d07f2cb8ac2d7fd876ba60/)

## What Makes It Work

ScreenConnect's installer is built to be customizable. MSPs and IT teams can specify what server the client connects to, what text appears in dialogs, and what logo displays during installation. All of that configuration data gets stored inside the PE file's `WIN_CERTIFICATE` structure, which is the same block that holds the Authenticode signature.

Here is the trick: when Windows runs `WinVerifyTrust` to check whether a file is signed, it does not hash the contents of the certificate table. The Authenticode hash covers most of the PE file, but the certificate table entry is explicitly excluded from the calculation. This is by design in the Authenticode spec. Microsoft has known about it since at least 2013 (CVE-2013-3900), published a fix, and then backtracked on enforcing it because too many legitimate vendors were embedding metadata the same way.

So an attacker takes a genuine, ConnectWise-signed installer, modifies the embedded configuration to point at their own server, and the resulting binary still passes signature validation. Windows reports it as signed by ConnectWise. VirusTotal shows a valid signature. A help desk analyst sees a green checkmark and installs it.

Researchers at G DATA documented this campaign beginning in March 2025. The payloads are increasingly brazen. Some samples replace the installer dialog title with "Windows Update" and swap the background graphic for a fake Windows update screen. The victim thinks they are applying a system patch. They are actually installing a full remote access client connected to attacker infrastructure.

Once the installer runs, the attacker has a persistent ScreenConnect session. That is already bad enough. But that is not where the campaign stops.

## The Full Attack Chain

The phishing chain usually starts with a malicious PDF. The PDF links to a Canva page or a Cloudflare R2 bucket hosting the trojanized installer. The file arrives signed, and security tooling frequently lets it through because the signer is a known vendor.

After ScreenConnect establishes its session, the attacker uses ScreenConnect's built-in automation features to push a second-stage dropper. This is typically a VBScript or JavaScript file that launches a shortcut, which then runs a PowerShell loader Acronis researchers named `Skype.ps1`. That name is intentional. The loader is designed to look like a Skype component sitting in `%APPDATA%\Skype\`.

`Skype.ps1` does two things based on what AV it detects. If it finds TotalAV or Avast running, it calls `System.Reflection.Assembly.Load` to reconstruct the next payload entirely in memory, never touching disk. If no recognized AV is present, it loads `libPK.dll` via `Add-Type` and calls `Execute` to inject payloads into a legitimate host process. Either way, the goal is reflective code loading: get bytes into a .NET context in memory without writing a second executable.

The final payloads are two RATs deployed simultaneously: AsyncRAT, the open-source .NET remote access tool, and a custom PowerShell-based RAT that handles credential and crypto wallet theft. Both connect back to attacker-controlled C2.

Persistence comes via scheduled task. The task is named either `SystemInstallTask` or `3losh` and is configured to execute every two minutes. That frequency is aggressive. It ensures that even if the session drops or a component gets killed, it comes back fast.

The full MITRE ATT&CK coverage runs: T1566.001 (Spearphishing Attachment), T1553.002 (Subvert Trust Controls: Code Signing), T1219 (Remote Access Software), T1059.001 (PowerShell), T1059.005 (Visual Basic), T1620 (Reflective Code Loading), T1055 (Process Injection), T1053.005 (Scheduled Task persistence).

## Educational Sample: Reflective Assembly Load Skeleton

This is the PowerShell pattern `Skype.ps1` uses to load a .NET assembly into memory without writing it to disk. The payload bytes below are zeroed. The structure is what matters.

```powershell
# EDUCATIONAL SAMPLE - demonstrates System.Reflection.Assembly.Load (T1620)
# This does NOT contain any malicious payload
# For research and defensive awareness only

# In the real loader, these bytes come from a base64-encoded string
# embedded in the script or fetched from a remote URL
$payloadBytes = [byte[]]@(0x00) * 1024  # zeroed placeholder

# Load the assembly into the current process memory - no disk write
$assembly = [System.Reflection.Assembly]::Load($payloadBytes)

# Locate the entry point and invoke it
# In the actual campaign this calls a type named after a legitimate-looking library
$entryType   = $assembly.GetType("Payload.Runner")
$entryMethod = $entryType.GetMethod("Execute")
$entryMethod.Invoke($null, @("arg1", "arg2"))
```

The key call is `[System.Reflection.Assembly]::Load($bytes)`. From an AV perspective, no second PE lands on disk. From a Sysmon perspective, you will see Event ID 7 (image loaded) for the CLR, but no corresponding Event ID 11 (file create) for a second executable. That asymmetry is what defenders need to watch for.

The scheduled task creation looks like this:

```powershell
# EDUCATIONAL SAMPLE - demonstrates T1053.005 scheduled task persistence
# This does NOT contain any malicious payload
# For research and defensive awareness only

schtasks /create /tn "SystemInstallTask" `
         /tr "powershell.exe -WindowStyle Hidden -File C:\Users\Public\Skype.ps1" `
         /sc MINUTE /mo 2 `
         /ru SYSTEM `
         /f
```

The `/mo 2` is two minutes. The `/ru SYSTEM` requests elevated privileges. The `/f` flag forces creation without prompting. This exact command pattern has appeared in multiple samples in this campaign family.

## Detection and Defense

The highest-value mitigation you can apply today is enabling strict Authenticode validation via the registry fix for CVE-2013-3900. Microsoft published it and then left it opt-in:

```
reg add "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
```

With that key set, `WinVerifyTrust` will reject PE files that have been modified after signing. The vast majority of production environments do not have this set. Check yours.

For Sysmon, start with Event ID 1 watching for ScreenConnect spawning `wscript.exe`, `cscript.exe`, or `powershell.exe`. A legitimate RMM tool has no business doing that outside of an explicitly authorized automation workflow. Pair that with Event ID 11 watching for `Skype.ps1` or any `.ps1` file appearing under `%APPDATA%\Skype\`, `%APPDATA%\Roaming\`, or `C:\Users\Public\`. Then watch Event ID 1 again for `schtasks.exe` with arguments containing `SystemInstallTask`, `3losh`, `/mo 2`, or `/ru SYSTEM` run from a user context. Finally, Event ID 7 catching CLR assemblies loading (`clr.dll`, `mscorjit.dll`) inside a PowerShell process with no corresponding child PE on disk is the dead giveaway for reflective loading.

A Sigma rule targeting the scheduled task creation:

```yaml
title: Suspicious Scheduled Task Created by ScreenConnect
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\ScreenConnect.ClientService.exe'
    Image|endswith: '\schtasks.exe'
    CommandLine|contains:
      - 'SystemInstallTask'
      - '3losh'
      - '/mo 2'
  condition: selection
falsepositives:
  - Legitimate ConnectWise automation workflows (verify with IT team)
level: high
```

Beyond detection, restrict which RMM tools are allowed in your environment with an allowlist. Validate that any ScreenConnect installer your help desk distributes connects only to your organization's ScreenConnect instance by checking the embedded server URL before installation. ConnectWise revoked the specific certificate used in documented samples, but new campaigns simply build fresh installers with different server configurations.

Two samples this morning. Same reporter. Same technique. This campaign is not slowing down.
