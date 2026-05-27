---
layout: post
title: "DarkTortilla Wraps DarkCloud: How a .NET Crypter Hides a Credential Stealer in a Fake Quotation Email"
date: 2026-05-27
categories: [malware, analysis]
tags: [darktortilla, darkcloud, dotnet, infostealer, reflective-loading, mitre-attack]
excerpt: "A DarkTortilla-packed .NET executable dropped on MalwareBazaar today carries a DarkCloud stealer payload that weaponizes reflective Assembly.Load() to run entirely in memory, bypassing AV and dumping browser credentials before you notice it launched."
---

A new sample hit MalwareBazaar this morning and it is a clean example of a two-layer attack that defenders routinely underestimate. The file, `Quotation No 550.exe`, arrived at 12:13 UTC on May 27, 2026, submitted by James_inthe_box. The outer layer is a DarkTortilla crypter, a .NET-based packer that has been quietly active since at least 2015. The inner payload, flagged by CAPE Sandbox, Intezer, and several others, is DarkCloud stealer.

SHA256: `82f667e77a036edce6b6bef25fbc989fbf1f27e1bdc3ddb99b821ca9f60dd10b`

Full MalwareBazaar entry: `https://bazaar.abuse.ch/sample/82f667e77a036edce6b6bef25fbc989fbf1f27e1bdc3ddb99b821ca9f60dd10b/`

One thing that stands out immediately is the imphash: `f34d5f2d4577ed6d9ceec516c1f5a744`. MalwareBazaar shows that same imphash across nearly 49,000 AgentTesla samples and almost 20,000 Formbook samples. That is not a coincidence. DarkTortilla is a malware-as-a-service crypter, and operators reuse the same .NET loader skeleton to wrap whatever payload they are distributing this week.

---

## What Makes It Work

The attack chain begins the way most credential theft operations do: a business-themed email. "Quotation No 550.exe" is designed to look like a legitimate procurement document, the kind of thing a purchasing manager opens without a second thought. The filename is the social engineering. Everything else is technical.

DarkTortilla is a two-stage .NET assembly. The initial loader, a standalone PE, does not execute the real payload directly. Instead, it reads an encrypted blob, usually embedded in a .NET resource or appended to the file, decrypts it with AES or a similar symmetric cipher, and then calls `Assembly.Load()` on the raw bytes. That single call is the trick. The .NET runtime loads the decrypted DLL into memory directly, no file is written to disk, no path shows up in Prefetch, no artifact lands in `%TEMP%`. The loaded DLL is the DarkTortilla "core processor," a second .NET assembly that handles everything else.

The core processor parses a configuration blob embedded within itself, which controls the behavior of the full infection chain. Before doing anything meaningful, it runs environment checks. DarkTortilla looks for common VM artifacts: MAC address prefixes associated with VirtualBox (`08:00:27`) and VMware (`00:0C:29`), registry keys under `HKLM\SOFTWARE\VMware, Inc.`, processor names containing "VBOX" or "VIRTUAL", and the presence of known analysis processes. If any check trips, the loader simply exits. This is T1497.001 (Virtualization/Sandbox Evasion: System Checks) and it works often enough that DarkTortilla has operated for over a decade without being widely burned.

Once the environment passes, the core processor injects the DarkCloud payload. The injection method commonly observed in DarkCloud campaigns uses `VirtualProtect()` to mark a memory region as executable and then calls `CallWindowProc()` to redirect execution into it. This sidesteps the classic `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` pattern that most behavior engines watch for. It is not novel but it is effective. The payload runs in memory under the original process. From the OS perspective, it is still just `Quotation No 550.exe`.

DarkCloud is an information stealer written in Visual Basic 6 at its core, though modern variants ship wrapped in .NET. Once active, it targets browser credential stores directly. For Chrome and Chromium-based browsers, it reads `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`, an SQLite database that stores saved passwords encrypted with DPAPI. The Windows Data Protection API ties encryption to the logged-in user account and machine, which means DarkCloud calls `CryptUnprotectData()` directly in the context of the victim process to decrypt those passwords with no external key required. For Firefox, it queries the NSS database via `SELECT a11,length(a11) FROM nssPrivate` and recovers master password-protected entries where the user has not set a strong master password. It also pulls from Gecko-based browsers, email clients (Thunderbird, Outlook profile files), FTP clients, and any crypto wallet data it can locate.

Persistence is straightforward. DarkCloud writes itself to `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` with a path pointing to a copy of the loader it drops, usually in `%APPDATA%` or `%USERPROFILE%`. RunOnce executes once on next login and removes itself afterward, so the registry entry is only visible between infection and first reboot.

Before exfiltration, DarkCloud checks for analysis tools. It looks for process names including `wireshark.exe`, `fiddler.exe`, `processhacker.exe`, `tcpview.exe`, `windbg.exe`, and `processhacker.exe` in the running process list. If it finds any, it sleeps or exits. The malware also fetches the victim's public IP from a site like `showip.net` to include in the exfil package, which is useful for the operator to geolocate victims and prioritize high-value targets.

The full MITRE ATT&CK coverage here: T1027 (Obfuscated Files), T1620 (Reflective Code Loading), T1497.001 (Sandbox Evasion: System Checks), T1055 (Process Injection), T1547.001 (Registry Run Keys), T1555.003 (Credentials from Web Browsers), T1056.001 (Keylogging), T1082 (System Information Discovery), T1113 (Screen Capture), T1071.001 (Web Protocols for C2 exfil).

---

## Educational Sample: Reflective .NET Loading Skeleton

The following demonstrates the core DarkTortilla technique, `Assembly.Load()` reflective loading, without any payload. This is what the two-stage loader looks like structurally.

```csharp
// EDUCATIONAL SAMPLE — demonstrates .NET Reflective Assembly Loading
// This is the structural pattern DarkTortilla uses to load its core processor
// This does NOT contain any malicious payload
// For research and defensive awareness only

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

class ReflectiveLoaderDemo
{
    // Anti-VM check: DarkTortilla looks for known VM MAC prefixes and registry keys
    static bool IsVirtualEnvironment()
    {
        try
        {
            object cpuReg = Microsoft.Win32.Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "ProcessorNameString", "");
            
            string cpu = cpuReg?.ToString().ToUpperInvariant() ?? "";
            string[] vmMarkers = { "VBOX", "VMWARE", "QEMU", "HYPERV" };
            
            foreach (string marker in vmMarkers)
                if (cpu.Contains(marker)) return true;
        }
        catch { /* silently pass on access errors */ }
        
        return false;
    }

    // Stage 1: Decrypt the core processor bytes from an embedded resource
    // In the real loader, encryptedBlob comes from a .NET resource or appended data
    static byte[] DecryptPayload(byte[] encryptedBlob, byte[] aesKey, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = aesKey;    // 32-byte key derived from hardcoded config value
        aes.IV  = iv;        // 16-byte IV stored adjacent to encrypted blob
        using var ms = new MemoryStream(encryptedBlob);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var result = new MemoryStream();
        cs.CopyTo(result);
        return result.ToArray();
    }

    // Stage 2: Reflective load — the key technique.
    // Assembly.Load() takes raw bytes, no file touches disk.
    // The loaded assembly's entry point is invoked directly in memory.
    static void ReflectiveLoad(byte[] assemblyBytes)
    {
        Assembly loaded = Assembly.Load(assemblyBytes);
        MethodInfo entry = loaded.EntryPoint;

        // Invoke with empty args — real DarkTortilla passes a config struct here
        entry?.Invoke(null, new object[] { new string[0] });
    }

    // Stage 3: RunOnce persistence — DarkCloud adds itself here post-injection
    static void SetRunOncePersistence(string keyName, string executablePath)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", writable: true);
        key?.SetValue(keyName, $"\"{executablePath}\"");
        // Registry entry auto-deletes after next login execution
    }

    static void Main()
    {
        if (IsVirtualEnvironment()) { Environment.Exit(0); return; }

        // Placeholder bytes — a real loader would decrypt these from a resource
        byte[] fakePayload   = new byte[256];  // zeroed, no real assembly
        byte[] fakeAesKey    = new byte[32];   // zeroed key
        byte[] fakeIv        = new byte[16];   // zeroed IV

        Console.WriteLine("[demo] Reflective loading pattern shown above.");
        Console.WriteLine("[demo] Assembly.Load() never writes a file to disk.");
        Console.WriteLine("[demo] RunOnce key: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

        // ReflectiveLoad(DecryptPayload(fakePayload, fakeAesKey, fakeIv));
        // SetRunOncePersistence("SystemUpdateHelper", @"C:\Users\victim\AppData\Roaming\svchst.exe");
    }
}
```

The comment on the last two lines is the point. In the real chain, those two calls are exactly what runs. The AV-bypassing part is entirely in `Assembly.Load()`: the runtime never sees a suspicious file path, no scan hook fires on a file write, and the loaded assembly inherits the parent process's trust level. It is a primitive that .NET exposes for legitimate plugin architectures, and DarkTortilla has been abusing it for years.

---

## Detection and Defense

The Stairwell team published a solid YARA hunting rule for DarkCloud variants in August 2025. Key strings to match include `SELECT a11,length(a11) FROM nssPrivate` (Firefox NSS query), `DarkCloud Credentials` and `DarkCloud Keylogger` (internal module names present in unobfuscated builds), and `C:\Users\Public\Libraries\vbsqlite3.dll` (a path the stealer drops its SQLite helper to). Three or more matches on the `$s*` strings or four matches on the `$c*` code-specific strings indicate a high-confidence hit.

For Sysmon-based detection, the events that matter most here are Event ID 13 (Registry value set) watching for writes to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` by unexpected processes, Event ID 10 (Process access) for `Quotation*.exe` or similarly named business-lure processes opening `lsass.exe` or accessing Chrome's `Login Data` file, and Event ID 7 (Image loaded) watching for `clrjit.dll` and `mscorlib.dll` being loaded inside uncommon processes, which signals .NET runtime activation in something that should not be running managed code.

On the network side, watch for outbound HTTP GET requests to `showip.net`, `checkip.amazonaws.com`, or similar IP-discovery services from user processes. That pattern is nearly always malware performing victim geolocation before exfil.

Mitigations: restrict execution of unsigned .NET assemblies via AppLocker or WDAC policies, enable Credential Guard to protect LSASS-based secrets, and consider pushing Chrome's App-Bound Encryption (introduced in Chrome 127) which stores encryption keys in a way that blocks cross-process DPAPI abuse at the browser credential level. That last control specifically targets the `CryptUnprotectData()` bypass DarkCloud relies on.

Practically speaking, this family is not going anywhere. DarkTortilla has been distributing payloads for over a decade because the combination of .NET reflective loading and layered encryption works. DarkCloud has been under active development since 2022 and is sold as a builder with configurable modules. When two mature, maintained tools combine in a single delivery, you get exactly what landed on Bazaar this morning: a 1.3MB `.exe` masquerading as a business document that empties a victim's credential store before their endpoint protection notices the loader ever ran.
