---
layout: post
title: "Prometei Is Back on Linux and Its UPX Trick Is Clever"
date: 2026-05-28
categories: [malware, analysis]
tags: [prometei, botnet, linux, cryptomining, upx, elf, persistence, lateral-movement, mitre-attack]
author: Garrett Stimpson
excerpt: "A fresh Prometei ELF hit MalwareBazaar this morning with the same UPX-plus-JSON-trailer trick that's been breaking analyst tooling since March 2025, and the campaign is still very much alive."
---

**SHA256:** `4d039c8a8570724cee76221274efc873d8a5f552dc4336160e08bd47db2651aa`  
**File type:** ELF 64-bit x86-64  
**Family:** Prometei  
**First seen:** 2026-05-28 08:21 UTC  
**Reporter:** c2hunter  
**MalwareBazaar:** https://bazaar.abuse.ch/sample/4d039c8a8570724cee76221274efc873d8a5f552dc4336160e08bd47db2651aa/

---

## What Showed Up

This morning a fresh Prometei ELF landed on MalwareBazaar alongside two companion shell script droppers, both named `k.php`. The dropper hashes are `ee03bd0f...` and `935e3d35...`, also submitted today, both classified as `text/x-shellscript` despite carrying a `.php` extension. The naming is intentional misdirection. Nothing in either file is PHP.

Prometei is a cross-platform botnet that first surfaced in July 2020 and has been under active development since at least 2016. It targets both Linux and Windows, mines Monero using XMRig, steals credentials, and maintains long-term persistence through a modular architecture. Unit 42 documented a significant resurgence starting in March 2025, and based on what's still flowing into threat feeds six months later, the operators are not slowing down. This latest ELF is version three or four of the Linux variant, packed with a technique that has been tripping up analysts repeatedly.

---

## What Makes It Work

**The delivery chain**

The initial access path for the Linux variant is SSH brute-force against exposed servers. The Windows variant goes further and uses EternalBlue (MS17-010, T1210) to hop laterally across subnets once it has a foothold. On Linux the approach is simpler and, honestly, effective enough that complexity is not needed. A lot of servers have SSH exposed with weak credentials. That's the door.

Once in, the implant pulls the main payload via HTTP GET:

```
hxxp[://]103.41.204[.]104/k.php?a=x86_64
```

A second URL variant assigns a parent bot ID for botnet topology tracking:

```
hxxp[://]103.41.204[.]104/k.php?a=x86_64,<PARENT_ID>
```

The server is not geo-restricted. Anyone can request the sample and will receive the same binary with a randomly assigned ParentID value embedded in the JSON configuration trailer. The URL is flagged in multiple threat intel feeds and has been active for months.

**The UPX trick that keeps breaking tools**

This is the part I find genuinely clever. The ELF binary is packed with UPX, which is ordinary enough. What makes it interesting is that the operators append a custom JSON configuration blob to the end of the packed file, after the legitimate UPX trailer. UPX validates its own trailer metadata before decompression. The appended JSON corrupts the overlay offset in a way that causes `upx -d` to throw an error and bail out.

The result: most automated static analysis pipelines that call `upx -d` as a first-pass deobfuscation step fail silently. The sample stays packed. No strings extracted, no IOCs surfaced.

To actually unpack it, you have to strip the JSON trailer first, run `upx -d` on the cleaned binary, then reattach the trailer for config parsing. The JSON config fields include `ParentId`, `ParentHostname`, `ParentIp`, `ip`, `config`, and `enckey`. Those fields drive C2 behavior and botnet hierarchy. Without them, the unpacked binary will not initialize correctly.

This is a deliberate anti-analysis design, not an accident. The operators know exactly what they are doing to defender tooling.

**Persistence and recon**

After execution, Prometei drops a malicious cron job (T1053.003) for persistence. The specific cron entry varies by variant but the effect is the same: the binary re-downloads and re-executes itself from the C2 URL on a schedule, ensuring the implant survives reboots and manual removal of the binary on disk.

The system recon routine collects CPU details from `/proc/cpuinfo`, motherboard information via `dmidecode`, OS information from `/etc/os-release` and `/proc/version`, uptime via the `uptime` command, and kernel details via `uname -r`. All of this goes out via HTTP GET to:

```
hxxp://152.36.128[.]18/cgi-bin/p.cgi
```

This telemetry feeds the operators' infrastructure map and probably helps them prioritize high-core-count targets for mining efficiency.

**C2 resilience**

The botnet uses a domain generation algorithm (T1568.002) to generate fallback C2 domains dynamically, which means hardcoded IP blocklisting is not enough for long-term defense. The self-updating mechanism means the binary can swap its own code out through the cron-based re-download loop. Defenders who remove the cron job and the binary but do not patch the initial access vector will get re-infected on next check-in.

**The miner**

The payload deploys XMRig targeting Monero pools (T1496). CPU-bound Monero mining works on any hardware, which is why Linux servers, especially cloud instances with substantial core counts, are attractive targets. The money is modest per node but scales across a large botnet. This is commodity exploitation economics.

---

## Educational Sample

The UPX JSON trailer technique is worth understanding as a defender because it breaks a lot of common tooling assumptions. This stripped-down Python skeleton shows how an automated unpacking pipeline would handle it correctly. No malicious payload, no C2 strings.

```python
# EDUCATIONAL SAMPLE — demonstrates UPX trailer strip-and-restore for Prometei-style packing
# This does NOT contain any malicious payload
# For research and defensive awareness only

import subprocess
import json

def find_json_trailer(data: bytes) -> int:
    """
    Locate the start of the appended JSON config blob.
    Prometei appends a JSON object starting with {"config": after the UPX trailer.
    Returns the offset of the JSON trailer, or -1 if not found.
    """
    marker = b'{"config":'
    idx = data.rfind(marker)
    return idx

def safe_unpack(packed_path: str, output_path: str) -> dict | None:
    """
    Strip the JSON trailer, unpack via UPX, return the parsed config.
    """
    with open(packed_path, "rb") as f:
        data = f.read()

    trailer_offset = find_json_trailer(data)
    if trailer_offset == -1:
        print("No JSON trailer found — may not be Prometei or already stripped.")
        return None

    # Separate the UPX-packed ELF from the appended JSON config
    packed_elf = data[:trailer_offset]
    json_trailer = data[trailer_offset:]

    # Write the stripped binary to a temp file for UPX decompression
    stripped_path = packed_path + ".stripped"
    with open(stripped_path, "wb") as f:
        f.write(packed_elf)

    # Attempt UPX decompression — this would fail on the original file
    result = subprocess.run(
        ["upx", "-d", stripped_path, "-o", output_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"UPX failed: {result.stderr}")
        return None

    # Parse the config trailer for IOC extraction
    try:
        config = json.loads(json_trailer)
        print(f"ParentId: {config.get('ParentId', 'N/A')}")
        print(f"ParentIp: {config.get('ParentIp', 'N/A')}")
        print(f"C2 ip: {config.get('ip', 'N/A')}")
        return config
    except json.JSONDecodeError:
        print("Trailer present but JSON parsing failed.")
        return None

# Example usage (benign test file only):
# config = safe_unpack("sample.elf", "sample_unpacked.elf")
```

The key insight for defenders building automated pipelines: before calling `upx -d`, scan the binary for a trailing JSON blob starting with `{"config":`. If it is present, strip it, unpack, then parse it separately. You will get significantly better coverage on this family.

---

## Detection and Defense

**YARA rules from Stairwell**

Stairwell's threat research team published three rules after the March 2025 resurgence, and they hold up against samples still appearing today:

```yara
rule Prometei_UPXJSON_config
{
    meta:
        description = "Detects Prometei malware with UPX and JSON config trailer"
        author = "vincentzell@stairwell.com"
        date = "2025-07-01"
    strings:
        $upx_magic      = { 55 50 58 21 }
        $overlay_offset = { F4 00 00 00 }
        $json_config    = "{\"config\":" ascii
    condition:
        all of them and
        filesize >= 404787 and filesize <= 436122
}

rule Prometei_ELF_Strings
{
    meta:
        author = "vincentzell@stairwell.com"
        date = "2025-07-01"
        description = "Detects recent Linux Prometei variants (March 2025+), works on packed samples"
    strings:
        $s1 = "HTTP/1.04Ho&:$" ascii
        $s2 = "9999 !\"#9999$%&'9999" ascii
        $s6 = "bOtEuMN2Bpx2" ascii
    condition:
        2 of them
}
```

**Linux audit and Sysmon events**

On Linux with `auditd`, watch for cron modification (writes to `/etc/cron.*` or `/var/spool/cron/crontabs/`), new ELF execution from `/tmp` or home directories, and outbound HTTP connections from cron-spawned processes. The specific syscalls to alert on are `execve` for new ELF process creation and `connect` for unexpected outbound HTTP from shell processes.

On Windows (for the SMB lateral movement path), Sysmon Event ID 3 will catch the EternalBlue exploit connections on port 445 before the implant lands. Event ID 1 will show the UPX-packed binary executing from a suspicious path. Event ID 11 tracks file creation, which helps if the binary writes itself to disk before executing.

For network-based detection, the C2 IP `152.36.128.18` hitting `/cgi-bin/p.cgi` is a reliable indicator for current campaign variants. The HTTP GET to `103.41.204.104/k.php` is the download channel. Both should be in your blocklists.

**Mitigations**

Disable SSH password authentication entirely. Key-based auth removes the brute-force vector in one change. Patch MS17-010 if any Windows boxes remain unpatched (they do, I keep seeing them in engagements). Monitor CPU usage anomalies for unexpected spikes, which are often the first observable sign of a miner on a system that has not been fully hardened. And build that JSON trailer check into your malware pipeline so UPX-packed samples with appended config blobs do not slip through unpacked.

The campaign is active. The technique is reproducible across new variants. Worth making sure your detections cover this specific packing pattern.
