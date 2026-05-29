---
layout: post
title: "ClearFake Drops a Go-Compiled DLL That Unhooks ntdll to Blind Your EDR"
date: 2026-05-29
categories: [malware, analysis]
tags: [clearfake, golang, dll, ntdll-unhooking, evasion, rundll32, mitre-attack]
excerpt: "A ClearFake sample dropped today on MalwareBazaar is a 32-bit Go-compiled DLL that bypasses EDR hooks by remapping ntdll from KnownDlls, uses NtClose(0xdeadc0de) as an anti-debug tripwire, and goes completely dark in sandbox — zero network hits, clean bail-out."
---

Fresh off MalwareBazaar today: a ClearFake dropper that is doing things I do not normally see from this campaign family. The name is `goog.ct_2026-05-29`. It is disguised as a Google Certificate Transparency log file, it is compiled in Go, and it performs a textbook ntdll unhook via KnownDlls to strip EDR hooks before doing anything visible. In the CAPE sandbox it made zero network calls and returned `DLL_INIT_FAILED` — it detected the analysis environment and shut down cleanly. Seven vendor detections at time of submission.

This is not generic ClearFake commodity garbage.

---

## What Showed Up

Sample submitted to MalwareBazaar 2026-05-29 19:25:15 UTC. Origin country: Norway.

SHA256: `2f6435c735dc6361121d8b675cc954e42dc53dd9eb64029bfee9f53d3853073f`

MalwareBazaar entry: [https://bazaar.abuse.ch/sample/2f6435c735dc6361121d8b675cc954e42dc53dd9eb64029bfee9f53d3853073f/](https://bazaar.abuse.ch/sample/2f6435c735dc6361121d8b675cc954e42dc53dd9eb64029bfee9f53d3853073f/)

File type: PE32 DLL (32-bit, SysWOW64 context). File size: 11,931,648 bytes — that 11.4 MB is suspicious on its own. Legitimate DLLs are rarely this large; the extra bulk is either padding, embedded payloads, or both. Tags: `ClearFake`, `dll`. YARA matches: `golang_bin_JCorn_CSC846` (Go binary), `pe_detect_tls_callbacks` (TLS callback execution), `Sus_CMD_Powershell_Usage` (obfuscated command execution).

Delivery method per MalwareBazaar: web download. That fits the ClearFake playbook perfectly.

CAPE sandbox analysis: [https://www.capesandbox.com/analysis/68500/](https://www.capesandbox.com/analysis/68500/)

---

## What Makes It Work

ClearFake is a JavaScript-based distribution framework, active since mid-2023, that operates by injecting malicious scripts into compromised WordPress sites. The victim visits a normal-looking website, gets served a fake "Your browser is out of date" or fake reCAPTCHA overlay, and is prompted to download an "update." As of early 2025, ClearFake had infected roughly 9,300 sites and upgraded its payload obfuscation by routing stage-two JavaScript through Binance Smart Chain contracts, making infrastructure takedowns harder. Recent campaigns have also converged with the ClickFix technique, prompting PowerShell execution instead of a direct download.

This sample represents a technical jump for the campaign. Here is what the CAPE behavioral trace tells us.

**Execution via rundll32 (T1218.011)**

The DLL lands in `%LocalAppData%\Temp\goog.ct_2026-05-29.dll` and is invoked as:

```
"%WINDIR%\System32\rundll32.exe" "%LocalAppData%\Temp\goog.ct_2026-05-29.dll",#1
```

The `,#1` is execution by ordinal export number rather than by name. That is a deliberate obfuscation choice — you cannot see the export name in a process listing, it just shows as `#1`. The parent process is PID 816, consistent with an installer or script host that dropped the file and called rundll32 as a child. rundll32 itself is a signed Microsoft binary, so the process is trusted by default on most allowlist configurations.

**TLS callbacks for pre-main execution**

The YARA hit on `pe_detect_tls_callbacks` means the DLL registers a Thread Local Storage callback. TLS callbacks in a PE fire before the standard `DllMain` entry point runs — before any debugger has a chance to set a breakpoint at the entry point, and before most PE analysis tools process the file normally. This is where the anti-analysis checks happen.

**Anti-debug via NtClose(0xdeadc0de) (T1497.001)**

The behavioral trace shows:

```
NtClose Handle: 0xdeadc0de  →  failed INVALID_HANDLE
```

Called twice, at different points in execution. This is a classic Windows debugger detection primitive. Under normal execution, `NtClose` on an invalid handle fails silently and returns `STATUS_INVALID_HANDLE`. When a kernel debugger like WinDbg is attached and has `sxe ch` (close handle exceptions) configured, the same call raises a `EXCEPTION_INVALID_HANDLE` exception instead. The malware catches that exception — or rather, checks whether the call throws at all — to determine if a debugger is present. The value `0xdeadc0de` is a well-known marker in this specific technique.

**ntdll unhooking via KnownDlls (T1562.001)**

This is the most interesting part of the trace. The DLL executes these NT calls in sequence:

```
NtOpenSection "\KnownDlls\ntdll.dll"  →  handle 0x220
NtMapViewOfSection  →  maps clean ntdll at 0x06d80000
NtUnmapViewOfSection 0x77830000  →  unmaps original ntdll
```

What is happening: EDR products (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, and others) instrument Windows API calls by placing hooks — short JMP instructions — at the start of key functions inside the loaded ntdll.dll copy in process memory. When your process calls `NtCreateProcess`, the EDR hook fires first, logs the call, then jumps to the real function. This is how behavioral monitoring works.

The bypass: `\KnownDlls\ntdll.dll` is a read-only memory-mapped section that the Windows kernel pre-creates at boot from the clean, on-disk ntdll.dll. It is not modified by EDRs. The DLL opens that clean section, maps it into its own address space, and then unmaps the EDR-hooked original at `0x77830000`. The result is a fresh, unhhooked ntdll — every syscall the malware makes from that point on bypasses EDR monitoring entirely.

This technique is well-documented in the red team community. What is notable here is that it is implemented in Go, which is unusual. The YARA rule `golang_bin_JCorn_CSC846` confirms the binary uses Go runtime structures. Go's garbage collector and goroutine scheduler complicate the mapping operations slightly, but the NT native API calls (`NtOpenSection`, `NtMapViewOfSection`) are platform-level regardless of language.

**Dynamic API resolution (T1027)**

Alongside the unhook, the DLL uses `LdrGetProcedureAddressForCaller` to resolve the following functions at runtime rather than importing them statically:

- `GetThreadContext` / `SetThreadContext`
- `OpenThread`
- `GetProcessId`
- `IsProcessorFeaturePresent`

This combination points toward thread-based code injection as a likely next stage. `GetThreadContext` and `SetThreadContext` together with `OpenThread` are the building blocks of thread hijacking injection: suspend a thread, redirect its instruction pointer to shellcode, resume. Static import analysis would miss all of these since they are resolved dynamically.

**Sandbox detection and clean exit**

Zero hosts were contacted in the CAPE analysis. The DLL returned `DLL_INIT_FAILED` to rundll32, meaning `DllMain` returned `FALSE` for `DLL_PROCESS_ATTACH`. The malware detected the sandbox environment — via the NtClose debugger check, via environment fingerprinting (`NtQuerySystemInformation` class 164 is an uncommon query used to detect analysis VMs), or via timing checks — and cleanly aborted before doing anything network-visible. This is why only 7 vendors flag it: there is almost no observable behavior to trigger signatures.

---

## Educational Sample: ntdll Unhooking via KnownDlls in Go

This demonstrates the unhooking technique using Go's `syscall` and `golang.org/x/sys/windows` packages. No payload. This maps the clean ntdll and prints section details only.

```go
// EDUCATIONAL SAMPLE -- demonstrates ntdll unhooking via KnownDlls section
// This does NOT contain any malicious payload
// For research and defensive awareness only

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SECTION_MAP_READ = 0x0004
	PAGE_READONLY    = 0x02
)

func main() {
	// Step 1: Open the \KnownDlls\ntdll.dll section (clean, kernel-mapped, no EDR hooks)
	knownDllsNtdll, _ := syscall.UTF16PtrFromString(`\KnownDlls\ntdll.dll`)

	oa := windows.OBJECT_ATTRIBUTES{}
	oa.Length = uint32(unsafe.Sizeof(oa))

	var uStr windows.NTUnicodeString
	windows.RtlInitUnicodeString(&uStr, knownDllsNtdll)
	oa.ObjectName = &uStr

	var sectionHandle windows.Handle
	ntStatus, _, _ := syscall.SyscallN(
		// NtOpenSection
		windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenSection").Addr(),
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_MAP_READ,
		uintptr(unsafe.Pointer(&oa)),
	)
	if ntStatus != 0 {
		fmt.Printf("[!] NtOpenSection failed: 0x%x\n", ntStatus)
		return
	}
	fmt.Printf("[+] Opened KnownDlls ntdll section: handle=0x%x\n", sectionHandle)

	// Step 2: Map the clean ntdll into our process
	var baseAddr uintptr
	var viewSize uintptr
	ntStatus, _, _ = syscall.SyscallN(
		windows.NewLazySystemDLL("ntdll.dll").NewProc("NtMapViewOfSection").Addr(),
		uintptr(sectionHandle),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&baseAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		2, // ViewUnmap -- child processes do not inherit
		0,
		PAGE_READONLY,
	)
	if ntStatus != 0 && ntStatus != 0x40000003 { // 0x40000003 = STATUS_IMAGE_NOT_AT_BASE, normal
		fmt.Printf("[!] NtMapViewOfSection failed: 0x%x\n", ntStatus)
		return
	}
	fmt.Printf("[+] Clean ntdll mapped at: 0x%x  size: 0x%x\n", baseAddr, viewSize)

	// In real malware: the original ntdll at its load address (~0x77830000) is
	// unmapped and replaced with this clean copy, stripping all EDR hooks.
	// We do NOT do that here -- we just print what we found and exit.
	fmt.Println("[*] In a real unhook, original ntdll would be unmapped here.")
	fmt.Println("[*] Subsequent syscalls would bypass all EDR hook points.")

	windows.CloseHandle(sectionHandle)
}
```

The real malware follows this map with `NtUnmapViewOfSection` on the EDR-patched ntdll at its original load address, then (probably) copies the clean mapping over. From that point on, every `NtCreateProcess`, `NtWriteVirtualMemory`, or `NtCreateThread` call runs raw with no interception.

---

## Detection and Defense

**YARA:**

```yara
rule ClearFake_Go_DLL_Unhook_2026 {
    meta:
        description = "ClearFake Go DLL with ntdll unhooking and anti-debug"
        hash        = "2f6435c735dc6361121d8b675cc954e42dc53dd9eb64029bfee9f53d3853073f"
    strings:
        $go_magic    = { 47 6F 20 62 75 69 6C 64 20 49 44 }  // "Go build ID"
        $deadc0de    = { DE AD C0 DE }
        $knowndlls   = "\KnownDlls\ntdll.dll" ascii wide
        $rundll_arg  = ",#1" ascii
        $appdata_tmp = "AppData\\Local\\Temp" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of ($go_magic, $deadc0de, $knowndlls) and
        1 of ($rundll_arg, $appdata_tmp)
}
```

**Sysmon detection points:**

Event ID 7 (Image Loaded): `rundll32.exe` loading a DLL from `%LocalAppData%\Temp\` is uncommon and worth flagging. Legitimate DLLs loaded by rundll32 almost always live in `%SystemRoot%\System32` or a program install directory.

Event ID 1 (Process Create): `rundll32.exe` with a command line containing `,#` (ordinal-based export invocation) and a path inside `%LocalAppData%\Temp`. Combine with a parent process that is not explorer.exe, msiexec, or a known installer.

Event ID 10 (Process Access): Any process requesting `PROCESS_VM_WRITE` on a process after calling `NtOpenSection` on KnownDlls. This is the post-unhook injection setup. Sysmon's `CallTrace` field will show `ntdll.dll+` offsets that do not match the known ntdll base if remapping has occurred.

Kernel-level detection: Monitor for `NtMapViewOfSection` calls where the source section is `\KnownDlls\ntdll.dll` and the target process is the caller itself. That pattern is specific to this unhooking class.

**Filesystem indicators:** Any file in `%LocalAppData%\Temp\` with a `.dll` extension and a filename mimicking a known vendor product or log format (`goog.*`, `chrome.*`, `msft.*`, etc.) that is over 5 MB should be treated as suspicious.

**Mitigation:** The ntdll unhooking bypass is not fully preventable from userland. The architectural answer is kernel-level monitoring via ETW (Event Tracing for Windows) providers that watch section mapping operations, or a driver-based EDR component that hooks at a level the userland DLL cannot reach. For environments without kernel-level EDR, constrain rundll32 execution via WDAC or AppLocker to signed, known DLLs only — that kills this delivery method before the DLL even loads.

The larger ClearFake picture: the campaign now distributes Lumma Stealer, Vidar Stealer, and multiple loaders through a network of 9,000+ compromised WordPress sites. Blocking the delivery layer (WordPress site compromise cleanup, browser-level script blocking) is more scalable than trying to catch each new dropper variant, especially when the dropper is this good at hiding.
