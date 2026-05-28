---
layout: post
title: "RemusStealer on MalwareBazaar Today: Go Injector, Blockchain C2, and the ABE Bypass Chrome Still Can't Stop"
date: 2026-05-27
categories: [malware, analysis]
tags: [RemusStealer, LummaStealer, process-injection, EtherHiding, ABE-bypass, golang, mitre-attack, infostealer]
excerpt: "RemusStealer, a signed Go-based infostealer descended from Lumma, landed on MalwareBazaar fresh this morning using blockchain-backed C2 resolution and a shellcode injection trick that strips Chrome's Application-Bound Encryption straight from browser memory."
---

Fresh off the MalwareBazaar browse queue this morning: a cluster of RemusStealer samples distributed from the `hippamsas-com` C2 domain, all first-seen within a two-hour window. The sample I'm working from is `84705a48cd1e868dc45ca6f42d565cf1c2a3c44def8fe25f7f15e5b3962bc5e8`, a 7.1MB Win64 PE timestamped 10:53 UTC today. It carries a code-signing certificate issued to www.sjabr.org (serial `06036922e36f40a6911679792abaafe28cd2`, valid May 8 through August 6, 2026), meaning it walks past naive signature-based defenses with a plausible-looking trust chain. A companion from the same campaign, `cdd16fc0a2bf1499ba815bc95288456e46c7245b64c9d06033f2c61eb06900f5`, carries an explicit `go` tag on Bazaar and hits ReversingLabs' Win64.Trojan.GoInject classification, confirming the delivery binary is Go-compiled. Six other samples in MalwareBazaar share the same rogue signing certificate.

MalwareBazaar entry: https://bazaar.abuse.ch/sample/84705a48cd1e868dc45ca6f42d565cf1c2a3c44def8fe25f7f15e5b3962bc5e8/

Remus has been active since early 2026, appearing shortly after Lumma Stealer's core operators were publicly identified between August and October 2025. Gen Threat Labs traced the lineage through intermediate builds labeled "Tenzor," compiled September 2025, which bridge earlier Lumma samples directly to current Remus binaries. The code continuity is not subtle: matching string obfuscation schemes, identical anti-VM logic, the same ChaCha20 config decryption layout, and a very specific Application-Bound Encryption bypass technique that, until Remus appeared, had only ever been seen in Lumma. This is a 64-bit native branch of the same codebase, not a copycat.

## What makes it work

The attack chain starts with a web download from hippamsas-com infrastructure. The binary is signed, 7MB, and Go-compiled, which already creates friction for analysis tools tuned to conventional C/C++ stealers. The techniques inside are where it gets interesting.

Remus hides its strings by assembling encrypted values on the stack using `mov` instruction sequences, then decoding each one with a per-string Mixed Boolean-Arithmetic (MBA) loop. MBA obfuscation produces mathematically equivalent but syntactically bizarre expressions like `((x ^ 0xDEAD) + 0x1234) & 0xFF` to represent a simple constant. It is not compression or XOR-with-key. These loops are specifically designed to defeat symbolic execution and pattern-matching deobfuscators, and they are padded with atypical `nop` sequences that show up identically in Lumma samples. C2 configuration, encrypted blobs, keys, and nonces, lives in `.rdata` and is decrypted at runtime with ChaCha20.

Rather than importing Windows APIs through the Import Address Table, Remus resolves them by CRC32-hashing export names in `ntdll.dll` at runtime and dispatching calls through a direct sysenter stub. This sidesteps usermode API hooks placed by EDR products, since the call never touches the monitored stub functions. Sysmon and ETW-based telemetry survive this. Many endpoint agents hooking `NtCreateProcess`, `NtWriteVirtualMemory`, and related functions at the usermode layer do not.

The C2 resolution technique is where Remus breaks from the commodity stealer mold. Old Lumma builds used dead drop resolvers on Steam profiles and Telegram channels, storing ROT-15 obfuscated C2 URLs in publicly accessible web content. Remus replaces that with EtherHiding. The malware issues an `eth_call` JSON-RPC request to a hardcoded Ethereum smart contract through a public RPC endpoint, then decodes the C2 address from the hex-encoded return data. Because Ethereum smart contract state is decentralized and effectively immutable from a takedown perspective, there is no domain to sinkhole, no account to ban, and no infrastructure to seize. The operator updates the embedded C2 by calling the contract, and every infected machine resolves the new value on next check-in. It's a genuinely clever piece of operational security.

The ABE bypass is the most technically dense part. Chrome's Application-Bound Encryption, introduced in Chrome 127, wraps the local database encryption key using DPAPI with a machine-bound identity specifically to prevent other processes from decrypting it. Remus sidesteps this by injecting a compact shellcode of roughly 51 bytes into the live browser process, where it inherits the browser's own process identity. Inside that context, the shellcode locates `dpapi.dll`, resolves `CryptUnprotectMemory` via export hash, and then scans `chrome.dll` for a specific opcode pattern leading to the `os_crypt_async::Encryptor` vtable that holds the protected key. Once it locates the vtable, it walks memory for object instances, extracts the `v20_master_key` at a known offset, copies it to a pre-allocated buffer, and calls `CryptUnprotectMemory` with the `CRYPTPROTECTMEMORY_SAME_PROCESS` flag. The key decrypts in-process. The result is the plaintext master key, which decrypts every cookie, saved password, and autofill entry in Chrome's `Login Data` SQLite database. MFA tokens stored as cookies come with it.

If injection fails or no browser is running, Remus falls back to calling `CreateDesktop` to spin up a hidden desktop, launching Chrome there to avoid any visible window, and using SYSTEM token impersonation as an alternate ABE unlock path (T1134.001).

The sandbox evasion is thorough. Remus checks CPUID leaf `0x40000000` for hypervisor brand strings, scanning for VMware's `VMwareVMware`, VirtualBox's `VBoxVBoxVBox`, KVM's `KVMKVMKVM`, and Xen signatures in the same order and with similarly obfuscated comparison constants as Lumma (T1497.001). On top of that, it runs a CRC32 scan of loaded DLLs hunting for modules associated with Avast Sandbox, Sandboxie, and Comodo. It also checks for a honeypot PST file, specifically a fake Outlook archive that some automated sandboxes place on disk. If either check triggers, the binary terminates silently with no network activity. It just looks like a crash.

## Educational sample: EtherHiding C2 resolution in Go

The most defensively useful technique to understand here is EtherHiding. Knowing what the malware's blockchain-based DNS equivalent looks like helps build network-layer detections. The snippet below demonstrates the mechanism with no malicious payload and no real C2 interaction.

```go
// EDUCATIONAL SAMPLE -- demonstrates the EtherHiding C2 resolution technique
// This does NOT contain any malicious payload
// For research and defensive awareness only
//
// Shows how malware can use a public Ethereum RPC endpoint to resolve a C2 address
// embedded in smart contract storage, rather than traditional DNS or a hardcoded domain.
// In a real stealer, the contract address and RPC endpoint are decrypted from .rdata
// at runtime using ChaCha20 with a per-sample key.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// In production malware, both values below are decrypted at runtime from .rdata.
// Using a nonexistent placeholder contract address here for safety.
const (
	contractAddr = "0x0000000000000000000000000000000000000001" // placeholder, not real
	rpcEndpoint  = "https://cloudflare-eth.com"               // public RPC, no malicious use
)

type ethCallRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// resolveC2FromChain simulates how EtherHiding reads C2 data from a smart contract.
// The returned hex-encoded contract state decodes to the C2 address string.
// Real samples apply a second ChaCha20 decryption pass on the decoded bytes.
func resolveC2FromChain(contract, rpc string) (string, error) {
	// ABI function selector for a simple get() view function.
	// Actual malware uses a contract-specific selector decoded from obfuscated config.
	callData := "0x6d4ce63c"

	req := ethCallRequest{
		JSONRPC: "2.0",
		Method:  "eth_call",
		Params: []interface{}{
			map[string]string{
				"to":   contract,
				"data": callData,
			},
			"latest",
		},
		ID: 1,
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(rpc, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	hexData, ok := result["result"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected RPC response shape")
	}

	// Strip the "0x" prefix and hex-decode.
	// In the wild this produces a null-terminated ASCII C2 hostname or IP:port string.
	raw, err := hex.DecodeString(strings.TrimPrefix(hexData, "0x"))
	if err != nil {
		return "", fmt.Errorf("hex decode failed: %w", err)
	}

	return strings.TrimRight(string(raw), "\x00"), nil
}

func main() {
	fmt.Println("[educational demo] Resolving C2 from Ethereum contract storage...")
	addr, err := resolveC2FromChain(contractAddr, rpcEndpoint)
	if err != nil {
		fmt.Println("Could not resolve:", err)
		return
	}
	fmt.Println("Decoded contract data:", addr)
}
```

The key detection implication: this produces outbound HTTPS POST requests to a public Ethereum JSON-RPC provider on port 443, not the usual RPC port 8545. Any process that is not a crypto wallet, blockchain node, or development tool making `eth_call` requests to `cloudflare-eth.com`, `rpc.ankr.com`, `mainnet.infura.io`, or similar endpoints is worth immediate investigation. The request body will contain `"method":"eth_call"` with a `"to"` address and a `"data"` field, which makes it identifiable in proxy or DPI logs regardless of TLS if you're doing full packet inspection.

## Detection and defense

A YARA rule targeting the family's behavioral fingerprint:

```yara
rule RemusStealer_Go_EtherHiding
{
    meta:
        description = "Detects RemusStealer Go injector with EtherHiding C2 and ABE bypass indicators"
        author      = "Garrett Stimpson"
        date        = "2026-05-27"
        reference   = "https://bazaar.abuse.ch/sample/84705a48cd1e868dc45ca6f42d565cf1c2a3c44def8fe25f7f15e5b3962bc5e8/"
        hash1       = "84705a48cd1e868dc45ca6f42d565cf1c2a3c44def8fe25f7f15e5b3962bc5e8"
        hash2       = "cdd16fc0a2bf1499ba815bc95288456e46c7245b64c9d06033f2c61eb06900f5"

    strings:
        $eth_call     = "eth_call"              ascii nocase
        $jsonrpc      = "jsonrpc"               ascii
        $latest       = "\"latest\""            ascii
        $go_runtime   = "runtime.GOMAXPROCS"    ascii
        $vmware       = "VMwareVMware"          ascii
        $vbox         = "VBoxVBoxVBox"          ascii
        $kvm          = "KVMKVMKVM"             ascii
        $c2_campaign  = "hippamsas"             ascii nocase
        $chacha       = "chacha20"              ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize > 4MB and filesize < 12MB
        and $go_runtime
        and (
            ($eth_call and $jsonrpc and $latest)
            or ($c2_campaign)
            or (2 of ($vmware, $vbox, $kvm) and $chacha)
        )
}
```

The Sysmon events that matter most here are process access (Event ID 10), file creation (Event ID 11), and image load (Event ID 7). On Event ID 10, flag any non-browser, non-system process requesting `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ` access on `chrome.exe` or `msedge.exe`. That exact access mask is needed to inject the ABE bypass shellcode and normal system behavior does not include cross-process browser memory writes. On Event ID 11, watch for short-lived SQLite database copies or files named `Processes.txt` created in `%TEMP%` or `%APPDATA%\Local\Temp` by a recently-executed unsigned PE. On Event ID 7, a `dpapi.dll` image load attributed to `chrome.exe` with an unusual initiating call stack (one that traces back through injected shellcode rather than a Chrome internal) is a strong secondary indicator.

For network detection, a Sigma rule on proxy or firewall logs targeting HTTPS POSTs to known Ethereum RPC providers from non-wallet processes is the highest-value detection for EtherHiding. The HTTP body will be JSON with `"method":"eth_call"`, and no legitimate browser, Office application, or general-purpose tool makes this call.

Mitigating the ABE bypass at the OS level is possible but requires some work. Enabling `PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS` on browser processes via Windows Defender Application Control blocks the shellcode write to browser memory. The Microsoft Attack Surface Reduction rule for blocking process injection (GUID `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`) will catch many injection paths. For the code signing evasion, adding a WDAC policy that requires certificates from a specific trusted root rather than allowing any valid EV cert will prevent rogue certs like the sjabr.org one from getting through. The CA that issued it (listed as "Issuer: E8" in the Bazaar entry) is worth monitoring for other recently-issued certs appearing in this campaign, since RemusStealer operators appear to be burning through short-lived signing certs roughly every 90 days.

Six samples in MalwareBazaar now share the same certificate thumbprint `eae49c47a0dde758f20b3bf6616579b11461873a072d371578eb42282f269277`. Blocking on that thumbprint is a quick defensive win until the next cert rotation.

MITRE ATT&CK coverage for this sample: T1027.010 (MBA string obfuscation), T1055 (process injection into Chrome), T1553.002 (rogue code signing certificate), T1497.001 (CPUID anti-VM), T1555.003 (credentials from web browsers), T1134.001 (SYSTEM token impersonation for hidden desktop fallback), T1071 (EtherHiding via Ethereum JSON-RPC as application layer protocol).
