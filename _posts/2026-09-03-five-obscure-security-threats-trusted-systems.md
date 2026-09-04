---
layout: post
title: "Five Security Threats Almost Nobody Is Watching Yet"
date: 2026-09-03
categories: [research, threats]
tags: [usenix-security, wild-attack, opossum-attack, windows-vbs, bacnet-sc, x402, wifi-geolocation, starttls, memory-aliasing, building-automation, agentic-payments]
excerpt: "Poisoned Wi-Fi maps, TLS that authenticates the wrong conversation, RAM that lies about its own size, authenticated building controllers stealing each other's identities, and payment agents that spend somebody else's gas. Five new attack classes hiding outside the normal CVE-and-patch loop."
---

I went through the attack papers from USENIX Security '26, and the bugs that bothered me most were not the browser zero-days or another clever way around an LLM guardrail. They were the ones sitting underneath things we already call secure.

The TLS handshake succeeds. The certificate is valid. Secure Boot is on. The building controller belongs to the right PKI. The blockchain signature verifies. Every green light turns on, and the system still does the wrong thing.

That is the common failure in the five attacks below. None of them beat the cryptography. They exploit the meaning around it: which conversation a TLS session belongs to, which physical cells a memory address reaches, which device identity a certificate is allowed to claim, whether a verified payment actually settles, and whether a crowd-sourced coordinate ever came from the access point it describes.

Most vulnerability scanners will not find any of this. Three of the five are protocol or infrastructure failures rather than ordinary product bugs. One lives in a two-dollar EEPROM on a RAM stick. One poisons a database you do not own and cannot inspect.

This is the security work waiting outside the CVE feed.

## 1. WILD Attack: poison the map instead of spoofing the phone

Phones do not use GPS alone to determine where they are. Indoors, between tall buildings, and on devices without a GPS receiver, they lean on Wi-Fi Positioning Systems. The device scans nearby access points, sends their BSSIDs to a provider, and gets coordinates back from a giant Location Lookup Table:

```
Nearby Wi-Fi BSSIDs
        |
        v
Google / Apple / A-Map / WiGLE lookup table
        |
        v
Estimated latitude and longitude
```

The lookup table is crowd-sourced. Phones that can see both Wi-Fi beacons and a known location continuously teach the provider where access points live. That makes the service scale. It also means the integrity of a global location system depends on providers deciding which crowd reports to believe.

WILD attacks that decision.

The attacker first collects the BSSIDs around a target area. The researchers did not need to visit it: they chained neighbouring results from Apple's geolocation interface and enumerated likely last-byte variations, recovering more than 90 percent of the target BSSIDs remotely. At a location the attacker controls, a cheap ESP32 broadcasts beacon frames carrying those BSSIDs. Real phones nearby see the forged beacons beside their genuine GPS coordinates and submit perfectly normal crowd-sourced reports.

Nothing malicious goes into the provider API. There is no forged certificate and no modified phone. Genuine devices report genuine observations. The lie is in the radio environment.

The provider now sees the same BSSID in two distant places. The researchers tested Google, Apple, A-Map, and WiGLE, and every one accepted the false reports. Their conflict policies produced different failures:

- Google eventually moved entries to the attacker's coordinates after roughly 11 days of sustained reporting. The false location remained for at least four weeks after the attacker stopped.

- WiGLE could be shifted in under 30 minutes, and affected entries remained near the false location months later.

- Apple removed conflicting entries after three days rather than choosing a location. Those entries were still gone two months later even though the real access points remained active.

- A-Map removed entries after roughly two days, with disruption persisting for two to three weeks.

The clever part is that the victim never sees a rogue access point. All the fake radio traffic happens somewhere else. Weeks later, a phone at the real location scans the legitimate routers it has always seen, asks the provider where they are, and receives an answer poisoned in advance.

The paper's case studies show three consequences: persistent location denial at city scale, ride-hailing pickups displaced by kilometres, and precise false location on GPS-less devices. I would add a fourth: any fraud, access-control, or device-management system treating Wi-Fi-derived location as an authorization signal has quietly inherited this trust failure. "Known office Wi-Fi nearby" does not mean the lookup service still maps that BSSID to the office.

There is very little an ordinary network operator can patch. The database belongs to the WPS provider. What defenders can do is stop treating a single location provider as proof. High-risk decisions should cross-check GPS, cellular, IP, device history, and impossible-travel signals, then fail closed when those sources disagree. Operators can also baseline the returned coordinates for fixed corporate access points and alert on movement or sudden disappearance. An AP bolted to a ceiling should not teleport across Toronto.

For the providers, the fixes are structural: restrict neighbouring-BSSID enumeration, quarantine large coordinate jumps, weight reports by stable device history and independent corroboration, and recover automatically to the last stable location after a conflict ends. The [WILD paper](https://www.usenix.org/conference/usenixsecurity26/presentation/zhu-changjia) says all four providers were notified. At publication, Google and Apple were reviewing the reports; A-Map said it would consider improvements, while WiGLE pointed to credibility and clustering controls that the researchers were still able to bypass with newly registered users.

## 2. Opossum: TLS authenticates the server and still delivers the wrong response

Old Internet protocols added encryption in two ways. Implicit TLS starts the secure connection immediately on a dedicated port: HTTPS on 443, IMAPS on 993, POP3S on 995. Opportunistic TLS starts in plaintext on the old port and upgrades the existing connection after a command such as `STARTTLS` or HTTP's largely forgotten `Upgrade: TLS` mechanism.

Running both modes on the same hostname looks like harmless compatibility. Opossum shows that the combination can break the ordering assumptions of the application protocol even when both endpoints are standards-compliant and the TLS implementation is flawless.

Here is the HTTP version stripped to its bones:

```
Browser thinks:                 Server thinks:

TLS handshake on :443          GET /attacker-chosen-path on :80
GET /victim-path               Upgrade: TLS
expect response to victim      TLS handshake
                               send response to attacker path
```

A man-in-the-middle opens a plaintext HTTP connection to the server, sends an attacker-chosen request that asks to upgrade to TLS, then tunnels the victim browser's HTTPS handshake through that upgraded connection. The certificate is valid because the same hostname serves both ports. After the handshake, the browser sends its real request inside TLS, but the attacker withholds it. The server sends the response to the pre-upgrade attacker request. The browser cannot see the missing history; it treats that response as the answer to its own request.

TLS protected every byte it was asked to protect. It just did not bind the channel to the application conversation that happened before the handshake.

The researchers turned that primitive into response substitution, cache poisoning, reflected XSS using HTTP range requests, and an Apache request-body desynchronization that can leak cookies carrying both `Secure` and `HttpOnly`. The last chain is particularly nasty: Apache expects the upgrade request's body after the TLS handshake, so the victim's first encrypted request becomes the body of the attacker's pre-handshake request. The following same-origin browser request can then be parsed as attacker-controlled POST data.

This is not a click-from-anywhere remote exploit. The attacker needs a man-in-the-middle position capable of manipulating the TCP stream. That means a hostile access point, a compromised router, a malicious network appliance, or another on-path foothold. But it does not require breaking TLS, stealing a private key, downgrading a cipher, or exploiting a parser bug.

The measured surface is not theoretical. An IPv4-wide scan found 20,121 servers that completed HTTP-to-TLS upgrades. Of the hosts from which the researchers could extract valid names, 2,268 also served implicit HTTPS and 539 used a certificate valid for both paths, creating the HTTP scenario Opossum needs. Their broader scan found susceptible implicit/opportunistic combinations across roughly 1.47 million IMAP servers, 1.14 million POP3 servers, 243,000 SMTP servers, and 219,000 FTP servers. The paper demonstrated practical end-to-end exploitation for HTTP; the other protocols were confirmed desynchronizable but not shown with equivalent full exploit chains.

Inventory is the first defense. Search configurations for HTTP `Upgrade: TLS`, SMTP/IMAP/POP `STARTTLS`, explicit FTPS, and libraries that automatically negotiate an upgrade. If a service already has an implicit-TLS port, turn the opportunistic path off. For mail environments where STARTTLS cannot disappear overnight, keep implicit and opportunistic endpoints on different identities and watch for abnormal upgrade sequences, unexpected `101 Switching Protocols`, and a request body arriving only after the TLS transition.

The clean protocol fix is a distinct ALPN identifier for the opportunistic variant, enforced at both ends, so the server can tell the two conversations apart. The researchers' blunt recommendation is better: deprecate opportunistic TLS wherever an implicit mode exists. The [Opossum paper](https://www.usenix.org/conference/usenixsecurity26/presentation/merget) won a distinguished paper award. The dusty HTTP feature it attacks is still documented in [RFC 2817](https://www.rfc-editor.org/rfc/rfc2817.html).

## 3. Download More RAM: turn an 8 GB stick into two views of the same 8 GB

Virtualization-Based Security is supposed to hold even after a Windows user gets local administrator. Credential Guard, Hypervisor-Protected Code Integrity, the secure kernel, Protected Process Light, and third-party EDR all depend on the hypervisor keeping protected memory outside the reach of the normal kernel.

Download More RAM walks around the hypervisor by convincing the hardware that the machine has memory cells that do not exist.

Every DIMM has a small Serial Presence Detect EEPROM containing its capacity, row geometry, timings, voltage, and vendor data. On affected consumer modules, that EEPROM is writable from software over SMBus/I2C. The attack increments the configured number of row-address bits, so an 8 GB stick reports 16 GB. The new high address bit is not connected to any physical row. Addresses in the supposed upper 8 GB therefore wrap onto cells in the real lower 8 GB.

```
Physical cells:       0 GB ---------------- 8 GB
                       ^                     ^
Normal addresses:     0 GB ---------------- 8 GB
Alias addresses:      8 GB --------------- 16 GB

Two physical addresses, one set of DRAM cells.
```

The page tables and hypervisor can mark the lower address protected and the upper address unused. The DIMM does not care. Both addresses activate the same row.

Turning that observation into a stable Windows attack took six steps. The researchers rewrote the SPD data from software, changed the vendor metadata so firmware would re-read it after reboot, used a Windows boot parameter to keep the OS out of the phantom upper half, read the alias with a forensic memory tool, overlaid a small RAM disk to obtain a limited write primitive, and patched `skci.dll` in the secure kernel. Once the vulnerable-driver blocklist stopped working, they loaded a previously blocked signed driver and turned the brittle write into arbitrary physical memory access.

From there VBS is scenery. Their case studies disabled Defender and third-party antivirus, modified VBS-protected processes, bypassed EDR and game anti-cheat, and defeated device-management policy. They automated the sequence into a one-click script that creates an account, configures auto-logon, reboots, kills the protected antivirus process, and runs a payload.

The prerequisite matters: this starts with local administrator on Windows 11 and a DIMM without SPD write protection. It is not initial access. The security failure is that VBS explicitly exists to contain privileged compromise, and the attack crosses that boundary without a Windows kernel vulnerability or physical access. The researchers found affected products from three DIMM manufacturers representing an estimated 55 percent of the high-performance memory market and 70 percent of gaming memory.

Microsoft assigned CVE-2026-23670 and changed Windows in the April 14, 2026 security update. On Secure Boot systems, the `removememory` boot option the published chain uses to stabilize aliased memory is now ignored. That breaks the demonstrated chain, but not the aliasing primitive; the paper is careful to say that another stabilization method would reopen it.

Defenders should install the April update, keep Secure Boot enabled, and enable any BIOS control that blocks SPD writes. Hardware teams should require SPD write protection in purchasing standards instead of treating RAM as an inert commodity. On endpoints, changes to BCD memory limits, SPD geometry or serial data, unexpected RAM-disk drivers, and a reboot followed by a new auto-logon account make a useful behavioural chain. DIMM manufacturers need to ship the real fix: permanently lock SPD writes before the module leaves the factory.

The full mechanics and affected market analysis are in [Download More RAM](https://www.usenix.org/conference/usenixsecurity26/presentation/collins), another distinguished paper from the conference.

## 4. Cuckoo: a valid building controller steals another controller's name

BACnet runs the machinery inside office towers, hospitals, campuses, and data centres: HVAC, lighting, access control, elevators, airflow, and fire-safety monitoring. Legacy BACnet/IP assumed a trusted network and shipped with essentially no native security. BACnet Secure Connect was the answer: TLS-protected WebSockets, mutual certificate authentication, and a site PKI.

The certificates work. The problem is what happens one layer above them.

A BACnet/SC node has at least three identities in play:

- its X.509 certificate, which proves it belongs to the site's trust domain;

- a UUID used to manage connections;

- a six-byte VMAC used by the hub to forward messages.

The certificate is not cryptographically bound to the UUID or VMAC. Any authenticated device can present its own valid certificate while claiming another device's logical identifiers. The standard's last-connection-wins reconnection behaviour then replaces the existing UUID mapping. Under some connection-table states, two sockets can also end up associated with the same VMAC, and deterministic table traversal sends the victim's traffic to whichever entry the attacker arranged to appear first.

That is Cuckoo. It does not forge a certificate, compromise the certificate authority, or break TLS. It starts from one legitimate certificate-bearing foothold—a compromised controller, infected engineering workstation, contractor device, or malicious insider—and uses protocol-compliant messages to discover a victim's identifiers, displace its connection state, and persistently receive traffic meant for it.

The prerequisite is realistic in building networks because the trust domain includes a messy population of controllers, integrator laptops, vendor appliances, and remotely serviced systems. One certificate says "this is a member of the building network." BACnet/SC accidentally interprets it as "this member may become any other member."

The researchers reproduced reconnaissance and hijacking against all six targets they tested: the official BACnet/SC Reference Stack, the open-source BACnet-Stack, Siemens Desigo CC V7, Johnson Controls Metasys ADS 13.0.3.103, Honeywell/Tridium VYKON N4 Supervisor 4.15.1.16, and Carrier/Automated Logic WebCTRL 1.12.218. That consistency matters. This is not six vendors making the same coding mistake; it is a standards-level identity-binding failure.

Default logging is not much help. Four tested platforms recorded a stolen-UUID reconnection as informational. Two silently replaced the connection without logging it at all. Defenders need explicit monitoring for UUID-to-socket changes, a UUID or VMAC moving between certificates, repeated reconnections, duplicate-VMAC errors, and address-resolution replies that suddenly point peers at a new URI. Site CAs should also be split by role and zone so a compromised lighting controller cannot join the same identity pool as access control or data-centre cooling.

The proposed fix has three parts: stop broadcast behaviour from leaking active VMACs, enforce VMAC uniqueness atomically during reconnection, and require a short-lived continuity token before a socket can reclaim an existing UUID. The token can ride in an existing BACnet/SC message field, so it does not require a new wire format or new cryptography. ASHRAE's SSPC 135 committee acknowledged the issue, coordinated vendor notification, and began preparing guidance. Until that lands in products, isolation and rebinding telemetry are the practical controls.

The paper is [A Cuckoo in the Nest](https://www.usenix.org/conference/usenixsecurity26/presentation/zhang-qiguang). It is one of the clearest examples I have seen of mutual TLS proving membership without proving identity continuity.

## 5. x402: the payment verifies, the agent gets the product, and the money never arrives

x402 is a payment protocol built around HTTP's long-unused `402 Payment Required` status. A client—often an autonomous agent—requests a paid API or resource. The server returns price and payment requirements. The client signs a payment payload and retries. A facilitator checks the proof and later settles it on a blockchain.

The attraction is obvious: an agent can buy data or compute without opening an account, waiting for an invoice, or handing every merchant a credit card. The dangerous word is "later."

```
client       merchant         facilitator       blockchain
  | payment proof |                |                 |
  |-------------->|  /verify      |                 |
  |                |------------->|                 |
  |                |   valid      |                 |
  |     product    |<-------------|                 |
  |<---------------|  /settle                       |
  |                |------------------------------->|
  |                |        may fail, expire, or do |
  |                |        something too expensive|
```

Verification is a read-only prediction that a payment should succeed. Settlement is the state-changing transaction. If the merchant releases the resource after `verify` but before a successful `settle`, the gap becomes a race condition with money attached.

Researchers evaluated 15 major facilitators used by more than 60,000 sellers and 360,000 buyers, covering 99 percent of the transactions they observed during the measurement window. Every facilitator violated at least one of eight authorization or execution-safety rules. They identified 31 exploitable attack instances across four classes:

- **Free shopping:** reuse one valid proof across concurrent requests before settlement consumes its nonce, or deliberately supply a proof that passes verification but will fail on-chain. The merchant fulfills every request and collects once—or never.

- **Asset theft:** abuse ERC-6492 handling so a facilitator trusts client-supplied deployment metadata and sends attacker-chosen calldata to an attacker-chosen address. The settlement service becomes an arbitrary-call primitive signed and funded by the facilitator.

- **Service denial:** submit proofs that verify but predictably expire, fail, or consume expensive work during settlement, tying up the facilitator and leaving merchants with failed payments.

- **Gas abuse:** steer sponsor-paid settlement into expensive contract-deployment paths rather than the simple transfer the sponsor thought it was funding.

Two free-shopping cases were validated end to end. Ten more facilitators showed the verification-success/settlement-failure pattern that becomes free shopping when the merchant releases work too early. Fourteen of 15 allowed a malicious server to trigger economically meaningless settlements. Three ERC-6492-capable facilitators exposed gas-abuse paths, and one exposed the asset-theft primitive.

The Coinbase Flask SDK at version 0.2.1 and earlier is a useful example of the integration mistake: it continued request handling and returned the protected response immediately after successful verification, without gating that response on settlement. None of the merchant SDKs the researchers evaluated implemented an explicit rollback for business side effects. The study reflects the deployments and versions tested before publication; x402 is moving quickly, and several vendors changed behaviour after disclosure.

If you are building around x402, treat `/verify` like a credit-card preauthorization, not cash in the bank. Reserve the nonce atomically, bind the verification result to one server, resource, amount, and short expiry, then re-check it during settlement. Do not release an irreversible resource until settlement succeeds unless you have an explicit compensation path. Facilitators should allowlist addresses, calldata shapes, signature schemes, gas limits, compute budgets, and transaction effects. "The client signed it" is not a reason for your infrastructure to execute it.

The [USENIX x402 study](https://www.usenix.org/conference/usenixsecurity26/presentation/wang-qinying) contains the measurements and attack validation. The current [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md) now makes the ordering of verification, resource execution, and settlement explicit. Implementations still have to preserve that meaning across SDKs, facilitators, chains, retries, and failure states.

## The pattern underneath all five

Every one of these attacks crosses a boundary the system forgot to bind:

```
WILD             BSSID              != physical location
Opossum          TLS identity       != application conversation
Download More RAM physical address  != physical memory cell
Cuckoo           valid certificate  != UUID / VMAC ownership
x402             verified proof     != settled payment
```

This is why more patching is not a complete answer. You cannot CVE-scan your way out of a crowd-sourced database policy, and a perfectly patched TLS stack still cannot tell which pre-handshake conversation its keys were meant to protect. The vulnerable component is often the seam between two components, each behaving correctly in isolation.

The practical review question is simple: when one layer authenticates a fact, what does the next layer assume that fact means? Write both statements down. If they are not identical, the space between them is where the next obscure attack is already growing.

*Primary research: [WILD Attack](https://www.usenix.org/system/files/usenixsecurity26-zhu-changjia.pdf); [Opossum Attack](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_merget.pdf); [Download More RAM](https://www.usenix.org/system/files/usenixsecurity26-collins.pdf); [A Cuckoo in the Nest](https://www.usenix.org/system/files/usenixsecurity26-zhang-qiguang.pdf); [When HTTP 402 Meets the Blockchain](https://www.usenix.org/system/files/usenixsecurity26-wang-qinying.pdf). All five were presented at the 35th USENIX Security Symposium, August 12–14, 2026.*
