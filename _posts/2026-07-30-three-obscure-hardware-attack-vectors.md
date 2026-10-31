---
layout: post
title: "Three Obscure Hardware Attack Vectors You've Never Heard Of"
date: 2026-07-30
categories: [hardware, exploits, vuln-research]
tags: [hardware-hacking, GhostWrite, RISC-V, T-Head, CVE-2024-44067, TPM, SPI-sniffing, Prime+Abort, CPU-side-channel, Intel-TSX, physical-attack]
excerpt: "GhostWrite, TPM SPI bus sniffing, and Prime+Abort — three wildly different hardware attacks that most defenders never even knew existed."
last_modified_at: 2026-10-31
---

In hardware security, the same old names get all the attention: Rowhammer, Meltdown, Spectre. Buried in obscure processor errata, vendor-issued advisories that barely make the news, and one-off academic papers that slip through the cracks are attacks that are far stranger, more original, and — in their own way — every bit as dangerous. Here are three that I think deserve a second look.

## GhostWrite — When the CPU Writes Where It Shouldn't

Most hardware bugs let an attacker read data they shouldn't have access to. GhostWrite does one better: it writes.

**The setup.** The T-Head C910, a RISC-V CPU used in Alibaba's Xuantie series and various SoCs, has a curious quirk in its vector unit. Certain illegally-encoded vector-store instructions write to physical memory instead of virtual memory — bypassing the Memory Management Unit entirely. The store goes straight to physical memory, ignoring page protections, SMAP/SMEP equivalents, and even the supervisor-mode memory protection.

**Why it's obscure.** GhostWrite was disclosed in August 2024 (CVE-2024-44067) by researchers at the CISPA Helmholtz Center for Information Security and appears in exactly one errata sheet from T-Head. It's a silicon bug, not a microcode patchable one. The affected CPUs are everywhere in Chinese cloud servers and RISC-V development boards, but almost nobody outside of China has even heard the name.

**The punchline.** With a small JavaScript or Python payload, an unprivileged attacker can write arbitrary values to arbitrary physical addresses. That means one-shot kernel root, direct firmware overwrite of SPI flash, or even permanent device bricking. Software can't fix the bug itself; the only mitigation is disabling the vector extension, which Linux 6.14 and later does automatically on affected hardware.

![Four-point diagram summarising GhostWrite, TPM SPI bus sniffing and Prime+Abort, and the advice to add them to hardware threat models.](/assets/figures/three-obscure-hardware-attack-vectors-diagram.svg){: width="640" height="478" loading="lazy"}
*Three obscure hardware attack vectors, as described in this post.*

## TPM SPI Bus Sniffing — The 30-Cent Logic Analyzer Attack

Trusted Platform Modules are meant to provide hardware-grounded attestation and key storage. Their security hinges on the assumption that the communication bus between the CPU and the TPM is trusted. In most laptops, that bus is SPI.

**The setup.** A TPM 2.0 chip (e.g., Infineon SLB9670 or Nuvoton NPCT75x) communicates with the host via SPI — a simple 4-wire synchronous serial bus. By placing a $30 logic analyzer on the SPI clock, MOSI, MISO, and CS lines (tiny test points are often unpopulated, but the vias are exposed on the motherboard), an attacker can capture every command and response in full cleartext. The protocol includes no encryption in hardware. Software-level encryption (like session-based encryption in TPM 2.0) is optional and rarely used in practice.

**Why it's obscure.** TPM bus sniffing has been demonstrated by researchers but never got a CVE — the chips themselves aren't vulnerable, the *system integration* is. OEMs don't route the SPI bus inside a protected layer, and they almost never disable the TPM's built-in debug interface (which dumps keys over JTAG). The attack requires physical access, but an attacker who can open a screwdriver-accessible panel can dump TPM-stored BitLocker keys, FIDO2 credentials, or Platform Configuration Register values used for attestation — all without triggering any intrusion detection.

**The technique.** Clip an 8-pin SOIC test clip onto the TPM's SPI flash chip (same bus shared by the TPM), decode the SPI frames with sigrok or PulseView, filter for the TPM command set (read/write to locality 0 registers), and extract key handles from `TPM2_Unseal` or `TPM2_Load` exchanges. The whole toolchain costs under $50.

**Mitigation.** Use TPM session-based encryption (set `TPM2_PolicySecret` + `TPM2_PolicyAuthorize` with HMAC). Most Linux distributions ship with `tpm2-abrmd` where encryption is off by default. Or better: solder a shield over the test points — but no OEM does.

## Prime+Abort — The Cache Side Channel That Uses Intel TSX as Its Weapon

Intel TSX (Transactional Synchronization Extensions) was designed to improve the performance of multi-threaded locking by allowing optimistic execution of critical sections. It turned out to be so buggy Intel had to disable it in microcode for most consumer CPUs. But before they did, a clever research group weaponized it as the finest-grained cache side-channel ever built.

**The setup.** Prime+Probe relies on measuring access times to detect which cache set the victim is using. Prime+Abort is different: the attacker executes a TSX transaction, primes a cache set, lets the victim run, then tries to complete the transaction. If the victim accessed the same set, the transaction aborts — the abort overhead is huge and unambiguous. The attacker observes only a binary signal (abort or no abort), which carries fine-grained timing information.

**Why it's obscure.** Prime+Abort was published at USENIX Security 2017 ("Prime+Abort: A Timer-Free High-Precision L3 Cache Attack using Intel TSX") and requires TSX hardware. Since Intel microcode patched TSX off on most CPUs in 2020 (CVE-2019-11135, etc.), the attack is largely forgotten — but it still works on any CPU with TSX enabled (older Skylake/Haswell, some Xeons) or on VMs where the microcode update was never applied. It's a near-perfect covert channel with low error rate and no requirement for precise timers.

**The method.** Two cooperating processes (or VMs) on the same physical core agree on a bit encoding: for bit 1, the sender accesses a specific cache set; for bit 0, it stays away. The receiver checks with a TSX transaction. The abort overhead is 1000+ cycles, far above the noise floor. Throughputs of 2 Mbps over shared L3 cache are achievable — enough to exfiltrate an SSH key in under a second.

**Why it matters.** It's a constant-time attack — no high-resolution timers needed, no `rdtsc`, no PMC counters. It works across processes, containers, and VMs if they share a physical core. Mitigation requires disabling TSX end-to-end (already done on most commercial clouds) or partitioning cache sets at the hypervisor level — complicated and performance-killing.

## What These Three Teach Us

Hardware security is full of these weird, specialized attack surfaces that feel like magic tricks in a world that only knows one card game. GhostWrite writes to physical memory because of an errata in a Chinese RISC-V core. TPM sniffing recovers keys from a bus that everyone *assumes* is trusted because the protocol is too fast and too cheap to encrypt. Prime+Abort weaponizes Intel's buggy transaction memory into a covert channel that needs no fine measurement at all.

Each of these is obscure in its own way — but all three are real, weaponizable, and still exploitable on millions of devices today. If you work in hardware security, add them to your threat model. If you don't, enjoy the rabbit hole. This is the stuff that keeps me up at night. — Garrett

## Sources

- [NVD: CVE-2024-44067](https://nvd.nist.gov/vuln/detail/CVE-2024-44067)
- [NVD: CVE-2019-11135](https://nvd.nist.gov/vuln/detail/CVE-2019-11135)
- [oss-security - CVE-2019-19338 Kernel: KVM: export MSR_IA32_TSX_CTRL to guest - incomplete fix for TAA (CVE-2019-11135)](http://www.openwall.com/lists/oss-security/2019/12/10/3)
