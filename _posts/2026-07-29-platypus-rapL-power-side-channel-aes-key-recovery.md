---
layout: post
title: "Platypus — Recovering AES Keys by Reading a Linux File (The RAPL Power Side Channel Nobody Knows About)"
date: 2026-07-29
categories: [hardware, side-channel, exploits, cpu-architecture]
tags: [RAPL, platypus, power-side-channel, AES, key-recovery, CVE-2020-8694, intel-architecture, MSR, speculative-execution-alternative, cpu-security]
excerpt: "Reading a Linux thermal sysfs file recovers AES keys from the same CPU — no exploit, no kernel compromise, no timing side channel."
---

**CVE:** CVE-2020-8694 / CVE-2020-8695  
**CVSS:** 5.6 (Medium) — despite the extraordinary implications, the attack requires local non-root code execution, so it didn't qualify for a higher base score  
**Alias:** Platypus  
**Published:** IEEE Symposium on Security & Privacy 2021 / ASHES 2021  
**Discovered by:** Moritz Lipp, Andreas Kogler, David Oswald, Michael Schwarz, Catherine Easdon, Claudio Canella, Daniel Gruss — Graz University of Technology / University of Birmingham  
**First disclosure:** Intel security advisory INTEL-SA-00389, August 2020  
**Affected:** All Intel Core processors (Sandy Bridge through Alder Lake, 2011–2022+), Intel Xeon (all generations supporting RAPL)  

---

Here is the most unintuitive security finding I have ever encountered. If I told you that reading a file from `/sys/class/powercap/` can recover AES encryption keys, you would probably assume I'm describing a kernel exploit chain — privilege escalation, some memory corruption, maybe a page-cache timing trick.

No. In this attack, you literally `cat` a file. The operating system hands you the data. No segfault. No TOCTOU. No overwrite. No speculative execution. And from that single, legitimate read, you extract the victim's AES key with >99% accuracy.

This is the RAPL power side channel, better known by its paper name: **Platypus**.

---

## What Is RAPL and Why Does It Exist?

Intel's **Running Average Power Limit (RAPL)** is a power management interface introduced with Sandy Bridge in 2011. It was designed to solve a practical engineering problem: modern CPUs can't be allowed to draw arbitrary amounts of power, because the thermal design power (TDP) of the package, the voltage regulator, and the cooling solution all have hard limits. RAPL provides the operating system and firmware with the ability to:

1. **Measure** energy consumption in near-real-time, via model-specific registers (MSRs)
2. **Enforce** power caps by throttling the CPU when it exceeds a configured limit

The measurement part is what concerns us. On every Intel Core since 2011, the following MSRs exist and are readable from user space via the Linux `intel-rapl` driver:

| Register | Address | Domain | Granularity |
|----------|---------|--------|-------------|
| `MSR_PKG_ENERGY_STATUS` | 0x611 | Entire package | ~15-30 µJ per LSB |
| `MSR_PP0_ENERGY_STATUS` | 0x613 | Cores only | ~15-30 µJ per LSB |
| `MSR_PP1_ENERGY_STATUS` | 0x614 | Uncore (GPU) | ~15-30 µJ per LSB |
| `MSR_DRAM_ENERGY_STATUS` | 0x619 | DRAM controller | ~15-30 µJ per LSB |

On Linux, these are exposed through the power capping framework. Any process (including unprivileged ones, on unpatched systems) can read:

```
/sys/class/powercap/intel-rapl:intel-rapl:0/energy_uj
```

This file returns a monotonically increasing 32-bit counter representing the total energy consumed by the CPU package since boot, in microjoules. The counter updates at a hardware-determined rate — typically **once per millisecond** on older CPUs, and **every ~100 microseconds** on newer microarchitectures.

---

## The Mechanism: Why Power Consumption Leaks Secrets

The central insight behind every power side channel is that **different CPU instructions consume measurably different amounts of power**, and those differences correlate with the data being processed.

At the transistor level, this is obvious: a CMOS gate only draws significant current when it switches. The energy consumed in a clock cycle is proportional to the number of transistors that toggle their output. In a digital circuit processing cryptography, the number of toggling gates depends on:

- **The Hamming weight** of the operands (how many bits are 1 vs. 0)
- **The Hamming distance** between consecutive values (how many bits change between cycles)
- **The specific micro-operation** being executed (a multiply consumes more than an add)

AES implementations — even hardware-accelerated AES-NI — have a power profile that varies with the round key and the plaintext. The RAPL counter captures this variation at microsecond resolution.

### The Attack in Three Steps

**Step 1: Contend for the same physical core**

The attacker and the victim must execute on the same physical CPU core. This can happen by design (the attacker is a co-located container or VM) or by manipulating the scheduler (affinity pinning, cgroups, CPU hotplug).

**Step 2: Victim performs AES encryption**

The victim runs AES-NI encryption (or a software AES implementation). Each AES round has a specific power signature determined by the round key. The attacker doesn't interfere — they just wait.

**Step 3: Attacker reads RAPL energy counter at the right moment**

Immediately after the victim's encryption completes, the attacker reads the RAPL counter. The delta between two consecutive reads gives the energy consumed during the victim's operation. A single trace is noisy, but averaging over hundreds or thousands of encryptions with the same key produces a clean power trace.

```
# Basic RAPL read — no privileges needed on an unpatched system
cat /sys/class/powercap/intra-rapl\:0/energy_uj
```

The attacker synchronizes with the victim using CPU timing (RDTSC), interrupts, or performance counters. The RAPL counter is then polled at precise intervals around the expected encryption window.

---

## What the Researchers Actually Recovered

### AES-128 Key Recovery

The Platypus paper demonstrated **full AES-128 key recovery** from an unprivileged Linux process against a victim using OpenSSL's AES-NI implementation. The attack:

1. Records ~10,000 power traces of AES-128 encryption with a fixed key
2. Aligns traces to the AES round boundaries using the known structure of AES (10 rounds, each consuming ~1 microsecond with AES-NI)
3. For each byte position, computes the correlation between the Hamming weight of the hypothesized round key byte and the measured power
4. The correct key byte produces the highest correlation — this is a simple **Correlation Power Analysis (CPA)** , identical to the technique used in hardware side-channel labs, but running purely in software

Results: **99.3% accuracy with 10,000 traces.** The attack completes in under 5 minutes on a modern Core i7.

### RSA Key Bit Recovery

For RSA, the attack exploits the difference in power consumption between modular squaring and modular multiplication in the binary exponentiation algorithm. The sequence of squaring vs. squaring+multiplication operations reveals each bit of the private exponent:

- If the bit is 0: one squaring (lower power)
- If the bit is 1: one squaring + one multiplication (higher power)

A single timing trace (one RSA decryption) is sufficient to recover significant portions of the key with >80% accuracy. With 10 traces, accuracy exceeds 95%.

### EdDSA Nonce Recovery

EdDSA signatures are fatal if the nonce is ever recovered — signing key reconstruction is then trivial. The Platypus attack demonstrated nonce recovery from Ed25519 operations on a co-located process by observing power consumption during the scalar multiplication.

---

## Why This Is Worse Than It Sounds

### No Speculative Execution Required

This is not Spectre. Not Meltdown. No transient instructions. No cache probing. The attacker reads a legitimate OS interface and uses statistical analysis on the data. The only "exploit" is Intel's engineering decision to expose microsecond-resolution energy counters to unprivileged software.

### Cross-Container and Cross-VM

Because RAPL is a machine-level counter (not a per-process counter), any process on the same physical CPU can observe the energy consumption of any other process, including processes in different containers, different KVM/QEMU VMs (if they share a pCPU), or different user accounts.

Container isolation provides zero defense. The `energy_uj` file is exposed through the host's sysfs, and unless explicitly masked by the container runtime, the containerized process can read it.

### The Countermeasures Are Incomplete

Intel's mitigation (microcode update + Linux kernel patch, August 2020) took the following approach:

1. **Restrict MSR access to root only** — prevents direct `rdmsr` attacks
2. **Restrict sysfs access to root only** — prevents `cat /sys/class/powercap/.../energy_uj` from unprivileged processes

These mitigations have two gaping holes:

- **The sysfs restriction is a file permission change, not a hardware fix.** Any process that is root (or has `CAP_SYS_ADMIN`) can still read RAPL counters. This includes containers running as root, init processes, system daemons, and any exploited process that escalates to root.
- **KVM guests can read RAPL if the MSR is not filtered.** While KVM typically masks these MSRs, not all hypervisors do, and the QEMU command-line flag `-cpu host` exposes host MSRs to the guest.
- **AMD CPUs have similar interfaces** (AMD's equivalent is the `MSR_PWR_UNIT` / `MSR_PKG_ENERGY_STAT` in the Family 17h/19h BKDG) — though the Linux driver for AMD doesn't expose them by default.

---

## Why Nobody Knows About This

The Platypus attack was disclosed in August 2020 alongside the usual Intel coordinated disclosure process. It received:

- A modest MITRE score (CVSS 5.6 — "Medium")
- A single Intel security advisory
- A few news articles on Tom's Hardware and BleepingComputer
- Then complete silence

The security community — myself included until I dug into this — largely categorized it as "interesting but impractical" because it requires co-location on the same physical core. But **co-location is the default** in cloud computing. AWS EC2, Google Cloud, and Azure all schedule multiple VMs (or containers) on the same physical core depending on the instance type. Any attacker who can land code on the same hyperthread as a victim in a public cloud (using topology-aware placement) can perform this attack.

The attack also works within a single machine: malicious browser extensions, sideloaded libraries, and background processes can all read RAPL counters if the system is unpatched.

---

## Detection and Forensics

Unlike Rowhammer or speculative execution attacks, RAPL-based attacks leave no specific forensic trace:

- **No cache eviction patterns** — the attacker isn't probing the cache
- **No page table manipulation** — standard `cat` via the VFS
- **No unusual system calls** — `open()`, `read()`, `close()` on a regular sysfs file
- **No timing measurements** — RAPL is the measurement, not RDTSC

Detection requires monitoring of RAPL sysfs access, which is not a standard audit event in any major EDR product as of 2026. The only way to detect a Platypus-style attack in progress is:

1. **Audit `energy_uj` file access** — SELinux or AppArmor policy that triggers on reads to `/sys/class/powercap/intel-rapl:*/energy_uj`
2. **Unusual context-switch patterns** — the attacker and victim must execute on the same physical core, which can be detected via `perf` context-switch event monitoring
3. **Power consumption analysis** — detecting repeated correlation computations is impractical

---

## Broader Implications: The RAPL Pattern

The Platypus attack is not an isolated bug. It represents a class of vulnerability that is likely to become more common as CPU manufacturers expose more telemetry:

| Interface | Data Leaked | Hardware | Status |
|-----------|-------------|----------|--------|
| RAPL (`MSR_PKG_ENERGY_STATUS`) | Power consumption | Intel Core (2011+) | Partial fix |
| AMDs SMU (System Management Unit) telemetry | Power, temperature, frequency | AMD Zen (2017+) | Not fully audited |
| ARM's DSU (DynamIQ Shared Unit) counters | Power, performance | ARM big.LITTLE (2018+) | Largely unexamined |
| Performance Monitoring Counters (PMC) | Instruction-level activity | All modern CPUs | Root-only by default |
| Intel's PECI (Platform Environment Control Interface) | Thermal, power, current | Intel server platforms (via BMC) | Physical access only |
| Apple's SMC (System Management Controller) | Thermal, power, sensors | Apple Silicon (2020+) | Accessible to root on macOS; security research ongoing |

Each of these interfaces was designed for legitimate power management, thermal monitoring, and performance optimization. Each becomes a side channel when exposed to untrusted code. The pattern is: **any hardware telemetry interface with microsecond resolution that an attacker can read is a side channel.**

---

## Mitigations

### Software (Immediate)
- **Kernel 5.10+** restricts RAPL sysfs access to root by default
- **Container security contexts** should set `read_only_paths: ["/sys/class/powercap"]`
- **Seccomp filters** can block `pread64` on RAPL file descriptors
- **SELinux/AppArmor** policies should audit reads to `energy_uj`
- **Cloud hypervisors** must mask `MSR_PKG_ENERGY_STATUS`, `MSR_PP0_ENERGY_STATUS`, and `MSR_DRAM_ENERGY_STATUS` from guests

### Hardware (Not Available)
- No hardware mitigation exists for the RAPL side channel. The power consumption is a physical property of the CPU that cannot be masked without also disabling RAPL entirely.
- Future architectures could introduce noise injection into RAPL counters, or make the counter resolution coarser at the hardware level when read from non-privileged contexts.
- Intel has not announced any such changes as of mid-2026.

### Operational
- **Cloud tenants:** Use dedicated instances (no shared pCPU) for cryptographic operations
- **Hosting providers:** Ensure RAPL MSRs are filtered in KVM/QEMU configurations
- **Security teams:** Audit systems for unpatched `intel-rapl` drivers; verify MSR filtering in virtualization stacks

---

## Why This Attack Matters in 2026

Six years after disclosure, the Platypus attack remains relevant for one simple reason: **the hardware cannot be fixed**. The RAPL interface is baked into the CPU's microcontroller and power management unit. No microcode update can eliminate the energy counter resolution. No new CPU generation removes the feature (RAPL is required for operating system power management). The only mitigations are software access controls that have been bypassed repeatedly in container escape chains.

The attack embodies a broader lesson: **physical side channels don't need physical access anymore.** If the hardware exposes a measurement of its physical state to software, and that measurement has sufficient resolution, the side channel is available to any code on the system. We saw this with speculative execution (Spectre/Meltdown — the CPU's microarchitecture state leaked through timing). We're now seeing it with power, and we will see it with temperature, voltage, EM emissions, and acoustic resonance as these sensors become software-accessible.

The Platypus attack is not the last power side channel. It is the first of a generation.

---

*References:*

*Moritz Lipp, Andreas Kogler, David Oswald, Michael Schwarz, Catherine Easdon, Claudio Canella, Daniel Gruss. "PLATYPUS: Software-based Power Side-Channel Attacks on x86." IEEE S&P 2021.*
*Intel Security Advisory INTEL-SA-00389. "Intel® RAPL Interface Advisory." August 2020.*
*CVE-2020-8694, CVE-2020-8695. National Vulnerability Database.*
*Screaming Channels (CHES 2019) — related work on wireless SoC power side channels.*
*Hertzbleed (USENIX Security 2022) — related work on frequency-scaling side channels.*
