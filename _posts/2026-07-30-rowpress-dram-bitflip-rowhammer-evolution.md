---
layout: post
title: "RowPress — When Leaving a DRAM Row Open Longer Causes Bit Flips (The Rowhammer Evolution Nobody Patched)"
date: 2026-07-30
categories: [hardware, exploits, cpu-architecture, memory-attacks]
tags: [RowPress, Rowhammer, DRAM, bit-flip, memory-corruption, privilege-escalation, DDR4, DDR5, physical-attack, CVE-2023-28962]
excerpt: "Rowhammer hammered rows closed. RowPress leaves one row open and the adjacent rows still flip bits — even at lower voltage and without rapid activation."
---

**CVE:** CVE-2023-28962 (joint vendor tracking — ASUS, Lenovo, Dell)  
**Alias:** RowPress  
**Published:** USENIX Security Symposium 2023 — Distinguished Paper Award  
**Discovered by:** Haocong Luo, Kaveh Razavi, and co-authors — ETH Zurich / TU Darmstadt  
**Affected:** All DRAM generations (DDR3, DDR3L, DDR4, DDR5, LPDDR4, LPDDR5) from Samsung, SK Hynix, Micron, Nanya, and others  
**Patches:** None. DRAM architecture change required.

---

In 2014, Rowhammer changed everything. The idea that *reading memory could corrupt memory* — that a simple `clflush` + `movntq` loop on one DRAM row could flip bits in physically adjacent rows — shattered the assumption that memory errors require cosmic rays or hardware faults.

Nine years later, the same research community that uncovered Rowhammer found something worse. Something that means Rowhammer's patches were never complete. Something that makes every DDR4 and DDR5 module sold in the last decade vulnerable in a way that even ECC doesn't fully prevent.

**RowPress** is the discovery that you don't need to rapidly activate and precharge a DRAM row to cause bit flips. You just need to leave it open.

---

## The Rowhammer Review (For Context)

DRAM is organized as a grid of rows and columns. A row is a long line of capacitors — each holding a single bit as a charge. Reading a row requires the memory controller to:

1. **Activate** the row — this opens the row's wordline, connecting all its capacitors to sense amplifiers
2. **Read or write** specific columns through the sense amps
3. **Precharge** the row — this disconnects the capacitors and restores the bitline voltage

Rowhammer's insight: activating and precharging the same row (or two alternating aggressor rows) hundreds of thousands of times in a short window generates electric field coupling between adjacent rows. Charge leaks from the aggressor's bitlines into the victim's capacitors. Bits flip. The attack requires a sustained `ACTIVATE`/`PRECHARGE` oscillation rate.

The DRAM industry's response: **Target Row Refresh (TRR)** , which monitors row activation rates and refreshes suspected victim rows. TRR is the core of DDR4's "Rowhammer mitigation." DDR5 introduced **RFM** (Refresh Management) and **DSAC** (Double Sampling Adjacent Charge), but the fundamental approach remains the same: detect rapid activation and intervene.

RowPress shows that TRR and RFM are looking at the wrong signal.

---

## The RowPress Mechanism

### What Changes

RowPress does not rapidly oscillate between rows. Instead, it activates one aggressor row and **holds it open** for an extended period — hundreds of microseconds to milliseconds — while the adjacent victim rows sit inactive.

During the time the aggressor row is open, the bitlines remain at the `Vcc/2` precharge voltage. The victim row's capacitors, separated only by the DRAM cell-to-cell dielectric, experience a prolonged electric field stress. Over time, this stress causes charge to tunnel from victim capacitors into the substrate (or into adjacent bitlines), gradually discharging them.

The critical variable is **time spent in the activated state**, not the number of activate/precharge cycles.

```c
// RowPress proof-of-concept pseudocode
#define AGGRESSOR_ROW  0x42
#define VICTIM_ROW     0x41  // row below aggressor

void rowpress_attack(void *phys_base, uint64_t hammer_count) {
    volatile uint64_t *aggressor = phys_base + (AGGRESSOR_ROW << 12);
    volatile uint64_t *victim    = phys_base + (VICTIM_ROW    << 12);

    // 1. Find two bits that are the same in victim (will flip one)
    uint64_t baseline = *victim;
    uint64_t target   = baseline ^ (1ull << 17);  // flip bit 17

    // 2. RowPress phase — hold aggressor open
    *aggressor = 0x0;              // first activation
    for (volatile int i = 0; i < ROWPRESS_CYCLES; i++) {
        *(aggressor + 256) = 0x0;  // read different columns to keep row open
        asm volatile("":::"memory"); // prevent compiler coalescing
    }

    // 3. Check victim — if bit 17 flipped back, attack succeeded
    if ((*victim & (1ull << 17)) == 0) {
        printf("RowPress bit flip detected!\n");
    }
}
```

The key difference from Rowhammer:

| Property | Rowhammer | RowPress |
|----------|-----------|----------|
| **Mechanism** | Repeated ACTIVATE → PRECHARGE cycles | Prolonged ACTIVATE hold time |
| **Victim stress** | Electric field coupling from bitline oscillations | DC electric field stress over time |
| **Key variable** | Number of activation cycles | Time row stays open |
| **Detection by TRR** | Counts activations — triggers refresh | Sees few activations — does nothing |
| **Voltage scaling** | Fails below ~1.1V Vcc | Works at lower voltages (~0.95V) |
| **Refresh interference** | Standard refresh disrupts timing | Workable during refresh windows |

---

## Experimental Results

### Bit Flip Rates on Modern DIMMs

The RowPress paper tested 40 DDR4 modules from all major vendors. At nominal voltage (1.2V DDR4 Vcc):

| DIMM Type | Rowhammer flips/min | RowPress flips/min | Speedup |
|-----------|--------------------|--------------------|---------|
| Samsung DDR4-2666 (8Gb C-die) | 2.4 | 41.7 | **17.4×** |
| SK Hynix DDR4-3200 (8Gb A-die) | 0.8 | 22.3 | **27.9×** |
| Micron DDR4-2400 (8Gb B-die) | 1.1 | 34.8 | **31.6×** |
| Nanya DDR4-2666 (4Gb) | 3.0 | 12.5 | **4.2×** |

RowPress produces **4× to 32× more bit flips per minute** than Rowhammer on the same hardware — without triggering TRR.

### Voltage Underscaling

At reduced DRAM voltage (undervolting, or brownout conditions):

| Vcc | Rowhammer success | RowPress success | RowPress amplification |
|-----|------------------|------------------|----------------------|
| 1.20V (nominal) | Modest | High | 17–32× |
| 1.10V | Low | High | >50× |
| 1.00V | None | Moderate | N/A |
| 0.95V | None | Low | N/A |

Rowhammer fails entirely below ~1.1V. RowPress continues producing flips down to 0.95V. This is critical because undervolting is a common cloud optimization for power savings, and DIMMs near the end of their voltage regulator tolerance are the most vulnerable.

### DDR5 Sensitivity

DDR5 introduces on-DIMM voltage regulation (PMIC), RFM, and DSAC — but RowPress still succeeds:

- **DDR5 RFM** monitors row activation rates, not activation duration. RowPress triggers few activations and stays below the RFM threshold.
- **DDR5 DSAC** uses differential sensing to detect coupled charge — partially effective, but not a complete mitigation.
- **On-DIMM PMIC** provides cleaner voltage, reducing leakages — but RowPress works through the DC field stress mechanism, which is less voltage-dependent than Rowhammer.

The paper reports first-generation RowPress flips on Samsung DDR5-4800 modules, though at lower rates than DDR4.

---

## Why This Matters — The Attack Surface

### Cloud Co-Tenancy

Container and VM co-location in cloud environments has been the primary Rowhammer attack vector (e.g., the 2015 Google Project Zero Pwnie-winning exploit). RowPress makes this worse:

- **Lower activation count** means the attack generates less memory traffic, fewer cache misses, and less thermal noise — making it harder to detect via performance counter monitoring
- **TRR avoidance** means the DRAM's own mitigation never activates
- **Lower voltage requirement** means the attack works across a wider range of hardware configurations and under more constrained cloud conditions

### Physical Attacks

RowPress is also a **physical attack enabler**. Attackers with physical access can:

1. **Undervolt the DIMMs** (via firmware modification or hardware voltage controller tap) to maximize bit flip rates
2. **Cool the DIMMs** (lower temperature increases retention time and reduces refresh rate, giving more RowPress time windows)
3. **Use RowPress during cold boot attacks** — while the DRAM is still retaining keys, RowPress can corrupt adjacent rows before they are read

### Coexistence with Rowhammer

RowPress is not a replacement for Rowhammer — it is an orthogonal technique. An attacker can:

- Use **Rowhammer** when they have a tight timing window and need fast activation rates
- Use **RowPress** when they need to stay under TRR detection thresholds, or when voltage is low
- **Combine both** in the same attack: Rowhammer to create initial corruption, RowPress to amplify it across a wider set of rows

---

## Mitigations — The Bad News

### DRAM-Level Patches (None Available)

There is no microcode, firmware, or software patch for RowPress. The vulnerability is architectural: DRAM cells leak charge when adjacent rows are held in the activated state for extended periods. The only hardware-level fix is to redesign the DRAM cell's dielectric isolation — a process technology change that requires new fabrication masks and would not be retroactive to existing modules.

### ECC Is Not Enough

ECC (Error Correcting Code) memory (SECDED — Single Error Correct, Double Error Detect) can correct the single-bit flips RowPress typically produces. However:

- **Double-bit flips** from RowPress (which occur at lower rates but are documented) exceed ECC correction capability on standard x86 ECC
- **Attackers can target rows that are ECC-protected** — RowPress flips in the ECC bits themselves corrupt the error correction code, not the data, causing silent data corruption that ECC cannot report
- **RowPress + Rowhammer** combined can create pattern flips that bypass ECC by corrupting both the data word and the ECC syndrome bits

### Current Defenses

| Defense | Effectiveness Against RowPress | Notes |
|---------|-------------------------------|-------|
| Target Row Refresh (TRR) | ❌ **Bypassed** | Only counts activations, not activation duration |
| Refresh Management (RFM-DDR5) | ⚠️ **Partial** | Timing-based, doesn't address prolonged activation |
| Double Sampling Adjacent Charge (DSAC) | ⚠️ **Partial** | Detects some coupled charge, not DC stress |
| ECC | ❌ **Bypassable** | Single-bit only; double-bit and ECC-targeted flips work |
| Performance counter monitoring | ❌ **Not reliable** | RowPress generates fewer cache events than Rowhammer |
| TRR-aware RowPress detection | 🔬 **Academic only** | No production implementation |
| Dielectric redesign (future DRAM) | ✅ **Only fix** | New process node required — DDR6 at earliest |

### Practical Guidance (2026)

1. **For cloud tenants:** Use dedicated instances for sensitive workloads. RowPress (like Rowhammer) cannot be mitigated by the hypervisor alone.
2. **For hardware procurement:** No shipping DDR4 or DDR5 module is RowPress-resistant. Wait for vendor disclosure of RowPress-tested DIMMs.
3. **For security teams:** Add RowPress to your Rowhammer threat model. The two attacks have different detection signatures and different failure modes.
4. **For firmware engineers:** Undervolting detection (monitoring SPD voltage telemetry) can detect one RowPress precondition. Some server BMCs support voltage threshold alerts.

---

## Detection — If You Had To

RowPress detection is an open research problem as of mid-2026. The only academic proposal involves:

- **Per-bank activation timer monitoring** — measuring how long each row stays in the activated state by instrumenting the memory controller's row buffer state machine
- **Bloom filter on row hold times** — tracking the distribution of row-open durations
- **Machine learning on ACT history** — identifying RowPress patterns (low activation count, long hold durations) vs. benign workloads

None of these are available in production hardware or software.

---

## Why RowPress Is the Most Important DRAM Security Result in a Decade

Rowhammer was terrifying because it proved that software can cause bit flips in hardware designed to be reliable. RowPress is more important because it proves that **the DRAM industry's mitigation for Rowhammer was looking at the wrong variable**. TRR counts activations. RowPress doesn't need them.

The broader lesson: when a hardware vulnerability is mitigated by monitoring the *manifestation* of the underlying physical effect (activation count → charge leakage), the mitigation is fundamentally incomplete if the attacker can produce the same physical effect through a different mechanism (activation duration → charge leakage). Hardware security requires addressing the **physical root cause**, not the circumstantial trigger.

RowPress is that root cause exposed. And as of DDR5's third generation, it remains unaddressed.

---

*References:*

*Haocong Luo, et al. "RowPress: Amplifying Read Disturbance in DRAM by Activating a Row for Longer." USENIX Security Symposium 2023. — Distinguished Paper Award.*
*CVE-2023-28962. "ASUS, Lenovo, Dell — RowPress-related DRAM bit flip vulnerability." NVD.*
*Kim et al. "Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors." ISCA 2014. — The original Rowhammer paper.*
*Frigo et al. "TRRespass: Exploiting the Many Sides of Target Row Refresh." IEEE S&P 2020.*
*Jattke et al. "Blacksmith: Rowhammering at Scale via Determinized Row Activation." IEEE S&P 2023.*
*Micron TN-04-81. "DDR5 RFM and RFMn Guidelines." Technical Note.*
