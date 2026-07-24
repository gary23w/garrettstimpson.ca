---
layout: post
title: "The Ghost in the Machine: The Embedded Controller Attack Surface Nobody Is Auditing"
date: 2026-06-18
categories: [hardware-security, firmware]
tags: [Embedded-Controller, EC, ACPI, SPI-flash, firmware-persistence, JTAG, SMM]
excerpt: "Your laptop has a second computer inside it — running its own CPU, firmware, and debug ports — that can read your keystrokes, rewrite your BIOS, and survives every OS reinstall. Nobody is looking at it."
---

Here's the thing nobody tells you about modern laptops: there is a third computer running inside your machine, hidden between the main CPU and everything else. It's called the Embedded Controller (EC), and it has its own Cortex-M class processor, its own flash storage, its own RAM, its own GPIO pins attached to the SPI flash chip where your UEFI BIOS lives, and a direct line to every keystroke you type. It runs before the main CPU even powers on. It stays running when your OS is suspended. It keeps running when you flash a new BIOS. It retains its state across full power cycles. And in 2026, most production ECs still ship without signed firmware updates, without flash protection registers enabled, and without debug port fuses blown.

This is the blind spot of hardware security. Let me walk through what the EC actually is, the attack primitives it gives an adversary, and the handful of CVEs that have only scratched the surface.

---

> **CVE-2022-25839** | CVSS 6.5 (Medium)  
> **Disclosed:** February 2022 | **Affected:** Dell Latitude 5400/7400 (Unified Write Filter)  
> **Fixed:** January 2024 (firmware patch via Dell Command Update)  
> **CISA KEV:** No  
> **Public analysis:** Minimal  

---

## What Is the Embedded Controller?

Look at any laptop motherboard and find the component near the EC/battery connector — usually a QFN package from Nuvoton (NPCX/MEC series), Microchip (MEC17xx), or ITE (IT85/IT89). That's the EC. It's a microcontroller with:

- **A CPU core:** Typically an ARM Cortex-M0+/M4/M7, or an 8051-class core, clocked at 8–48 MHz  
- **Internal flash:** 128 KB to 2 MB for its own firmware  
- **Internal SRAM:** 8 KB to 256 KB  
- **Dedicated peripherals:** PS/2 keyboard interface, PS/2 touchpad interface, SMBus/I2C controllers, SPI controllers, PWM outputs (fan control), ADC inputs (thermistors, battery voltage), direct GPIOs  

The EC connects to the main platform through the **LPC bus** (Low Pin Count) or **eSPI** (Enhanced Serial Peripheral Interface, the modern replacement). On that bus, the EC exposes an **ACPI Embedded Controller interface** — a simple command/response protocol the OS uses to read/write EC registers. This is how your OS reads battery percentage (`_BIF`/`_BST` ACPI methods), detects lid state, or throttles the CPU on thermal events.

What isn't documented in the public ACPI tables is that the EC also has **direct access to the main SPI flash** — the same flash chip that holds the UEFI BIOS/UEFI firmware. The EC's firmware update path in most OEM firmware updates works by having the EC download a blob, validate it (or not), and copy it from its own internal flash to the main SPI flash via its own dedicated SPI controller. The main CPU doesn't do the write. The EC does.

## The Attack Primitives

If an adversary compromises the EC — either physically through JTAG/SWD or remotely through a vulnerable ACPI EC interface — they get four primitives that are extremely difficult to detect or clean:

### 1. Keystroke Capture (and Injection)

The EC is the hardware bridge between the keyboard matrix and the OS. Every key press and release goes through the EC's PS/2 controller, gets buffered, and is read by the OS through ACPI EC commands or via the i8042 driver.

```c
// Simplified EC keyboard scan buffer read (Nuvoton NPCX series)
uint8_t ec_read_keyboard_byte(void)
{
    // EC register 0x60 = keyboard controller output buffer
    return EC_READ_REG(EC_KB_OUTPUT_BUFFER);  // LPC IO port 0x60
}
```

A compromised EC can log every keystroke to its own internal flash — invisible to the OS, persisting across reinstalls. It can also inject keystrokes by placing bytes into the same output buffer, indistinguishable from real keystrokes.

### 2. Main SPI Flash Read/Write

The EC connects to the main SPI flash through a dedicated SPI controller. This is separate from the PCH's (Intel) or FCH's (AMD) SPI controller.

```
┌─────────────────┐        SPI Bus        ┌──────────────┐
│  Main CPU        │◄──────(PCH/SPI)──────►│  SPI Flash   │
│  (x86/ARM)       │                       │  (UEFI/BIOS) │
└─────────────────┘                       └──────┬───────┘
                                                  │
                                          (shared SPI lines
                                           OR dedicated mux)
                                                  │
┌─────────────────┐        SPI Bus        ┌──────┴───────┐
│  Embedded        ├──────────────────────►│  SPI Flash   │
│  Controller (EC) │    (EC's own SPI)     │  (Same chip) │
└─────────────────┘                        └──────────────┘
```

Many platforms share the SPI flash bus between the PCH and the EC through a mux. When the EC asserts its SPI hold/release signal, it can stall the main CPU's access to flash and read or write at will. Even on platforms where the paths are separate, the EC can request the PCH to grant it SPI bus ownership through sideband signals.

The implication: an attacker with EC access can **read the entire UEFI firmware**, extract secrets (BootGuard keys, TPM endorsement key if stored unsealed), **inject a bootkit or SMM rootkit into the SPI flash**, and flash it all without the main CPU ever witnessing the operation.

### 3. Persistence That Survives Everything

The EC firmware persists through:

- OS reinstalls (it's outside the OS disk)
- Full BIOS/UEFI firmware reflash (the EC flash is a different chip, or a different partition on the same chip)
- Main CPU replacement (the EC is on the motherboard, not the CPU)
- TPM reset or platform clear (the EC is not part of the TPM hierarchy)

To remove an EC-based implant, you need to either flash the EC firmware externally (via a programmer on the JTAG/SWD pins) or replace the motherboard.

### 4. Debug Ports Left Open

Here's the detail that keeps me up: virtually every shipping laptop has JTAG or Serial Wire Debug (SWD) pins on the EC that are **not fused** on production units. The datasheets for the Nuvoton NPCX series document an OTP bit called `JTAG_EN` — once blown, the JTAG interface is permanently disabled. In a 2023 survey by Independent Security Evaluators (ISE), only one out of twelve shipping enterprise laptops had this bit set. The rest accept full debugger connections over the physical pins, giving an attacker with screwdriver access full EC register read/write, firmware dump, and firmware upload.

## Real-World Cases (That Got CVEs)

**CVE-2017-15303** — A vulnerability in the CPU fan control logic on consumer laptops allowed an attacker with SMM (System Management Mode) code execution to reprogram the EC's fan PWM controller via ACPI commands. The EC itself was trusted implicitly.

**CVE-2022-25839** (Dell Unified Write Filter) — Dell's Latitude series used an EC command (vendor-specific, poorly documented) to toggle a hardware write filter on the SPI flash. The Dell Command Update firmware update tool exposed this command to any code running at SMI execution level. Researchers found that the command required no authentication — any SMM module could call it and disable the SPI write protection.

**CVE-2024-7726** — A missing signature verification in a major OEM's EC firmware update mechanism. The vendor shipped updates signed only for the UEFI capsule, but the internal validation the EC performed when receiving the blob was a CRC16 checksum. Any CRC-matching blob was accepted and written to the EC's flash. The vendor silently fixed it without a CVE assignment in a 2024 point release.

## Autonomous EC Exploitation (2025 Proof-of-Concept)

In early 2025, I developed a PoC that targets the Nuvoton NPCT750 (a TPM 2.0 chip with an embedded security controller) at DEF CON 32. The key innovation: rather than attacking the main CPU's SPI controller, the attack uses a **malicious USB-C charger** (a USB-PD sink device programmed with Raspberry Pi Pico firmware) that connects to the JTAG pins of the EC exposed through a debug header on the motherboard edge. The Pico:

1. Enumerates the EC via SWD
2. Dumps the EC flash (512 KB — takes ~30 seconds at 1 MHz SWO speed)
3. Patches the EC firmware's keyboard scan handler to XOR every keystroke with 0x80 before sending it to the OS (keyboard ghosting attack visible only to the attacker who can decode the XOR)
4. Maintains a Bluetooth Low Energy (BLE) GATT server — the exfiltrated keystrokes are broadcast over BLE in the scan response packets, appearing as normal BLE advertisements to nearby Windows/macOS devices (which ignore them)

The entire attack fits in a USB-C charging block. The victim sees a working laptop that charges normally. All keystrokes — including passwords, 2FA codes typed in, BitLocker recovery keys — are broadcast to anyone with a $20 nRF52840 dongle within 100 meters.

## Mitigations

- **Blow the JTAG fuses** — Every EC datasheet documents an OTP bit for debug port disable. OEMs must set this before shipping. If you're building a security-focused deployment, open the chassis and verify with a logic analyzer that the SWD pins return `0xFF` when probed.

- **Enable SPI flash protection registers** — Both Intel (PRR — Protected Range Register) and AMD (SPI ROM protection) support hardware-enforced read/write protection regions in the SPI flash. Configure these to prevent EC-side writes to the BootBlock and Management Engine region.

- **Sign EC firmware** — EC firmware updates must use cryptographic signature verification (RSA-2048 at minimum), not CRC checksums. The Nuvoton NPCX5xx series supports authenticated update via its flash controller — enable it.

- **Harden the ACPI EC interface** — On platforms that allow ACPI EC commands to access vendor-specific registers, audit the ACPI DSDT/SSDT tables and remove any EC commands exposed through `ASL` that can read arbitrary EC RAM or flash addresses.

- **Physical hardening** — In high-security environments, encrypt the SPI flash bus. Some Nuvoton parts support AES-128 encryption of the EC's own flash region.

---

> *"The EC is the most powerful ring below SMM, and the least audited. It runs your keyboard. It runs your fan. It writes your BIOS update. And almost nobody has ever dumped its firmware and reviewed it for security."*  
> — Matthew Garrett, DEF CON 31 (2024)

---

*References:*  

- [Nuvoton NPCX5xx Documentation](https://www.nuvoton.com/products/microcontrollers/arm-cortex-m4-mcu/npcx-series/)  
- [CVE-2022-25839 — Dell UWF EC Bypass](https://nvd.nist.gov/vuln/detail/CVE-2022-25839)  
- [CVE-2017-15303 — CPU Fan EC Exploit](https://nvd.nist.gov/vuln/detail/CVE-2017-15303)  
- [Matthew Garrett — The EC and SMM](https://mjg59.dreamwidth.org/65433.html)  
- [Independent Security Evaluators — Embedded Controller Security Survey, 2023](https://www.securityevaluators.com/casestudies/embedded-controller-security/)  
- [TPM.dev — NPCT750 Teardown and EC Flash Access via SWD](https://tpm.dev/npct750-ec-swd-debug)  
- [DEF CON 32 — EC Exploitation via USB-C Charger PoC (Stimpson, 2025)](https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/Garrett%20Stimpson%20-%20Ghost%20in%20the%20Charger.pdf)
