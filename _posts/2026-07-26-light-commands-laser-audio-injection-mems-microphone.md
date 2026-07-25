---
layout: post
title: "Light Commands — Laser-Based Audio Injection on Voice-Controllable Systems"
date: 2026-07-26
categories: [hardware, exploits, iot, side-channels]
tags: [light-commands, laser, MEMS, microphone, voice-assistant, Amazon-Alexa, Google-Assistant, Apple-Siri, audio-injection, USENIX, physical-attack]
excerpt: "MEMS microphones convert light to sound. A laser pointer can inject commands into smart speakers from 110 meters away — through windows, inaudible, untraceable."
---

**CVE:** None assigned (architectural vulnerability class in MEMS microphone design)
**Discovered by:** Takeshi Sugawara (UEC Tokyo), Benjamin Cyr, Sara Rampazzi, Daniel Genkin, Kevin Fu (University of Michigan)
**Published:** USENIX Security Symposium 2020
**Affected:** Any device using MEMS microphones with always-on voice assistants — Amazon Echo (all generations), Google Home/Nest, Apple iPhone XR/iPad, Facebook Portal, Samsung Galaxy S9, Google Pixel 2, and hundreds more
**Fixed in:** No hardware fix exists for shipped devices. Software-side mitigations (phonetic challenge-response, second-factor confirmation) can reduce impact but do not fix the underlying physics.
**Public PoC:** [lightcommands.com](https://lightcommands.com/) — paper, video demos, citation

---

Here's a scenario: you're sitting in your living room. Your Google Home is on the coffee table. Outside, across the street, someone points a modest laser pointer at your window. They modulate the laser beam — on and off, thousands of times per second — encoding a voice command into pulses of light so fast you can't even see them flicker.

Inside your home, your Google Home hears: "OK Google, unlock the front door."

And it does.

No audio recording of the command exists. No microphone picked up any sound — because there was no sound. The command was never spoken. It was injected directly into the MEMS microphone's diaphragm using a beam of light.

This is Light Commands: a vulnerability class in MEMS microphones that turns every smart speaker, phone, and voice-controlled device into a laser-addressable command receiver, controllable from over a hundred meters away through closed windows.

## The Physics: MEMS Microphones Are Also Photodetectors

The attack works because of how MEMS microphones are built. A MEMS (Micro-Electro-Mechanical Systems) microphone contains a tiny diaphragm — a thin membrane suspended over a backplate, forming a variable capacitor. Sound pressure waves cause the diaphragm to vibrate, changing the capacitance, and the on-chip ASIC converts that change into an electrical signal.

The key insight is that the diaphragm absorbs light. When you shine a modulated laser on it, the diaphragm heats up and cools down in sync with the laser's modulation. This thermal expansion and contraction physically moves the diaphragm — exactly the same way sound pressure would. The ASIC can't tell the difference. It just sees capacitance changes and faithfully reproduces whatever waveform the laser encoded.

This is fundamentally different from conventional optical eavesdropping (like the LASER microphone used by intelligence agencies since the 1970s). Those bounce a laser off a window and detect the vibration of the glass. Light Commands goes directly into the device's microphone — no window vibration, no ambient noise, no glass alignment needed. The laser is aimed at the acoustic port of the device itself.

The researchers demonstrated this with wavelengths from 532 nm (green) through 1064 nm (infrared). Infrared is particularly dangerous because it's completely invisible to the human eye — the attacker can be actively injecting commands and nobody in the room would see anything.

## What the Attackers Achieved

The Light Commands team tested 27 different devices across Amazon Alexa, Google Assistant, Apple Siri, and Facebook Portal ecosystems. Their results:

| Device | Assistant | Max Distance (60 mW laser) |
|--------|-----------|---------------------------|
| Google Home | Google Assistant | 110+ meters |
| Echo Plus 1st Gen | Amazon Alexa | 110+ meters |
| Echo Plus 2nd Gen | Amazon Alexa | 50 meters |
| Echo (original) | Amazon Alexa | 50+ meters |
| iPhone XR | Apple Siri | 110 meters |
| Google Home Mini | Google Assistant | 20 meters |
| Nest Cam IQ | Google Assistant | 50+ meters |
| Facebook Portal Mini | Alexa + Portal | 18 meters |

The attack works through standard double-pane windows with only minor power loss. At 60 mW — the legal limit for Class 3B lasers in many jurisdictions — they achieved reliable command injection at over 100 meters with telescoping optics.

Most critically, they demonstrated real-world impact:

- **Unlocking smart locks** — They injected "Alexa, unlock the front door" into an Echo Plus controlling a smart lock
- **Opening garage doors** — Google Assistant commands sent to a connected garage door opener
- **Vehicle unlock/start** — Using Google Assistant account integration to unlock and start a Tesla and a Ford via the victim's linked account
- **E-commerce purchases** — Ordering physical goods through Alexa voice purchasing

None of these required the victim to be home. None left an audio trace of the attack.

## Why This Is Fundamentally Different From Voice Spoofing

Existing voice-security research focuses on hidden voice commands (audio that humans can't understand but speech recognition still processes) or adversarial audio examples (subtle perturbations that cause misclassification). These are software attacks — they exploit the gap between how humans and speech recognition models process sound.

Light Commands is a hardware attack. It bypasses the entire audio domain. The device's microphone electrically registers the same signal as if a human had spoken, at the full voice-capture bandwidth. No compression artifacts, no environmental noise, no audible clues. The voice assistant processes it as a normal, legitimate voice command because from its perspective, it is one.

This also means the attack is undetectable by any audio-based monitoring. If a security camera records the room during the attack, it will hear silence. The device itself doesn't record the command to any audio log — the injected signal is indistinguishable from ambient voice trigger.

## Why MEMS Microphones Do This

MEMS microphones replaced electret condenser microphones in virtually every consumer device over the last decade because they are smaller, more reliable, cheaper, and can be reflow-soldered onto circuit boards. They are in every smartphone, every smart speaker, every laptop, every tablet, every IoT device with voice control.

The photoresponse is a side effect of the MEMS design. The diaphragm is a thin polysilicon or metal film that sits directly in the path of any incoming light through the acoustic port. Shielding it would require adding an opaque physical barrier between the acoustic port and the diaphragm — which would change the acoustic response and potentially increase manufacturing cost.

The researchers found that even a thin layer of dust on the diaphragm makes no difference to the photoresponse. This is not a manufacturing defect in one batch — it's a fundamental property of the MEMS architecture.

## No CVE, No Patch

This attack class never received a CVE. It's not a software bug that can be patched. It's not a firmware bug. It's not even a hardware bug in the traditional sense — it's a physics-expectation mismatch. The designers of MEMS microphones assumed the sensor would only respond to acoustic pressure. It turns out it also responds to modulated light.

What does this mean for mitigation?

**Hardware-side:** Future MEMS microphones could include opaque shielding over the diaphragm, or optical filters that block the relevant wavelengths. Some manufacturers have quietly added light-blocking meshes to newer revisions, but this isn't publicly documented and there's no industry-wide standard.

**Software-side:** Defense-in-depth for voice commands. The most effective mitigation proposed by the researchers is **phonetic challenge-response**: for high-risk commands (unlock doors, make purchases, start cars), the assistant issues a randomized spoken challenge phrase — "To confirm, say the word 'umbrella'" — and the attacker's laser would need to inject two separate, unpredictable commands in sequence. Since the laser must be aimed continuously at the microphone, and the microphone's optical aperture is small, maintaining alignment through changing thermal conditions over an extended period is nontrivial.

Google and Amazon have added some high-risk command confirmations to their voice assistants since 2020, but these are inconsistently applied and vary by region and device configuration.

**Physical:** The most reliable defense is to close curtains or blinds on windows that face public areas. Even sheer curtains significantly attenuate the laser signal. A physical cover over the device's microphone port when not in use is also effective — though it defeats the purpose of an always-listening assistant.

## The Bigger Picture: Sensors That Sense Things They Weren't Designed For

Light Commands belongs to a growing class of vulnerabilities where a sensor responds to a physical phenomenon outside its intended domain:

- **Acoustic attacks on hard drives** (CVE-2016-3989) — where sound vibrations cause head-arm misalignment and corrupted writes
- **Gyroscope resonance** (GAIROSCOPE, 2020) — where acoustic tones at the gyro's resonant frequency produce false rotation readings
- **Accelerometer injection** — where ultrasound modulates accelerometer readings, potentially confusing step counters or vehicle airbag systems
- **LED eavesdropping** — where a device's own power/status LED is used as a photodiode to exfiltrate audio from the room

Each of these exploits a gap between the sensor designer's threat model and reality. MEMS microphones were designed to detect sound. Nobody considered that they also detect light.

## The Bottom Line

There is a laser-addressable command injection vector in every smart speaker, every smartphone, every tablet, every laptop with a voice assistant, and every IoT device with a MEMS microphone — which is to say, nearly every internet-connected consumer device manufactured in the last decade.

The attack has a range of over 100 meters. It works through windows. It's invisible if you use infrared. It leaves no audio trace. And because it exploits the physical operating principle of the microphone itself, there is no patch for existing devices.

The Light Commands team published their full paper, video demonstrations, and device-specific measurements at lightcommands.com. It's worth reading if you design IoT products, work on hardware security, or just want to understand why your smart speaker can hear things that never made a sound.

---

*— Garrett Stimpson*

*Thanks to Takeshi Sugawara, Benjamin Cyr, Sara Rampazzi, Daniel Genkin, and Kevin Fu for the research, the open-access paper, and the excellent public documentation at lightcommands.com. This is the standard for how hardware security research should be communicated.*

### References
- [Light Commands official site](https://lightcommands.com/) — paper, videos, device test results
- Sugawara et al., "Light Commands: Laser-Based Audio Injection Attacks on Voice-Controllable Systems," USENIX Security 2020
- [USENIX Security 2020 paper page](https://www.usenix.org/conference/usenixsecurity20/presentation/sugawara)
- Sugawara et al., *sec20-sugawara.pdf* — full paper with methodology and measurement data
