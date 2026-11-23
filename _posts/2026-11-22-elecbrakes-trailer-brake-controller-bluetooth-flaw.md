---
layout: post
title: "Someone in the Next Lane Could Touch Your Trailer Brakes: The Elecbrakes Bluetooth Flaw"
seo_title: "Elecbrakes Trailer Brake Bluetooth Flaw (ICSA-26-323-02)"
author: Garrett Stimpson
date: 2026-11-22 07:00:00 -0500
categories: [security, vulnerabilities]
tags: [elecbrakes, ics-advisory, icsa-26-323-02, bluetooth, ble, towing, trailer-brakes, physical-security, cve-2026-96805, cve-2026-125273, cve-2026-124281]
excerpt: "A CISA advisory says nearby Bluetooth devices could reach the controls of popular trailer brake controllers with no pairing at all. The fix shipped in July. The older model has no fix. Almost nobody is talking about it."
description: "CISA advisory ICSA-26-323-02 covers three flaws in Elecbrakes EB2, VM1 and ELBC2000 trailer brake controllers: no Bluetooth authentication, command replay and an unprotected firmware channel. Affected versions, fixed firmware, and what towers should do now."
permalink: /posts/2026/11/22/elecbrakes-trailer-brake-controller-bluetooth-flaw/
---

Most security bugs cost you data. This one is about the thing that stops two tonnes of caravan from pushing your car through an intersection.

On November 19, 2026, CISA published advisory ICSA-26-323-02 for three trailer brake controllers made by Elecbrakes, an Australian company: the EB2, the VM1 and the older ELBC2000. CISA's summary is blunt. Successful exploitation "could allow an attacker to gain control of the brakes of a trailer, modify the firmware, disable the brake lights, modify the brake conditions or disable other critical safety features."

That landed in the same week as a pile of louder news, and it got a handful of trade-press write-ups and not much else. If you tow, or you know someone who does, it is worth five minutes.

## What these devices are

An electric brake controller is the box that tells a trailer's brakes when and how hard to brake. Without it, the trailer just shoves the tow vehicle. Elecbrakes sells into Australia and New Zealand, where caravans, horse floats, boat trailers and tradie trailers are everywhere, and its controllers sit in a lot of rigs.

Their pitch is convenience. The EB2 mounts on the trailer drawbar, so you can hook the same trailer up to different vehicles. The VM1 mounts in the vehicle for people who tow several trailers. Both pair with a phone app over Bluetooth Low Energy (BLE), and both include automatic sway control. The ELBC2000 is the earlier model, no longer sold but still out there.

That phone connection is where the trouble lives.

## The three flaws, in plain language

CISA lists three CVEs. Here is what each one means for a normal person:

**1. No lock on the door (CVE-2026-96805, CVSS 3.1 score 9.6, critical).** According to the advisory, a Bluetooth device within range can write to the control interface and "influence braking with no authentication or pairing." In other words, the controller did not check that the thing talking to it was your phone.

**2. Commands can be recorded and played back (CVE-2026-125273, CVSS 3.1 score 9.6, critical).** Commands had no sequence numbers, nonces or session tokens. CISA says captured commands "can be replayed, and the last command persists across sessions." That last part matters: a bad setting does not reset when you reconnect.

**3. Firmware updates were not protected (CVE-2026-124281, CVSS 3.1 score 6.1, medium).** The firmware-update channel was unprotected, which may allow unauthorized firmware modification. Changed firmware on a brake controller is the kind of problem that outlives a reboot.

All three are rated "adjacent network" attacks. Nobody can do this from the other side of the world. Someone has to be within Bluetooth range: the car park, the campground, the servo, the next lane at a red light. That limits who can try it. It does not make it harmless, because towing happens in exactly the places strangers are close by.

I am not going to describe how to send these commands. You do not need that to protect yourself, and nobody needs a how-to for messing with someone's brakes.

## The quiet timeline

This is the part I find most interesting, and it is a pattern worth remembering.

- **May 18, 2026:** Elecbrakes was notified of the vulnerabilities, according to CISA.
- **July 6, 2026:** Elecbrakes released fixed firmware for the EB2 and VM1.
- **November 19, 2026:** CISA published the advisory.

So the fix has existed for more than four months. That is good, responsible behaviour. But a firmware update on a brake controller only arrives if the owner opens the app and installs it. Plenty of people set these up once and never open the app again. The public warning that would push them to do it only came out this week.

Elecbrakes reports no known incidents of damage or injury, and CISA's records do not mark any of these as exploited. This is not an active attack campaign. It is a serious safety gap that has been quietly sitting in driveways.

The researchers credited are Patrick Forck and Jeremy McCarthy of Element Digital.

## Affected versions and fixes

| Device | Affected | Fix |
|---|---|---|
| EB2 (trailer-mounted) | 3.0.4.2.0 and earlier | Firmware 3.0.4.4.3 |
| VM1 (vehicle-mounted) | Earlier than 1.3.4.2.1 | Firmware 1.3.4.2.1 |
| ELBC2000 (older model) | All versions | **No fix available** |

For the ELBC2000, CISA says the vendor "is determining how to address these vulnerabilities for this particular controller" and encourages owners to check the Elecbrakes app periodically for updates.

## What to do if you tow with one of these

**If you have an EB2 or VM1:**

1. Open the Elecbrakes app and connect to the controller.
2. Check the firmware version against the table above.
3. If you are behind, install the update through the app, which is the method CISA and the vendor point to.
4. If you share, hire out or borrow trailers, check every trailer. The EB2 lives on the drawbar, so the firmware belongs to the trailer, not to whichever car is towing it. A trailer you bought second-hand may never have been updated.

**If you have an ELBC2000:**

1. Keep an eye on the Elecbrakes app for an update.
2. Contact Elecbrakes directly and ask what they recommend. Their own guidance says to reach out with questions.
3. Do a proper brake check after hooking up and before every trip: test the trailer brakes at low speed and confirm the brake lights work. Those are the exact functions CISA says could be tampered with.
4. Think seriously about whether replacing an unsupported controller is worth it for the towing you do. That is your call, but "no fix available" on a braking system is a real factor.

**For everyone who tows, whatever brand you use:**

- Know which parts of your rig talk Bluetooth or Wi-Fi, and check for firmware updates the way you would check tyre pressure.
- If a controller starts behaving strangely, such as brake settings changing on their own or brake lights failing, stop, inspect and contact the manufacturer before carrying on.

## Why this kind of bug matters

We have spent years worrying about hacked laptops and leaked passwords. Meanwhile, more and more physical safety gear has quietly gained an app and a radio: door locks, garage openers, e-bikes, medical devices, and now brake controllers. Each one is a small computer that somebody has to remember to update, usually with no reminder.

This advisory is a good example of the system working slowly: researchers found it, the vendor fixed it, CISA published it. The weak link is the last step, getting the fix onto the device in your driveway. That step is on us, so pass this along to the person in your life with a caravan.

## Keep reading

- [The water utility software that shipped a map of its own customers](/posts/2026/11/23/dorsett-infoscan-water-scada-vulnerabilities/)
- [The survey link that ran code: REDCap's quiet two months](/posts/2026/11/21/redcap-survey-link-quiet-exploitation/)
- [Three exploitation stories nobody is talking about](/posts/2026/11/15/three-quiet-exploitation-stories-nobody-is-covering/)

## Sources

- CISA, ICS Advisory ICSA-26-323-02, Elecbrakes EB2, VM1, ELBC2000 (November 19, 2026): [cisa.gov/news-events/ics-advisories/icsa-26-323-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-02)
- CISA CSAF record for ICSA-26-323-02: [github.com/cisagov/CSAF](https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-323-02.json)
- OT Security Wire coverage: [otsecuritywire.com](https://otsecuritywire.com/articles/elecbrakes-eb2-vm1-elbc2000-icsa-26-323-02-ble-trailer-brake-controller-no-authentication/)
- Elecbrakes product information: [elecbrakes.com](https://www.elecbrakes.com/products)
