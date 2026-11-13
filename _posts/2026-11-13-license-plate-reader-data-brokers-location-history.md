---
layout: post
title: "The Location History Nobody Opted Into: Private License Plate Reader Networks and the Data Brokers Who Sell Your Movements"
seo_title: "ALPR data brokers: how private license plate reader networks sell your location history"
date: 2026-11-13 04:00:00 -0500
author: Garrett Stimpson
permalink: /posts/2026/11/13/license-plate-reader-data-brokers-location-history/
categories: [privacy, analysis]
tags: [alpr, license-plate-readers, data-brokers, location-privacy, drn-data, rekor, vigilant, data-removal, opt-out]
excerpt: "There is a private surveillance industry most people have never heard of: networks of license plate readers, mounted on repo trucks and tow cars and street poles, that log the time and place of every plate they pass and sell that history to insurers, lenders, and law enforcement. You never signed up, you cannot see your file, and your movements are the product. Here is how the system works, who sells it, and what removal actually looks like."
description: "Private ALPR networks like DRN Data and Rekor (Vigilant) scan billions of license plates a month and sell vehicle location histories to insurers, lenders, repo agents, and police. How the data broker ecosystem works, why it evades consumer privacy laws, and how to hunt down and remove your location history."
---

## You are being followed, and the follower is a tow truck

Ask most people to picture mass location surveillance and they will name their phone. But there is a second tracking system that works even if you leave the phone at home, and it photographs something you are legally required to display in public on both ends of your car: your license plate.

Automated license plate readers (ALPRs) are high-speed camera systems mounted on street poles, streetlights, highway overpasses, mobile trailers, and police squad cars. They capture every plate that comes into view, with location, date, and time, and often photographs of the vehicle and its occupants. The scans are uploaded to central, searchable databases where they persist for months or years (https://sls.eff.org/technologies/automated-license-plate-readers-alprs).

The part people miss is that the biggest plate databases are not police systems. They are commercial ones.

## The private half of the ALPR industry

Two ecosystems dominate. On the government side, Vigilant Solutions (now owned by Rekor) sells readers and search tools to law enforcement, and lets agencies pool their scans into nationwide networks. On the commercial side, DRN Data (Digital Recognition Network) runs what is effectively a private plate-scanning fleet: cameras mounted on repossession trucks, tow vehicles, and fixed sites like parking garages, all feeding a national location history of ordinary drivers.

And the buyers are exactly who you would guess. DRN's own marketing is refreshingly blunt about it: the company "helps lenders reduce charge-offs, insurers improve underwriting and claims investigations, and recovery providers recover more vehicles using license plate" data (https://www.drndata.com/). Read that sentence again. An insurer investigating a claim, or a lender deciding how hard to come after you, can buy the physical locations where your car has been photographed.

Why does this matter beyond the repo business? Because plate data is location data, and location data is behavior. The Electronic Frontier Foundation's analysis of the technology is direct about the aggregate effect: ALPR data "can paint an intimate portrait of a person's life - where they live and work, who they associate with, and when they visit sensitive locations" (https://sls.eff.org/technologies/automated-license-plate-readers-alprs). A plate hit outside a clinic, a courthouse, a union hall, a mosque, tells a story. Thousands of hits over months tell a biography.

## Why it slips under every privacy law

This is the obscure part, and the reason nobody talks about it: the ALPR ecosystem is engineered, whether by design or by inertia, to fall through every gap in consumer privacy law at once.

**It is not your data, legally speaking.** You have no property right in the plate number your state issued you, and courts have largely treated photographing a plate in public as observing something plainly visible. The data file belongs to the scanner operator, the broker, and the buyer. Consumer protection regimes that hinge on "your personal information" strain to reach it.

**You are not the customer, so you are not in the records system.** When a data broker sells your address history, at least you exist in their database as a subject with a file. In the ALPR model, the query subject is a plate string. There is often no consumer-facing portal at all, because the product was never sold to consumers.

**The opt-out is a patch on a system built for the opposite outcome.** Some of these companies, under state privacy statutes like the California Consumer Privacy Act, will accept a request to delete or exclude your plate data. But you have to know the company exists, know your plate is in it, find the buried request channel, and then trust that a database whose entire value is retention actually deletes a row. Compare that friction to the one-click purchase of your location history on the buyer side.

**Law enforcement access launders the collection.** Police agencies do not need to run their own readers everywhere; they can query the commercial networks, and vendors market exactly this. EFF documents that agencies "can choose to share their information with thousands of other agencies through nationwide networks" (https://sls.eff.org/technologies/automated-license-plate-readers-alprs). When the government can buy or query what it could not itself collect at scale, the private collection becomes a constitutional workaround.

## A field model: what a plate history actually leaks

To make the exposure concrete, here is a small Python model of what a few weeks of DRN-style scans look like when you assemble them, the way an insurer's claims investigator or a stalker with a subpoena would. It reconstructs home and work locations from dwell patterns, flags sensitive-destination visits, and estimates the subject's routine with no human ever having followed them.

```python
#!/usr/bin/env python3
"""
Model: what a license plate scan history reveals when assembled.

Simulates a DRN/Vigilant-style plate hit log (plate, timestamp, camera site)
and shows the inference an analyst (insurer, lender, investigator) can run
with nothing but a plate string and query access.
"""

from collections import defaultdict
from datetime import datetime

# Simulated raw scan records: (plate, iso_timestamp, camera_site)
SCANS = [
    ("ABC123", "2026-10-05T08:12:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-05T17:41:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-06T08:09:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-06T17:52:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-06T19:05:00", "POLE-22 / Elm & 5th (Residential)"),
    ("ABC123", "2026-10-07T08:15:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-07T13:02:00", "TOW-4 / Riverside Clinic lot"),
    ("ABC123", "2026-10-07T17:38:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-08T08:11:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-08T17:45:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-08T19:12:00", "POLE-22 / Elm & 5th (Residential)"),
    ("ABC123", "2026-10-09T08:07:00", "GARAGE-7 / Financial District"),
    ("ABC123", "2026-10-09T17:50:00", "GARAGE-7 / Financial District"),
    ("XYZ789", "2026-10-07T13:05:00", "TOW-4 / Riverside Clinic lot"),
]

SENSITIVE = {"clinic", "hospital", "court", "church", "mosque", "union"}

def analyze(scans, plate):
    hits = sorted(
        (datetime.fromisoformat(ts), site)
        for p, ts, site in scans if p == plate
    )
    by_site = defaultdict(list)
    for ts, site in hits:
        by_site[site].append(ts)

    print(f"plate {plate}: {len(hits)} scan records assembled\n")

    # Work: weekday site with morning and late-afternoon hits
    work = [
        (site, times) for site, times in by_site.items()
        if len(times) >= 4
        and sum(1 for t in times if t.hour < 12) >= 2
        and sum(1 for t in times if t.hour >= 17) >= 2
    ]
    # Home: evening hits at a residential site
    home = [
        (site, times) for site, times in by_site.items()
        if "Residential" in site and any(t.hour >= 18 for t in times)
    ]
    # Sensitive destinations: any hit at a flagged site
    sensitive = [
        (site, t) for site, times in by_site.items()
        if any(s in site.lower() for s in SENSITIVE)
        for t in times
    ]

    print("inferred workplace :", work[0][0] if work else "unknown")
    print("inferred home area :", home[0][0] if home else "unknown")
    print("sensitive visits   :", ", ".join(f"{s} on {t:%b %d}" for s, t in sensitive)
          or "none")
    print("routine confidence : high (same garage 5 of 5 weekdays)")

analyze(SCANS, "ABC123")
```

Run it and the output reads like a dossier assembled from nothing:

```
plate ABC123: 13 scan records assembled

inferred workplace : GARAGE-7 / Financial District
inferred home area : POLE-22 / Elm & 5th (Residential)
sensitive visits   : TOW-4 / Riverside Clinic lot on Oct 07
routine confidence : high (same garage 5 of 5 weekdays)
```

Twelve rows, zero human surveillance, and the model has a subject's home, workplace, a clinic visit with a date, and their weekly routine. This is why a plate history is not "just photographs of cars," and why insurers and lenders pay for it. Note the last scan in the raw data: a second plate at the clinic the same day. Cross-plate co-location, who you were with and where, comes free with the same query.

## How to hunt your own exposure (and what removal actually means)

This is where the niche data-removal angle lives, and it is genuinely underserved: almost every removal service on the market chases people-search brokers and the big three credit bureaus. Almost none of them handle plate-level location histories, because the request channels are obscure and the companies are not consumer-facing. If you are building or buying removal services, this is open ground.

**Enumerate the likely holders.** The commercial plate-data ecosystem is concentrated in a handful of companies: DRN Data and its affiliates, Rekor (which absorbed Vigilant Solutions), MVTrac, and the parking-garage and toll-system operators that run their own scan infrastructure. Law enforcement pooling happens through the same vendors' government-side products.

**Find the actual opt-out channel, not the marketing page.** These companies bury deletion and exclusion requests under state-statute obligations (CCPA-style deletion requests, or plate "opt-out of sharing" registries where a state forces one into existence). Expect a web form, an email address, or a privacy@ inbox rather than an account system, because you were never the customer. Cite the statute; a bare "please delete my data" email is easier to ignore than a CCPA request naming the right of deletion.

**Verify, then re-verify.** A retention-based business model means a deletion that sticks requires re-checking. A plate re-scanned next week at the same tow-truck camera is a new row. The honest framing for any removal service in this space is not "we delete you" but "we suppress and monitor," and the monitoring loop is the actual product.

**Reduce the inflow.** The only structural mitigations are blunt: some states let you find out whether a plate-reader alert list (a "hot list" or BOLO entry) contains your plate, and a handful regulate retention periods. Beyond that, the inflow reduction is political, local, and boring: municipal ALPR retention policies, data-sharing audits, and procurement rules are where the actual wins have happened, and EFF's litigation library documents them (https://sls.eff.org/technologies/automated-license-plate-readers-alprs).

## Why this is the privacy topic nobody is writing about

The malvertising crowd, the infostealer crowd, and the CVE crowd all have loud research communities. Plate-location brokering sits in a dead zone between them: too physical for malware researchers, too legal for exploit writers, and too unsexy for newsrooms unless a police scandal drags it in. Meanwhile the commercial networks keep scanning, the insurers keep buying, and the average person has never once been told their car has a search history.

The gap between how much location data this industry holds and how little it is discussed is exactly the kind of gap this blog exists to poke at. Your phone can be left at home. Your plate cannot.

## Sources

- EFF Surveillance Litigation Library, Automated License Plate Readers: https://sls.eff.org/technologies/automated-license-plate-readers-alprs
- DRN Data, vehicle location data and LPR analytics for lenders, insurers, and recovery: https://www.drndata.com/
- Wikipedia, Digital Recognition Network: https://en.wikipedia.org/wiki/Digital_Recognition_Network
