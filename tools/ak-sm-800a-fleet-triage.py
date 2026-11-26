#!/usr/bin/env python3
"""Offline fleet triage for Danfoss AK-SM 8xxA CVE-2026-129713.

This tool reads operator-supplied CSV inventory data. It does not scan networks,
connect to controllers, or test the vulnerability.
"""

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

AFFECTED_THROUGH = (5, 4, 0)


def parse_bool(value):
    value = (value or "").strip().lower()
    if value in {"yes", "true", "1", "on", "enabled"}:
        return True
    if value in {"no", "false", "0", "off", "disabled"}:
        return False
    return None


def parse_version(value):
    try:
        parts = tuple(int(p) for p in value.strip().split("."))
    except (AttributeError, ValueError):
        return None
    if not 1 <= len(parts) <= 4:
        return None
    return (parts + (0, 0, 0))[:3]


def public_address(value):
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError):
        return None
    return address.is_global


def assess(row):
    version = parse_version(row.get("version"))
    affected = version is not None and version <= AFFECTED_THROUGH
    internet = parse_bool(row.get("internet_exposed"))
    strict = parse_bool(row.get("strict_mode"))
    vpn = parse_bool(row.get("vpn_only"))
    address_public = public_address(row.get("address"))

    reasons = []
    score = 0
    if version is None:
        reasons.append("version unknown")
        score += 3
    elif affected:
        reasons.append("version 5.4.0 or earlier")
        score += 5
    else:
        reasons.append("version appears newer than affected range")

    if internet is True or address_public is True:
        reasons.append("internet exposure reported")
        score += 5
    elif internet is None and address_public is None:
        reasons.append("exposure unknown")
        score += 2

    if strict is False:
        reasons.append("Strict Mode disabled")
        score += 2
    elif strict is None:
        reasons.append("Strict Mode unknown")
        score += 1

    if vpn is False:
        reasons.append("remote access not VPN-only")
        score += 1
    elif vpn is None:
        reasons.append("VPN status unknown")
        score += 1

    if not affected and version is not None:
        priority = "VERIFY"
    elif score >= 10:
        priority = "CRITICAL"
    elif score >= 7:
        priority = "HIGH"
    elif score >= 4:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return priority, score, "; ".join(reasons)


def main():
    parser = argparse.ArgumentParser(description="Prioritize AK-SM 8xxA inventory for CVE-2026-129713 without scanning devices")
    parser.add_argument("inventory", type=Path, help="CSV with name,version,address,internet_exposed,strict_mode,vpn_only")
    parser.add_argument("-o", "--output", type=Path, help="write results to CSV instead of stdout")
    args = parser.parse_args()

    destination = args.output.open("w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        with args.inventory.open(newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            required = {"name", "version", "address", "internet_exposed", "strict_mode", "vpn_only"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                parser.error("missing CSV columns: " + ", ".join(sorted(missing)))
            fields = list(reader.fieldnames) + ["priority", "score", "reason"]
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            results = []
            for row in reader:
                priority, score, reason = assess(row)
                row.update(priority=priority, score=score, reason=reason)
                results.append(row)
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "VERIFY": 4}
            for row in sorted(results, key=lambda r: (order[r["priority"]], -int(r["score"]))):
                writer.writerow(row)
    finally:
        if args.output:
            destination.close()


if __name__ == "__main__":
    main()
