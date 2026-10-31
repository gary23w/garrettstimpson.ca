---
layout: doc
title: "On-prem directory lab: recorded simulation"
description: "Recorded baseline and hardened runs of a deterministic, offline policy simulation of a fictional on-prem directory. No live infrastructure was contacted."
last_modified_at: 2026-10-16
---

# On-prem directory lab: recorded simulation

**Run date:** 2026-10-16

**Target:** `corp.example.test` (fictional)

**Method:** Deterministic, offline policy simulation; no live infrastructure was contacted.

## Objective and result

The exercise models a common assessment question: can a low-privilege identity reach a protected record through a directory delegation mistake and an allowed management path, and can a defender observe the sequence? The fixture intentionally starts with a blocked direct route, so the full path depends on the identity and management-policy decisions.

| Check | Baseline | Hardened rerun |
| --- | --- | --- |
| Direct workstation route | Blocked | Blocked |
| Delegated maintenance identity | Allowed by fixture | Blocked after delegation removal |
| Protected canary reached | Yes, simulated | No |
| Durable role edge | Yes, simulated | No |
| Defender alert | Yes, simulated | Yes, simulated |

The baseline reached its synthetic objective and modeled repeat access. It did **not** evade the synthetic detector: the role change and protected read produced an alert. In the hardened rerun, removing the delegated identity prevented the rest of the path.

The simulator evaluates each directory, firewall, canary, and role-grant gate. A separate test disables the management route while leaving the delegation mistake in place; the canary then remains unreachable. That checks the chain's dependency on the firewall policy rather than simply printing a fixed success story.

## Evidence

- [Baseline terminal recording](recordings/baseline.txt) and [machine-readable events](recordings/baseline.json)
- [Hardened terminal recording](recordings/hardened.txt) and [machine-readable events](recordings/hardened.json)
- Each event includes its SHA-256 hash and the previous event's hash. `node run.mjs --verify recordings/baseline.json` validates the saved sequence.

## Interpretation

This recording demonstrates the **reporting workflow**, not a product benchmark. It cannot establish that Agent Garrett bypasses Microsoft Defender Firewall, avoids AI detection, compromises Active Directory, or establishes persistence on a real host. A client engagement would need written scope, real authorization, a controlled target, collection of firewall and detection telemetry, and independently verified outcomes before making those claims.
