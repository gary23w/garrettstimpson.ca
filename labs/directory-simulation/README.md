# On-prem directory path simulation

This is an **offline, synthetic** lab for demonstrating an Agent Garrett style assessment workflow. It models a fictional on-prem directory, Windows Defender Firewall policy decisions, an identity delegation mistake, access to a canary, a durable role assignment, and a correlated detection alert. It does not contact a host, use credentials, change a firewall, install persistence, or test a real AI defender.

Run with Node.js 22 or newer:

```powershell
node labs/directory-simulation/run.mjs --out labs/directory-simulation/recordings
node labs/directory-simulation/run.mjs --verify labs/directory-simulation/recordings/baseline.json
node labs/directory-simulation/run.mjs --verify labs/directory-simulation/recordings/hardened.json
```

The baseline demonstrates a complete *simulated* path: directory inventory → blocked direct path → mistaken delegation → allowed management path → protected canary → durable role edge → defender alert. The hardened rerun removes the mistaken delegation and stops the path before the objective. Each event carries a SHA-256 hash of its contents and the previous event's hash, so the saved sequence can be checked for alteration. These hashes provide integrity for the local recording, not proof that the modeled events occurred on real infrastructure.

The two text recordings are suitable for a terminal walkthrough. The JSON files are machine-readable evidence for a report or GUI viewer. For a real engagement, replace the fixture with a written scope and controlled environment, obtain operator access through the engagement process, and collect actual system and defender evidence before making effectiveness claims.
