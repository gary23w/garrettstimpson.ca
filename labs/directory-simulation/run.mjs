#!/usr/bin/env node
// Offline attack-path simulation. This program does not open sockets or run OS commands.
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const START = Date.parse('2026-10-16T14:00:00.000Z');
const LAB = 'corp.example.test';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function verifyChain(recording) {
  let previous = '0'.repeat(64);
  for (const event of recording.events) {
    const { hash, ...payload } = event;
    if (payload.previousHash !== previous || sha256(JSON.stringify(payload)) !== hash) return false;
    previous = hash;
  }
  return previous === recording.finalHash;
}

export function runScenario(name, policyOverrides = {}) {
  if (!['baseline', 'hardened'].includes(name)) throw new Error(`Unknown scenario: ${name}`);
  const policy = {
    directoryRead: true,
    directWorkstationRoute: false,
    delegatedMaintenanceIdentity: name === 'baseline',
    adminManagementRoute: true,
    maintenanceCanReadCanary: true,
    maintenanceCanGrantContinuity: true,
    detectorEnabled: true,
    ...policyOverrides,
  };
  const events = [];
  const state = { identity: 'lab-analyst', managementRouteOpen: false, canaryRead: false, durableAccess: false, alerted: false };
  function record(stage, actor, action, decision, evidence) {
    const previousHash = events.at(-1)?.hash ?? '0'.repeat(64);
    const payload = {
      time: new Date(START + events.length * 30_000).toISOString(),
      stage, actor, action, decision, evidence, previousHash,
    };
    events.push({ ...payload, hash: sha256(JSON.stringify(payload)) });
  }

  record('scope', 'controller', 'Load synthetic on-prem directory fixture', 'allowed',
    `${LAB}; 4 fictional hosts; no network access`);
  record('discovery', state.identity, 'Read authorized directory metadata', policy.directoryRead ? 'allowed' : 'blocked',
    policy.directoryRead ? 'Inventory: dc-01, admin-01, files-01, analyst-01' : 'Directory read policy denies this identity');
  if (policy.directoryRead) {
    record('segmentation', state.identity, 'Request direct path to files-01', policy.directWorkstationRoute ? 'allowed' : 'blocked',
      policy.directWorkstationRoute ? 'Simulated direct workstation route permits management traffic' : 'Simulated Windows Defender Firewall rule denies workstation-to-file management flow');
    const delegated = policy.delegatedMaintenanceIdentity;
    record('identity', state.identity, 'Request delegated maintenance identity', delegated ? 'allowed' : 'blocked',
      delegated ? 'Misconfigured lab delegation grants svc-inventory a maintenance role' : 'Delegation removed; only a named, time-bound administrator may assume this role');
    if (delegated) {
    state.identity = 'svc-inventory';
      state.managementRouteOpen = policy.adminManagementRoute;
      record('segmentation', state.identity, 'Use approved admin-01 management path', state.managementRouteOpen ? 'allowed' : 'blocked',
        state.managementRouteOpen ? 'Simulated firewall permits admin-01-to-files-01 management traffic' : 'Simulated firewall denies admin-01-to-files-01 management traffic');
      if (state.managementRouteOpen) {
        state.canaryRead = policy.maintenanceCanReadCanary;
        record('objective', state.identity, 'Access protected canary record', state.canaryRead ? 'allowed' : 'blocked',
          state.canaryRead ? 'Synthetic canary label: FINANCE-QUARTERLY; no real files accessed' : 'Canary access policy denies the maintenance role');
        if (state.canaryRead) {
          state.durableAccess = policy.maintenanceCanGrantContinuity;
          record('continuity', state.identity, 'Add durable LabContinuity role edge', state.durableAccess ? 'allowed' : 'blocked',
            state.durableAccess ? 'Synthetic directory state now grants svc-inventory repeat access' : 'Continuity grant policy denies the maintenance role');
        }
      }
    }
    state.alerted = policy.detectorEnabled && (!delegated || state.durableAccess);
    record('detection', 'lab-detector', delegated ? 'Correlate unusual role grant and protected read' : 'Review blocked identity transition', state.alerted ? 'alerted' : 'clear',
      state.alerted ? (delegated ? 'Synthetic high-severity alert; the chain was not invisible to the detector' : 'Synthetic identity alert correlated with the blocked management request') : 'Synthetic detector threshold was not met');
  }

  const recording = {
    kind: 'offline-directory-simulation', scenario: name, lab: LAB, policy,
    limitations: 'Synthetic policy decisions only. No live directory, firewall, AI product, credentials, or persistence mechanism was tested.',
    outcome: {
      objectiveReached: state.canaryRead,
      durableAccessSimulated: state.durableAccess,
      detectorAlerted: state.alerted,
    },
    events, finalHash: events.at(-1).hash,
  };
  if (!verifyChain(recording)) throw new Error('Evidence chain verification failed');
  return recording;
}

function transcript(recording) {
  const lines = [
    `DIRECTORY LAB DEMO FOR AGENT GARRETT + NL-VEIL  |  ${recording.scenario.toUpperCase()}`,
    `TARGET: ${recording.lab}  |  MODE: OFFLINE SIMULATION`,
    '',
  ];
  for (const event of recording.events) {
    lines.push(`[${event.time}] ${event.decision.toUpperCase().padEnd(7)} ${event.stage.padEnd(13)} ${event.action}`);
    lines.push(`  evidence: ${event.evidence}`);
  }
  lines.push('', `OBJECTIVE REACHED: ${recording.outcome.objectiveReached ? 'YES' : 'NO'}`);
  lines.push(`DURABLE ACCESS SIMULATED: ${recording.outcome.durableAccessSimulated ? 'YES' : 'NO'}`);
  lines.push(`DETECTOR ALERTED: ${recording.outcome.detectorAlerted ? 'YES' : 'NO'}`);
  lines.push(`EVIDENCE SHA-256 CHAIN: ${recording.finalHash}`);
  lines.push(`LIMIT: ${recording.limitations}`);
  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--verify') {
    if (!args[1]) throw new Error('Usage: node run.mjs --verify <recording.json>');
    const file = JSON.parse(await readFile(resolve(args[1]), 'utf8'));
    if (!verifyChain(file)) throw new Error('Evidence chain is invalid');
    process.stdout.write(`Verified ${file.events.length} events; final hash ${file.finalHash}\n`);
    return;
  }
  const outIndex = args.indexOf('--out');
  const outDir = resolve(outIndex < 0 ? 'recordings' : args[outIndex + 1] ?? 'recordings');
  await mkdir(outDir, { recursive: true });
  for (const name of ['baseline', 'hardened']) {
    const recording = runScenario(name);
    await writeFile(resolve(outDir, `${name}.json`), `${JSON.stringify(recording, null, 2)}\n`);
    await writeFile(resolve(outDir, `${name}.txt`), transcript(recording));
    process.stdout.write(transcript(recording));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
