import assert from 'node:assert/strict';
import test from 'node:test';
import { runScenario, verifyChain } from './run.mjs';

test('the baseline reaches its canary, models durable access, and produces a defender alert', () => {
  const result = runScenario('baseline');
  assert.deepEqual(result.outcome, {
    objectiveReached: true, durableAccessSimulated: true, detectorAlerted: true,
  });
  assert.equal(result.events.find((event) => event.stage === 'segmentation').decision, 'blocked');
  assert.equal(verifyChain(result), true);
});

test('the hardened control prevents the objective and durable access', () => {
  const result = runScenario('hardened');
  assert.deepEqual(result.outcome, {
    objectiveReached: false, durableAccessSimulated: false, detectorAlerted: true,
  });
  assert.equal(verifyChain(result), true);
});

test('a firewall control independently stops the chain after mistaken delegation', () => {
  const result = runScenario('baseline', { adminManagementRoute: false });
  assert.equal(result.events.find((event) => event.action === 'Use approved admin-01 management path').decision, 'blocked');
  assert.equal(result.outcome.objectiveReached, false);
  assert.equal(result.outcome.durableAccessSimulated, false);
  assert.equal(verifyChain(result), true);
});

test('an altered event invalidates the evidence chain', () => {
  const result = runScenario('baseline');
  result.events[2].decision = 'allowed';
  assert.equal(verifyChain(result), false);
});
