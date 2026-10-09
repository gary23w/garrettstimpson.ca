import test from 'node:test';
import assert from 'node:assert/strict';
import { accessPasswordMinimum } from './src/access-policy.mjs';

test('access password policy retains the default for absent or invalid settings', () => {
  assert.equal(accessPasswordMinimum(), 16);
  for (const value of ['', 'invalid', '7', '0', '-1', '129', '10.5']) assert.equal(accessPasswordMinimum({ ACCESS_PASSWORD_MIN_LENGTH: value }), 16);
});

test('access password policy permits an explicit deployment minimum', () => {
  for (const value of [8, 10, 16, 128]) assert.equal(accessPasswordMinimum({ ACCESS_PASSWORD_MIN_LENGTH: String(value) }), value);
});
