#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk test runner — runs all test suites sequentially.
 * Exit code 0 if all pass, 1 if any fail.
 */

const { execSync } = require('child_process');
const path = require('path');

const suites = [
  'test-crypto.js',
  'test-keys.js',
  'test-ghost-share.js',
  'test-hmac-sentinel.js',
  'test-stratum-client.js',
  'test-vs3-client.js',
];

const dir = __dirname;
let totalPassed = 0, totalFailed = 0;

for (const suite of suites) {
  const file = path.join(dir, suite);
  try {
    const output = execSync(`node "${file}"`, { encoding: 'utf8', timeout: 30000 });
    const match = output.match(/(\d+) passed, (\d+) failed/);
    if (match) {
      totalPassed += parseInt(match[1]);
      totalFailed += parseInt(match[2]);
    }
    process.stdout.write(output);
  } catch (err) {
    process.stdout.write(err.stdout || '');
    process.stderr.write(err.stderr || '');
    totalFailed++;
  }
}

console.log(`\n══ SDK Total: ${totalPassed} passed, ${totalFailed} failed ══\n`);
process.exit(totalFailed > 0 ? 1 : 0);
