'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const launcher = path.resolve(__dirname, '../bin/pkgscope.js');

test('forwards argv without shell evaluation and preserves exit status', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pkgscope-launcher-'));
  const binary = path.join(directory, 'native.js');
  fs.writeFileSync(
    binary,
    '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify(process.argv.slice(2))); process.exit(7);\n',
    { mode: 0o755 }
  );
  const result = spawnSync(process.execPath, [launcher, 'literal;value', '$(not-a-shell)'], {
    encoding: 'utf8',
    env: { ...process.env, PKGSCOPE_BINARY_PATH: binary }
  });
  assert.equal(result.status, 7);
  assert.deepEqual(JSON.parse(result.stdout), ['literal;value', '$(not-a-shell)']);
  assert.equal(result.stderr, '');
});

test('reports a missing explicit binary without a stack trace', () => {
  const result = spawnSync(process.execPath, [launcher], {
    encoding: 'utf8',
    env: { ...process.env, PKGSCOPE_BINARY_PATH: '/definitely/missing/pkgscope' }
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^pkgscope: native binary is missing/);
  assert.doesNotMatch(result.stderr, /at Object\./);
});

