#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const launcherPackage = require('../package.json');

function fail(message) {
  process.stderr.write(`pkgscope: ${message}\n`);
  process.exit(1);
}

function platformPackage() {
  if (process.platform !== 'darwin') {
    fail(`unsupported platform ${process.platform}/${process.arch}; v0.2 supports macOS only`);
  }
  if (process.arch === 'arm64') return '@pkgscope/darwin-arm64';
  if (process.arch === 'x64') return '@pkgscope/darwin-x64';
  fail(`unsupported macOS architecture ${process.arch}`);
}

function resolveBinary() {
  if (process.env.PKGSCOPE_BINARY_PATH) {
    return process.env.PKGSCOPE_BINARY_PATH;
  }
  const packageName = platformPackage();
  let packageJson;
  try {
    packageJson = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    fail(
      `native package ${packageName}@${launcherPackage.version} is missing; ` +
      'reinstall pkgscope with optional dependencies enabled'
    );
  }
  const nativePackage = JSON.parse(fs.readFileSync(packageJson, 'utf8'));
  if (nativePackage.version !== launcherPackage.version) {
    fail(
      `version mismatch: launcher ${launcherPackage.version}, ` +
      `${packageName} ${nativePackage.version}; reinstall pkgscope`
    );
  }
  return path.join(path.dirname(packageJson), 'bin', 'pkgscope');
}

const binary = resolveBinary();
if (!fs.existsSync(binary)) {
  fail(`native binary is missing from ${binary}`);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: 'inherit',
  shell: false,
  windowsHide: true
});

if (result.error) {
  fail(`could not start native binary: ${result.error.message}`);
}
if (result.signal) {
  const signalNumber = require('node:os').constants.signals[result.signal];
  process.exit(typeof signalNumber === 'number' ? 128 + signalNumber : 1);
}
process.exit(result.status === null ? 1 : result.status);
