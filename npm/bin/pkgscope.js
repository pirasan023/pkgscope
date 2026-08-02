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

function platformPackage(platform = process.platform, architecture = process.arch) {
  if (!['darwin', 'linux'].includes(platform)) {
    throw new Error(`unsupported platform ${platform}/${architecture}; v0.3 supports macOS and Linux`);
  }
  if (!['arm64', 'x64'].includes(architecture)) {
    throw new Error(`unsupported ${platform} architecture ${architecture}`);
  }
  return `@pirasan023/pkgscope-${platform}-${architecture}`;
}

function resolveBinary() {
  if (process.env.PKGSCOPE_BINARY_PATH) {
    return process.env.PKGSCOPE_BINARY_PATH;
  }
  let packageName;
  try {
    packageName = platformPackage();
  } catch (error) {
    fail(error.message);
  }
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

function main() {
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
}

if (require.main === module) main();

module.exports = { platformPackage };
