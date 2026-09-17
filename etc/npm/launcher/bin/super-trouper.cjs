#!/usr/bin/env node

'use strict';

const { spawn } = require('node:child_process');
const { existsSync, accessSync } = require('node:fs');
const path = require('node:path');

const packageScope = '@crissyfield';

// Determine libc variant on Linux hosts
function detectLibc() {
  if (process.platform !== 'linux') {
    return null;
  }

  try {
    const report = process.report.getReport();
    if ((report != null) && (report.header != null) && (report.header.glibcVersionRuntime != null)) {
      return 'gnu';
    }
  } catch {
    // Fall through
  }

  try {
    accessSync('/etc/alpine-release');
    return 'musl';
  } catch {
    return 'gnu';
  }
}

// Build ordered list of platform package suffixes to resolve
function packageSuffixes() {
  const libc = detectLibc();
  if (libc == null) {
    return [`${process.platform}-${process.arch}`];
  }

  const other = (libc === 'gnu') ? 'musl' : 'gnu';
  return [`${process.platform}-${process.arch}-${libc}`, `${process.platform}-${process.arch}-${other}`];
}

// Locate platform package directory
function packageDirectory(suffix) {
  const packageName = `${packageScope}/super-trouper-${suffix}/package.json`;

  try {
    return path.dirname(require.resolve(packageName));
  } catch {
    // Fall back to resolution relative to the working directory.
  }

  try {
    return path.dirname(require.resolve(packageName, { paths: [process.cwd()] }));
  } catch {
    return null;
  }
}

// Locate package binary
let binaryPath = null;

for (const suffix of packageSuffixes()) {
  const packageDirectoryPath = packageDirectory(suffix);
  if (packageDirectoryPath == null) {
    continue;
  }

  const candidate = path.join(packageDirectoryPath, 'bin', 'super-trouper');
  if (existsSync(candidate)) {
    binaryPath = candidate;
    break;
  }
}

if (binaryPath == null) {
  console.error(`super-trouper: no prebuilt binary available for ${process.platform}-${process.arch}`);
  console.error('Download a binary directly from https://github.com/crissyfield/super-trouper/releases');

  process.exit(1);
}

// Run real binary
const child = spawn(binaryPath, process.argv.slice(2), { stdio: 'inherit' });

const signalNumbers = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGTERM: 15 };

for (const signal of Object.keys(signalNumbers)) {
  process.on(signal, () => child.kill(signal));
}

child.on('error', (error) => {
  console.error(`super-trouper: unable to launch ${binaryPath}: ${error.message}`);
  process.exitCode = 1;
});

child.on('close', (code, signal) => {
  if (signal != null) {
    process.exitCode = 128 + (signalNumbers[signal] || 15);
  } else {
    process.exitCode = (code != null) ? code : 1;
  }
});
