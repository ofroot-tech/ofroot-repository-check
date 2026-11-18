import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { scanRepository, formatText } from '../lib/scan.mjs';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(packageRoot, 'bin/ofroot-repo-check.mjs');
const accessKey = () => 'AKIA' + 'A'.repeat(16); // Synthetic format, never a real credential.
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'ofroot-check-synthetic-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  execFileSync('git', ['init', '--quiet'], { cwd: root });
  return root;
}
function put(root, filename, content) {
  const path = join(root, filename);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}
function stage(root) { execFileSync('git', ['add', '--all', '--'], { cwd: root }); }
function runCli(args) { return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' }); }

test('reports credential and selected code patterns without source values, paths or root', t => {
  const root = fixture(t);
  const filename = 'PRIVATE-FILENAME-EXAMPLE/app.js';
  const literal = 'ONLY_SYNTHETIC_SECRET_VALUE';
  put(root, filename, `const api_key = "${literal}";\nconst key = "${accessKey()}";\neval(input);\n`);
  stage(root);
  const report = scanRepository({ root });
  assert.equal(report.status, 'complete');
  assert.equal(report.coverage.filesScanned, 1);
  assert.ok(report.findings.some(item => item.ruleId === 'credential-aws-access-key' && item.line === 2));
  assert.ok(report.findings.some(item => item.ruleId === 'code-javascript-dynamic-execution' && item.line === 3));
  for (const output of [JSON.stringify(report), formatText(report)]) {
    for (const sensitive of [literal, accessKey(), filename, root, 'eval(input)']) assert.ok(!output.includes(sensitive));
  }
  assert.ok(report.findings.every(item => item.fileId === 'file-000001' && !Object.hasOwn(item, 'path')));
});

test('health-data checks are opt-in and identify only supported nearby quoted fields', t => {
  const root = fixture(t);
  put(root, 'synthetic-record.json', JSON.stringify({ patient_name: 'SYNTHETIC PERSON', diagnosis: 'SYNTHETIC CONDITION' }));
  stage(root);
  assert.ok(!scanRepository({ root }).findings.some(item => item.category === 'possible-health-data'));
  const report = scanRepository({ root, healthData: true });
  assert.equal(report.findings.filter(item => item.category === 'possible-health-data').length, 1);
  assert.match(report.notice, /does not establish/);
  assert.ok(!JSON.stringify(report).includes('SYNTHETIC PERSON'));
  assert.ok(!JSON.stringify(report).includes('SYNTHETIC CONDITION'));
});

test('a clinical field without a supported nearby identifier is not called a health record', t => {
  const root = fixture(t);
  put(root, 'definition.json', JSON.stringify({ diagnosis: 'SYNTHETIC CONDITION' }));
  stage(root);
  assert.equal(scanRepository({ root, healthData: true }).findings.length, 0);
});

test('scans index content rather than newer working files and does not stage anything', t => {
  const root = fixture(t);
  put(root, 'config.txt', accessKey());
  stage(root);
  const before = readFileSync(join(root, '.git/index'));
  put(root, 'config.txt', 'working tree changed after staging');
  put(root, 'untracked.txt', '-----BEGIN PRIVATE KEY-----');
  const report = scanRepository({ root, staged: true });
  assert.equal(report.scope.selection, 'changed-staged-index');
  assert.equal(report.coverage.filesScanned, 1);
  assert.ok(report.findings.some(item => item.ruleId === 'credential-aws-access-key'));
  assert.deepEqual(readFileSync(join(root, '.git/index')), before);
  assert.equal(readFileSync(join(root, 'config.txt'), 'utf8'), 'working tree changed after staging');
});

test('--staged narrows selection and does not silently read untracked or ignored files', t => {
  const root = fixture(t);
  put(root, 'tracked.txt', 'ordinary tracked content');
  put(root, '.gitignore', 'ignored.txt\n');
  stage(root);
  execFileSync('git', ['-c', 'user.name=Synthetic Test', '-c', 'user.email=synthetic@example.invalid', 'commit', '--quiet', '-m', 'synthetic baseline'], { cwd: root });
  put(root, 'ignored.txt', accessKey());
  put(root, 'untracked.txt', accessKey());
  put(root, 'tracked.txt', accessKey()); // Deliberately not staged yet.
  const report = scanRepository({ root, staged: true });
  assert.equal(report.status, 'complete');
  assert.equal(report.coverage.filesScanned, 0);
  assert.equal(report.findings.length, 0);
  const all = scanRepository({ root });
  assert.equal(all.coverage.filesScanned, 2);
  assert.equal(all.findings.length, 0);
});

test('symlink index entries do not cause reads outside the repository', { skip: process.platform === 'win32' }, t => {
  const root = fixture(t);
  const outside = fixture(t);
  put(outside, 'outside.txt', accessKey());
  symlinkSync(join(outside, 'outside.txt'), join(root, 'link.txt'));
  stage(root);
  const report = scanRepository({ root });
  assert.equal(report.status, 'partial');
  assert.equal(report.coverage.skipped.symlink, 1);
  assert.equal(report.coverage.filesScanned, 0);
  assert.equal(report.findings.length, 0);
  assert.ok(!JSON.stringify(report).includes(outside));
});

test('already tracked files are scanned even when their names later match .gitignore', t => {
  const root = fixture(t);
  put(root, 'tracked-config.txt', accessKey());
  stage(root);
  put(root, '.gitignore', 'tracked-config.txt\n');
  stage(root);
  const report = scanRepository({ root });
  assert.equal(report.status, 'complete');
  assert.ok(report.findings.some(item => item.ruleId === 'credential-aws-access-key'));
});

test('missing promised blobs produce incomplete coverage without invoking a remote helper', { skip: process.platform === 'win32' }, t => {
  const root = fixture(t);
  put(root, 'data.txt', accessKey());
  stage(root);
  const oid = execFileSync('git', ['rev-parse', ':data.txt'], { cwd: root, encoding: 'utf8' }).trim();
  rmSync(join(root, '.git/objects', oid.slice(0, 2), oid.slice(2)));
  const marker = join(root, 'UNEXPECTED-REMOTE-HELPER');
  put(root, 'fake-remote.sh', `#!/bin/sh\ntouch '${marker}'\nexit 1\n`);
  for (const [key, value] of [
    ['extensions.partialClone', 'origin'], ['remote.origin.promisor', 'true'],
    ['remote.origin.url', `ext::sh ${join(root, 'fake-remote.sh')}`], ['protocol.ext.allow', 'always'],
  ]) execFileSync('git', ['config', key, value], { cwd: root });
  const report = scanRepository({ root });
  assert.equal(report.status, 'partial');
  assert.equal(report.coverage.skipped.unreadable, 1);
  assert.equal(report.findings.length, 0);
  assert.equal(existsSync(marker), false);
});

test('binary, invalid encoding and oversized blobs are visible incomplete coverage', t => {
  const root = fixture(t);
  put(root, 'binary.bin', Buffer.from([0, 1, 2]));
  put(root, 'invalid.txt', Buffer.from([0xc3, 0x28]));
  put(root, 'large.txt', 'x'.repeat(33));
  stage(root);
  const report = scanRepository({ root, limits: { fileBytes: 32 } });
  assert.equal(report.status, 'partial');
  assert.equal(report.coverage.skipped.binary, 1);
  assert.equal(report.coverage.skipped.encoding, 1);
  assert.equal(report.coverage.skipped.oversized, 1);
});

test('file, byte, finding and time caps produce partial reports rather than clean success', t => {
  const root = fixture(t);
  put(root, 'one.txt', accessKey() + '\n' + accessKey());
  put(root, 'two.txt', accessKey());
  stage(root);
  for (const limits of [{ files: 1 }, { totalBytes: 1 }, { findings: 1 }, { milliseconds: 0 }]) {
    const report = scanRepository({ root, limits });
    assert.notEqual(report.status, 'complete');
  }
  const capped = scanRepository({ root, limits: { findings: 1 } });
  assert.equal(capped.findings.length, 1);
  assert.equal(capped.coverage.limitReached, true);
});

test('opaque file IDs remain usable for explicit local path lookup, including unusual filenames', t => {
  const root = fixture(t);
  const name = 'PRIVATE-NAME\nextra-line.txt';
  put(root, name, accessKey());
  stage(root);
  const redacted = scanRepository({ root });
  const local = scanRepository({ root, includePaths: true });
  assert.equal(local.findings[0].fileId, redacted.findings[0].fileId);
  assert.equal(local.findings[0].path, name);
  assert.equal(local.scope.pathsIncluded, true);
  assert.ok(!JSON.stringify(redacted).includes('PRIVATE-NAME'));
  assert.ok(formatText(local).includes(JSON.stringify(name)));
});

test('Git fsmonitor hooks are disabled and inherited Git redirection is ignored', { skip: process.platform === 'win32' }, t => {
  const root = fixture(t);
  put(root, 'data.txt', accessKey());
  stage(root);
  const marker = join(root, 'UNEXPECTED-HOOK');
  put(root, 'fake-monitor.sh', `#!/bin/sh\ntouch '${marker}'\n`);
  execFileSync('chmod', ['+x', join(root, 'fake-monitor.sh')]);
  execFileSync('git', ['config', 'core.fsmonitor', join(root, 'fake-monitor.sh')], { cwd: root });
  const previous = process.env.GIT_DIR;
  process.env.GIT_DIR = join(root, 'PRIVATE-INVALID-REDIRECTION');
  try {
    const report = scanRepository({ root });
    assert.equal(report.status, 'complete');
    assert.equal(report.findings.length, 1);
    assert.equal(existsSync(marker), false);
  } finally {
    if (previous === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = previous;
  }
});

test('CLI exits zero with findings and emits parseable redacted JSON with empty stderr', t => {
  const root = fixture(t);
  put(root, 'source.txt', accessKey());
  stage(root);
  const result = runCli(['--root', root]);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'complete');
  assert.equal(report.findings.length, 1);
  assert.ok(!result.stdout.includes(accessKey()));
});

test('CLI errors do not echo private paths, invalid arguments or native error text', t => {
  const root = fixture(t);
  const invalid = 'PRIVATE-INVALID-ARGUMENT';
  for (const args of [
    ['--root', join(root, 'PRIVATE-NOT-FOUND')],
    ['--root', root, invalid], ['--format', invalid], ['--root'],
  ]) {
    const result = runCli(args);
    assert.equal(result.status, 2);
    assert.equal(result.stderr, '');
    assert.equal(JSON.parse(result.stdout).status, 'error');
    assert.ok(!result.stdout.includes(root));
    assert.ok(!result.stdout.includes(invalid));
    assert.ok(!result.stdout.includes('PRIVATE-NOT-FOUND'));
  }
});

test('unreadable repository and subdirectory roots are errors, not clean scans', t => {
  const root = fixture(t);
  mkdirSync(join(root, 'subdir'));
  assert.equal(scanRepository({ root: join(root, 'subdir') }).status, 'error');
  const notRepo = mkdtempSync(join(tmpdir(), 'ofroot-not-a-repo-'));
  t.after(() => rmSync(notRepo, { recursive: true, force: true }));
  const result = runCli(['--root', notRepo]);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stdout).errors[0].code, 'GIT_READ_FAILED');
});

test('CLI exits two when a skipped blob makes coverage incomplete', t => {
  const root = fixture(t);
  put(root, 'image.bin', Buffer.from([0, 1, 2]));
  stage(root);
  const result = runCli(['--root', root, '--format', 'text']);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /partial/);
  assert.match(result.stdout, /"binary":1/);
});
