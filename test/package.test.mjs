import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';

const source = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('published archive installs offline and its installed CLI reports only redacted synthetic findings', t => {
  const root = mkdtempSync(join(tmpdir(), 'ofroot-package-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  // npm test supplies the CLI path; invoke it through Node to avoid Windows
  // shell wrappers and interpolation of generated paths.
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, 'Run this packaging test with npm test.');
  const npm = (args, cwd) => execFileSync(process.execPath, [npmCli, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const packed = JSON.parse(npm(['pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', root], source))[0];
  for (const item of packed.files) {
    assert.ok(['package.json', 'README.md', 'LICENSE'].includes(item.path) || /^(?:bin|lib|skills|templates)\//.test(item.path));
  }
  const install = join(root, 'install');
  const target = join(root, 'synthetic');
  mkdirSync(install); mkdirSync(target);
  npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', join(root, packed.filename)], install);
  const git = args => execFileSync('git', args, { cwd: target, stdio: 'pipe' });
  git(['init', '--quiet']);
  const secret = 'AKIA' + 'A'.repeat(16);
  writeFileSync(join(target, 'PRIVATE-FILENAME.js'), `const key = "${secret}";\neval(input);\n`);
  writeFileSync(join(target, 'PRIVATE-RECORD.json'), JSON.stringify({ patient_name: 'SYNTHETIC PERSON', diagnosis: 'SYNTHETIC CONDITION' }));
  git(['add', '--all', '--']);
  const indexBefore = readFileSync(join(target, '.git/index'));
  const binary = join(install, 'node_modules/ofroot-repository-check/bin/ofroot-repo-check.mjs');
  const result = spawnSync(process.execPath, [binary, '--root', target, '--health-data'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'complete');
  const categories = new Set(report.findings.map(finding => finding.category));
  for (const kind of ['credentials', 'code-patterns', 'possible-health-data']) assert.ok(categories.has(kind));
  for (const privateValue of [secret, 'SYNTHETIC PERSON', 'SYNTHETIC CONDITION', 'PRIVATE-FILENAME', target]) assert.ok(!result.stdout.includes(privateValue));
  assert.deepEqual(readFileSync(join(target, '.git/index')), indexBefore);
});
