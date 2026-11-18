import { execFileSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { isUtf8 } from 'node:buffer';
import { performance } from 'node:perf_hooks';
import { inspectText, RULE_IDS, HEALTH_RULE_ID } from './rules.mjs';

export const VERSION = '0.1.0';
export const LIMITS = Object.freeze({
  files: 5000, fileBytes: 1024 * 1024, totalBytes: 20 * 1024 * 1024,
  findings: 1000, milliseconds: 30000,
});

class ScanError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function git(root, args, maxBuffer, timeout) {
  // Do not inherit Git redirection/config injection, start hooks, invoke
  // fsmonitor, or lazily fetch missing objects from a partial clone.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  Object.assign(env, {
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_NO_LAZY_FETCH: '1', GIT_NO_REPLACE_OBJECTS: '1',
    GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_ALLOW_PROTOCOL: '',
  });
  try {
    return execFileSync('git', [
      '--no-pager', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=',
      '-c', 'diff.external=', '-c', 'core.quotePath=false', ...args,
    ], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'], timeout, maxBuffer });
  } catch {
    // Native Git errors may contain credentials, sensitive paths or content.
    throw new ScanError('GIT_READ_FAILED');
  }
}

function emptyReport(options, limits) {
  return {
    schemaVersion: 1,
    tool: { name: 'OfRoot Repository Check', version: VERSION },
    status: 'complete',
    scope: {
      selection: options.staged ? 'changed-staged-index' : 'tracked-index',
      healthData: !!options.healthData, pathsIncluded: !!options.includePaths,
      historyScanned: false, workingTreeScanned: false, untrackedFilesScanned: false,
      externalRequests: false,
    },
    rules: [...RULE_IDS, ...(options.healthData ? [HEALTH_RULE_ID] : [])],
    limits,
    coverage: {
      entriesSelected: 0, entriesConsidered: 0, filesScanned: 0, bytesRead: 0,
      skipped: { symlink: 0, submodule: 0, conflict: 0, oversized: 0, binary: 0, encoding: 0, unreadable: 0 },
      limitReached: false,
    },
    findings: [], errors: [],
    notice: 'Limited text-pattern review of a Git index snapshot. No findings does not establish security, absence of sensitive data, or HIPAA compliance.',
  };
}

export function scanRepository(options = {}) {
  const limits = { ...LIMITS, ...options.limits };
  const report = emptyReport(options, limits);
  const started = performance.now();
  const timeLeft = () => Math.max(1, Math.ceil(limits.milliseconds - (performance.now() - started)));
  try {
    let root;
    try {
      root = realpathSync(options.root ?? process.cwd());
      if (!statSync(root).isDirectory()) throw new Error();
    } catch { throw new ScanError('INVALID_ROOT'); }
    const top = git(root, ['rev-parse', '--show-toplevel'], 65536, timeLeft()).toString('utf8').replace(/\r?\n$/, '');
    if (realpathSync(top) !== root) throw new ScanError('REPOSITORY_ROOT_REQUIRED');
    const index = git(root, ['ls-files', '--stage', '-z'], 8 * 1024 * 1024, timeLeft());
    if (!isUtf8(index)) throw new ScanError('UNSUPPORTED_FILENAME_ENCODING');
    let changed;
    if (options.staged) {
      const names = git(root, ['diff', '--cached', '--name-only', '--no-ext-diff', '--no-textconv', '--diff-filter=ACMRTU', '-z', '--'], 8 * 1024 * 1024, timeLeft());
      if (!isUtf8(names)) throw new ScanError('UNSUPPORTED_FILENAME_ENCODING');
      changed = new Set(names.toString('utf8').split('\0').filter(Boolean));
    }
    const entries = index.toString('utf8').split('\0').filter(Boolean).map(value => {
      const tab = value.indexOf('\t');
      const [mode, oid, stage] = value.slice(0, tab).split(' ');
      if (tab < 0 || !/^[0-9a-f]{40,64}$/.test(oid ?? '')) throw new ScanError('INVALID_INDEX');
      return { mode, oid, stage, name: value.slice(tab + 1) };
    }).filter(entry => !changed || changed.has(entry.name));
    // Detect index changes during the scan instead of describing mixed
    // snapshots as complete. The returned data is still just the captured blobs.
    report.coverage.entriesSelected = entries.length;
    for (let i = 0; i < entries.length; i++) {
      if (i >= limits.files || performance.now() - started >= limits.milliseconds) {
        report.coverage.limitReached = true;
        break;
      }
      const entry = entries[i];
      const fileId = `file-${String(i + 1).padStart(6, '0')}`;
      report.coverage.entriesConsidered++;
      let skipped;
      if (entry.stage !== '0') skipped = 'conflict';
      else if (entry.mode === '120000') skipped = 'symlink';
      else if (entry.mode === '160000') skipped = 'submodule';
      else if (!['100644', '100755'].includes(entry.mode)) skipped = 'unreadable';
      if (skipped) { report.coverage.skipped[skipped]++; continue; }
      try {
        const sizeText = git(root, ['cat-file', '-s', entry.oid], 128, timeLeft()).toString('utf8').trim();
        const size = Number(sizeText);
        if (!Number.isSafeInteger(size) || size < 0) throw new ScanError('INVALID_OBJECT_SIZE');
        if (size > limits.fileBytes) { report.coverage.skipped.oversized++; continue; }
        if (report.coverage.bytesRead + size > limits.totalBytes) {
          report.coverage.limitReached = true;
          break;
        }
        const content = git(root, ['cat-file', 'blob', entry.oid], limits.fileBytes + 1, timeLeft());
        report.coverage.bytesRead += content.length;
        if (content.includes(0)) { report.coverage.skipped.binary++; continue; }
        if (!isUtf8(content)) { report.coverage.skipped.encoding++; continue; }
        report.coverage.filesScanned++;
        const remaining = limits.findings - report.findings.length;
        const findings = inspectText(content.toString('utf8'), entry.name, !!options.healthData, remaining);
        report.findings.push(...findings.slice(0, remaining).map(finding => ({
          fileId, ...(options.includePaths ? { path: entry.name } : {}), ...finding,
        })));
        if (findings.length > remaining) { report.coverage.limitReached = true; break; }
      } catch {
        report.coverage.skipped.unreadable++;
        report.errors.push({ code: 'OBJECT_READ_FAILED', fileId });
      }
    }
    const finalIndex = git(root, ['ls-files', '--stage', '-z'], 8 * 1024 * 1024, timeLeft());
    if (!index.equals(finalIndex)) report.errors.push({ code: 'INDEX_CHANGED_DURING_SCAN' });
    if (report.coverage.limitReached || report.errors.length || Object.values(report.coverage.skipped).some(Boolean)) {
      report.status = 'partial';
    }
  } catch (error) {
    report.status = 'error';
    report.errors.push({ code: error instanceof ScanError ? error.code : 'SCAN_FAILED' });
  }
  return report;
}

export function formatText(report) {
  const lines = [
    `OfRoot Repository Check ${VERSION}: ${report.status}`,
    `Scope: ${report.scope.selection}; health-data checks ${report.scope.healthData ? 'enabled' : 'disabled'}.`,
    `Scanned: ${report.coverage.filesScanned}; findings for review: ${report.findings.length}.`,
    'Scope excludes unstaged changes, untracked files (including ignored untracked files) and Git history.',
    report.notice,
  ];
  if (report.scope.pathsIncluded) lines.push('Local path disclosure enabled. Review paths before sharing this report.');
  for (const finding of report.findings) {
    lines.push(`${finding.fileId}:${finding.line} [${finding.severity}] ${finding.ruleId}: ${finding.message}`);
    if (finding.path !== undefined) lines.push(`  Local path: ${JSON.stringify(finding.path)}`);
    lines.push(`  Review: ${finding.remediation}`);
  }
  lines.push(`Coverage: ${JSON.stringify(report.coverage)}`);
  for (const error of report.errors) lines.push(`Scan error: ${error.code}${error.fileId ? ` (${error.fileId})` : ''}`);
  return `${lines.join('\n')}\n`;
}
