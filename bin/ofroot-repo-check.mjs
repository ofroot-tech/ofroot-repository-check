#!/usr/bin/env node
import { scanRepository, formatText, VERSION } from '../lib/scan.mjs';

const help = `OfRoot Repository Check ${VERSION} (prototype)
Usage: ofroot-repo-check [--root REPOSITORY_ROOT] [--staged] [--health-data]
                         [--format json|text] [--include-paths]

Reads tracked Git index blobs, not working files. --staged selects changed
staged entries only. Does not stage files, execute repository code, make
network requests or alter source files. Findings are for human review.
Health-data checks are optional and limited to nearby quoted field patterns.
Default reports omit paths, matched values and code snippets. --include-paths
discloses relative paths for local review; do not send those reports to AI.
Exit 0: scan completed, including findings. Exit 2: incomplete scan or error.
No findings does not prove security, absence of PHI or HIPAA compliance.
`;

function parse(args) {
  const options = { format: 'json' };
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (seen.has(arg)) throw new Error('INVALID_ARGUMENTS');
    seen.add(arg);
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--version') options.version = true;
    else if (arg === '--staged') options.staged = true;
    else if (arg === '--health-data') options.healthData = true;
    else if (arg === '--include-paths') options.includePaths = true;
    else if (arg === '--root' || arg === '--format') {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error('INVALID_ARGUMENTS');
      options[arg === '--root' ? 'root' : 'format'] = value;
    } else throw new Error('INVALID_ARGUMENTS');
  }
  if (!['json', 'text'].includes(options.format)) throw new Error('INVALID_ARGUMENTS');
  return options;
}

process.stdout.on('error', () => { process.exitCode = 2; });
try {
  const options = parse(process.argv.slice(2));
  if (options.help) process.stdout.write(help);
  else if (options.version) process.stdout.write(`${VERSION}\n`);
  else {
    const report = scanRepository(options);
    process.stdout.write(options.format === 'text' ? formatText(report) : `${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = report.status === 'complete' ? 0 : 2;
  }
} catch {
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, status: 'error', errors: [{ code: 'INVALID_ARGUMENTS' }] })}\n`);
  process.exitCode = 2;
}
