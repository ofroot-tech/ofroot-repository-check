// Intentionally small, locally owned text rules. These are review signals,
// not a parser, data classifier, exploit test or complete secret detector.
const rules = [
  {
    id: 'credential-private-key', category: 'credentials', severity: 'high',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    message: 'Possible private key material.',
    remediation: 'Review locally. If real and exposed, revoke or rotate the key and remove it from the appropriate storage and history.',
  },
  {
    id: 'credential-aws-access-key', category: 'credentials', severity: 'high',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    message: 'Possible AWS access key identifier.',
    remediation: 'Confirm locally whether the identifier is real. Investigate exposure and rotate affected credentials when required.',
  },
  {
    id: 'credential-github-token', category: 'credentials', severity: 'high',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g,
    message: 'Possible GitHub access token.',
    remediation: 'Review locally. Revoke exposed real tokens and replace embedded values with an approved secret source.',
  },
  {
    id: 'credential-literal-assignment', category: 'credentials', severity: 'medium',
    pattern: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)["']?\s*[:=]\s*(["'])(?!\$\{|\{\{|<)[^"'\r\n]{12,200}\1/gi,
    message: 'Possible credential stored as a literal value.',
    remediation: 'Check whether this is a placeholder, test value or real credential. Move real credentials to an approved secret source and review exposure.',
  },
  {
    id: 'code-javascript-dynamic-execution', category: 'code-patterns', severity: 'medium',
    extensions: /\.(?:[cm]?js|jsx|tsx?)$/i,
    pattern: /(?<![.\w$])(?:eval|new\s+Function)\s*\(/g,
    message: 'Dynamic JavaScript execution needs review.',
    remediation: 'Trace the input locally. Avoid interpreting untrusted input as code; this text match alone does not establish a vulnerability.',
  },
  {
    id: 'code-node-shell-execution', category: 'code-patterns', severity: 'medium',
    extensions: /\.(?:[cm]?js|jsx|tsx?)$/i,
    pattern: /\b(?:child_process|childProcess)\s*\.\s*exec(?:Sync)?\s*\(/g,
    message: 'Node shell execution needs review.',
    remediation: 'Review inputs and shell interpolation locally. Prefer fixed commands and argument arrays when appropriate.',
  },
  {
    id: 'code-php-execution', category: 'code-patterns', severity: 'medium',
    extensions: /\.(?:php\d?|phtml)$/i,
    pattern: /\b(?:eval|shell_exec|system|passthru)\s*\(/gi,
    message: 'PHP code or command execution needs review.',
    remediation: 'Trace inputs locally and remove unsafe interpretation of untrusted values. This text match alone does not establish a vulnerability.',
  },
  {
    id: 'code-tls-verification-disabled', category: 'code-patterns', severity: 'medium',
    pattern: /\brejectUnauthorized["']?\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0\b/g,
    message: 'TLS certificate verification may be disabled.',
    remediation: 'Review the runtime configuration locally. Use trusted certificates and certificate verification for real connections.',
  },
];

export const RULE_IDS = Object.freeze(rules.map(rule => rule.id));
export const HEALTH_RULE_ID = 'health-identifier-with-clinical-field';

function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return starts;
}

function lineAt(starts, offset) {
  let low = 0, high = starts.length;
  while (low + 1 < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

export function inspectText(text, filename, healthData, limit) {
  const findings = [];
  const starts = lineStarts(text);
  const add = (rule, index) => {
    findings.push({
      ruleId: rule.id, category: rule.category, severity: rule.severity,
      line: lineAt(starts, index), message: rule.message, remediation: rule.remediation,
    });
  };
  for (const rule of rules) {
    if (rule.extensions && !rule.extensions.test(filename)) continue;
    rule.pattern.lastIndex = 0;
    for (let match; (match = rule.pattern.exec(text));) {
      add(rule, match.index);
      if (findings.length > limit) return findings;
    }
  }
  if (healthData) {
    // Deliberately narrow: quoted identifier and clinical field values within
    // 512 characters, in either order. No claim to cover CSV, images or free text.
    const identifiers = /["'](?:patient[_ -]?(?:name|id)|mrn|medical[_ -]?record[_ -]?(?:number|id))["']\s*:\s*["'][^"'\r\n]{2,200}["']/gi;
    const clinical = /["'](?:diagnosis|diagnoses|medication|prescription|icd[_ -]?(?:9|10)(?:[_ -]?code)?)["']\s*:\s*["'][^"'\r\n]{2,200}["']/i;
    for (let match; (match = identifiers.exec(text));) {
      const window = text.slice(Math.max(0, match.index - 512), match.index + match[0].length + 512);
      if (clinical.test(window)) {
        add({
          id: HEALTH_RULE_ID, category: 'possible-health-data', severity: 'medium',
          message: 'Possible sensitive health data requiring review.',
          remediation: 'Review locally whether nearby identifier and clinical values describe a real person. Replace inappropriate fixtures with synthetic data. Legal PHI classification requires context.',
        }, match.index);
        if (findings.length > limit) return findings;
      }
    }
  }
  return findings;
}
