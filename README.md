# OfRoot Repository Check

A free repository check for software teams, with optional checks for possible sensitive health data. Findings are for human review. The scanner does not block commits, change files or upload code and reports to OfRoot.

**Early release:** this is a deliberately limited scanner, released under the [MIT license](LICENSE). Review its coverage before using the results to make security decisions.

## Install from GitHub

In a separate tools directory, outside the repository you want to inspect:

```sh
npm install --ignore-scripts https://github.com/ofroot-tech/ofroot-repository-check/archive/refs/tags/v0.1.0.tar.gz
node node_modules/ofroot-repository-check/bin/ofroot-repo-check.mjs --root /path/to/your-repository
```

The versioned source and installation archive are distributed through [GitHub releases](https://github.com/ofroot-tech/ofroot-repository-check/releases). Review the source and version before installation. No npm registry account is required.

## Run locally

Requires Node.js 20 or newer and Git. Keep the reviewed scanner outside the repository being inspected.

```sh
node /path/to/repository-check/bin/ofroot-repo-check.mjs --root /path/to/your-repository
```

The scanner reads the **Git index**, the snapshot prepared by `git add`. It does not read current working files. New files and later edits enter scope only after you stage them yourself; the scanner never stages anything.

The default output is JSON. It identifies findings with opaque file IDs and line numbers, without matched values, source snippets or file paths.

```sh
# Inspect only changed staged entries instead of every tracked index entry.
node /path/to/repository-check/bin/ofroot-repo-check.mjs --root /path/to/your-repository --staged

# Opt into checks for possible sensitive health data.
node /path/to/repository-check/bin/ofroot-repo-check.mjs --root /path/to/your-repository --health-data

# Use a text report.
node /path/to/repository-check/bin/ofroot-repo-check.mjs --root /path/to/your-repository --format text
```

For local human investigation, `--include-paths` adds file paths to the report. Paths can themselves contain sensitive information. Keep that report private; the supplied agent skill and GitHub workflow do not enable this option.

The scanner writes its report to standard output. It does not create a report file automatically. If you save output yourself, choose a private location and apply your own retention rules.

## Install a reviewed local package

From this package directory:

```sh
npm test
npm pack
```

Install the resulting `.tgz` archive in a separate tools directory, outside the repository to be scanned:

```sh
npm install --ignore-scripts /path/to/ofroot-repository-check-0.1.0.tgz
./node_modules/.bin/ofroot-repo-check --root /path/to/your-repository
```

No OfRoot account, API key or model connection is required. The package has no runtime dependencies or install hooks. Installing Node.js, npm or other tooling is a separate operation with its own network behavior.

## What this prototype checks

- Common credential patterns.
- Selected JavaScript and PHP code patterns that need security review.
- Nearby quoted JSON-style patient identifier and clinical string values when `--health-data` is enabled. This check does not classify arbitrary prose or CSV records.

These are limited pattern checks. A match may be benign or synthetic, and a real issue may be missed. The prototype does not determine exploitability or replace a code review, security assessment or penetration test.

Health-data findings mean **possible sensitive health data requiring review**. The scanner cannot decide whether information is legally protected health information, whether disclosure occurred or whether a system complies with HIPAA. [HHS explains the context that determines PHI](https://www.hhs.gov/hipaa/for-professionals/special-topics/hipaa-ftc-act/index.html).

## Coverage and completion

The default scan reads all tracked entries in the Git index. `--staged` narrows this to changed staged entries. Neither mode reads unstaged edits, so edits made after staging do not change those results. The report describes its selection and coverage.

Unstaged edits, Git history, untracked files (including ignored untracked files), external services, runtime behavior and dependency advisory databases are outside this prototype's scope. Files already tracked in the index remain in scope even if they match `.gitignore`. It does not perform OCR or inspect images and other binary formats. A scan of the index does not check everything an AI assistant might read from the filesystem.

Limits are 1 MiB per file, 20 MiB in total, 5,000 files, 1,000 findings and a 30-second runtime budget. Skipped files, read errors and reached limits are reported. An incomplete scan must not be presented as a clean scan.

| Exit code | Meaning |
| --- | --- |
| `0` | The scan completed. Findings may still need review. |
| `2` | Invalid arguments, an error or incomplete coverage. Review the report. |

Finding severity does not change the exit code. This release is for reporting, not automatic merge enforcement. No findings means only that the enabled checks found no matches in the content they inspected.

## GitHub

[templates/github-workflow.yml](templates/github-workflow.yml) is a manual, non-blocking workflow example. Review and vendor the scanner at `.ofroot/repository-check`, then copy the workflow to `.github/workflows/ofroot-repository-check.yml`.

The template pins the checkout action, grants read-only repository access and prints the default redacted report. It does not upload artifacts, publish comments, use application secrets or run on pull requests. GitHub retains workflow logs according to your repository settings. Restrict access and retention as appropriate for your organization.

Run it only from a trusted ref containing the reviewed scanner. A copy of the scanner inside a repository can be modified like any other repository code. Before expanding this to pull requests, arrange a trusted scanner source and review the handling of untrusted changes.

## Claude Code and Codex

The shared [skill](skills/ofroot-repository-check/SKILL.md) runs the scanner and explains its default redacted report. Copy the `ofroot-repository-check` skill folder to either:

- `.agents/skills/ofroot-repository-check` for Codex.
- `.claude/skills/ofroot-repository-check` for Claude Code.

Install or locate the reviewed scanner separately. The skill does not download it automatically. See the official [Codex skills documentation](https://learn.chatgpt.com/docs/customization/overview#skills) and [Claude Code skills documentation](https://code.claude.com/docs/en/skills).

A skill does not prevent an assistant from reading other files or change its provider's data settings. Review what you plan to share with an AI service separately, including unstaged and ignored files that this prototype does not scan. The supplied skill instructs the assistant to read only the default redacted report and does not authorize source inspection, fixes, external uploads or communications.

## OfRoot services and AI discoverability

For help reviewing findings, [contact OfRoot](https://www.ofroot.technology/partners/staffing#partnership-inquiry) with a short, non-sensitive overview. Leave out credentials, patient records and raw reports. Reviews, remediation and specialist testing require agreed scope and authorization. Opening that page does not upload a report or start an engagement.

OfRoot's [AI Website Readiness Scanner](https://www.ofroot.technology/services/ai-audit) is a separate assessment of a public website. Repository findings are not combined into its score, uploaded to it or published in discovery metadata. Public AI discoverability and private repository security answer different questions.

## Development

```sh
npm test
```

Use synthetic fixtures for development and demonstrations. Do not add real credentials, patient records or client material to this package.
