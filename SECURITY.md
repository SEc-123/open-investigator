# Security Policy

Open Investigator is designed as a read-only local server investigation tool.

## Supported safety boundary

- Safe mode uses sealed investigation tools only.
- Investigator mode allows a controlled read-only command channel after policy validation.
- The tool does not implement remediation actions such as deleting files, killing processes, changing services, changing accounts, modifying firewall rules, or isolating hosts.

## Reporting security issues

Please report vulnerabilities privately through the project feedback address [oi@arvantacyber.com](mailto:oi@arvantacyber.com). Include:

- version/commit
- operating system
- exact command used
- expected behavior
- observed behavior
- relevant case/command log excerpts with secrets redacted

## Sensitive output

Case directories can contain logs, usernames, command lines, paths, and historical command excerpts. Treat `.oi/cases` as incident evidence and store it securely.
