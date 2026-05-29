# How to investigate a suspicious IP on a Linux server with read-only evidence

When an alert starts with only an IP address, the first response question is not
"is the host compromised?" It is narrower:

```text
Where did this IP appear, what changed around that time, and what evidence is
still missing?
```

Open Investigator is built for this first-pass loop. It runs locally on the
host, lets AI call sealed read-only investigation tools, and writes an auditable
case folder instead of giving the model raw shell access.

Repository:

```text
https://github.com/SEc-123/open-investigator
```

Relevant page:

```text
https://www.arvantacyber.com/open-investigator/local-ai-incident-response/
```

## Start with the IP

Build the tool:

```bash
git clone https://github.com/SEc-123/open-investigator.git
cd open-investigator
cargo build --release
```

Run an IP-focused investigation:

```bash
./target/release/oi ip 1.2.3.4 -s 7d
```

This asks a practical set of questions:

- Did the IP appear in auth logs?
- Did it hit web access logs?
- Is it connected now?
- Is it tied to a listening service or process?
- Did suspicious files, persistence entries, or account activity appear nearby?
- Which evidence categories were unavailable because of permissions or platform
  differences?

## Why this should be read-only

Early in triage, the responder often does not know whether the IP is an
attacker, scanner, customer, proxy, admin VPN, monitoring system, or false
positive.

That is why Open Investigator keeps the default boundary narrow:

- no raw shell for the AI in safe mode
- no host isolation
- no IP blocking
- no process killing
- no file deletion
- no account disabling
- no firewall or registry changes

The output is evidence and a report. Remediation belongs in separate,
human-approved response systems.

## What gets collected

For an IP investigation, useful evidence usually spans more than one log file:

- IOC search across readable logs and text surfaces
- authentication events and login anomalies
- process and network context
- services and persistence entries
- web logs and recent web-root changes
- package and container context when available
- recent files and command history signals

Open Investigator records observations into:

```text
.oi/cases/<case-id>/
  case.json
  evidence.jsonl
  commands.log
  report.json
  report.md
```

The report is not the source of truth by itself. The important property is that
the report can point back to evidence records and command audit entries.

## Follow-up with a natural-language question

If the IP appears in web logs or auth logs, ask a focused follow-up:

```bash
./target/release/oi ask "Investigate 1.2.3.4 on this host. Focus on auth logs, nginx access logs, related processes, outbound connections, recent web-root changes, and persistence over the last 7 days." -s 7d
```

The AI investigator can branch from observations:

- web hit -> suspicious paths -> recent files -> process context
- failed login burst -> successful login -> account context -> shell history
- active connection -> process owner -> service context -> persistence

That loop is the reason to use AI here. It can decide the next bounded evidence
request while staying inside the read-only tool catalog.

## What a useful result looks like

A useful first-pass report should include:

- where the IP appeared
- timestamps and source files where possible
- related users, processes, services, files, and network connections
- severity and confidence for findings
- evidence gaps and permission issues
- recommended manual confirmation steps

It should not pretend that one scan proves absence of compromise.

## When to use deeper mode

Open Investigator has an investigator mode for controlled read-only command
fallback:

```bash
./target/release/oi ask "Investigate 1.2.3.4 and explain any remaining evidence gaps." -s 7d -m inv
```

Even then, `oi_ro_run` is policy-filtered and audited. It blocks commands that
delete, modify, kill, restart, install, download, upload, edit registry, change
firewall state, change accounts, or execute interactive shells.

Use this only when the team accepts the broader read-only command surface.

## Takeaway

A suspicious IP is a starting point, not a verdict. The useful first step is to
collect linked host evidence, preserve the audit trail, and produce a report
another responder can challenge.

Open Investigator tries to make that first step faster while keeping the AI
inside a local, read-only investigation boundary.

