# Community post drafts

Use these drafts as starting points. Adapt each one to the community. Do not
copy-paste the same link everywhere.

Disclose affiliation when posting:

```text
Disclosure: I maintain/build Open Investigator at Arvanta Cyber.
```

## Hacker News

Title:

```text
Show HN: Open Investigator - local read-only AI server investigation CLI
```

URL:

```text
https://github.com/SEc-123/open-investigator
```

First comment:

```text
Hi HN, I built Open Investigator because I wanted a safer shape for AI-assisted
server incident response.

It runs locally on Linux/Windows hosts and gives the model a sealed catalog of
read-only investigation tools instead of raw shell access. The AI can inspect
auth logs, accounts, processes, network, persistence, services, web logs, Java
processes, recent files, containers, packages, and shell history, then produce
case artifacts:

- evidence.jsonl
- commands.log
- report.json
- report.md

The explicit non-goal is remediation. It does not isolate hosts, block IPs, kill
processes, delete files, disable accounts, restart services, or change firewall
or registry state.

The part I would most like feedback on is the boundary: how much tool-directed
AI is useful for first-pass investigation while still keeping production hosts
safe?

Try it:

git clone https://github.com/SEc-123/open-investigator.git
cd open-investigator
cargo build --release
./target/release/oi scan -s 7d

Natural language example:

oi ask "Suspect this web server was compromised. Focus on nginx, Java processes,
recent logins, and persistence over the last 14 days." -s 14d

Happy to answer questions about the safety model, Java memory-shell checks, or
the AI tool loop.
```

Alternate HN title if Show HN feels too early:

```text
Open Investigator: local read-only AI server investigation through sealed tools
```

## Reddit technical post

Suggested communities:

- r/blueteamsec
- r/cybersecurity
- r/linuxadmin
- r/selfhosted
- r/java
- r/netsecstudents

Before posting:

- Read rules.
- Search for "self promotion", "tools", "open source", "show and tell".
- If uncertain, message moderators first.
- Prefer discussion posts over link drops.

Title:

```text
I am building a read-only AI incident investigation CLI. What safety boundary would you expect?
```

Body:

```text
Disclosure: I maintain Open Investigator at Arvanta Cyber. It is Apache-2.0:
https://github.com/SEc-123/open-investigator

I am trying to design a safer pattern for AI-assisted first-pass server
investigation.

The idea:

- run locally on the host being investigated
- expose only sealed read-only investigation tools to the model
- collect evidence from logs, auth, accounts, process, network, persistence,
  services, web logs, Java processes, recent files, packages, containers, and
  shell history
- write evidence.jsonl, commands.log, report.json, and report.md
- do not remediate or mutate the host

Safe mode has no raw shell. Investigator mode has a policy-filtered read-only
command fallback, but it blocks destructive commands and is audited.

The Java memory-shell path is layered:

1. Default: low-impact outer checks only.
2. --java-deep -m inv: explicit JVM internal diagnostics.
3. --heap-dump or --jfr-dump: explicit heavy artifacts into the case directory.

Question for people who do IR/DFIR/SRE work:

What would you require before trusting a local AI investigator for first-pass
triage? More command policy transparency? Better evidence IDs? Signed binaries?
Offline model support? Collector coverage? Something else?
```

Shorter Reddit comment when replying to a relevant thread:

```text
One pattern I have been experimenting with is to give AI a sealed investigation
toolbox instead of a shell. In Open Investigator the model can request things
like auth, process, network, persistence, web, Java, and recent-file checks, but
safe mode cannot mutate the host. The useful output is not just a summary; it is
evidence.jsonl plus report.md/report.json. Repo if useful:
https://github.com/SEc-123/open-investigator
```

## LinkedIn

Post:

```text
Normal server incident response often starts from weak clues:

- "This IP looks suspicious."
- "There may be a WebShell."
- "A Java service might have memory-shell indicators."
- "Root logged in at a weird time."

I published Open Investigator, an Apache-2.0 local AI server investigator for
Linux and Windows hosts.

The design goal is deliberately narrow: let AI help collect and correlate host
evidence without giving it remediation authority.

Open Investigator gives the model sealed read-only tools for auth, accounts,
processes, network, persistence, services, web logs, Java, recent files,
containers, packages, and history. It records evidence and produces:

- evidence.jsonl
- commands.log
- report.json
- report.md

It is not EDR, SOAR, cleanup automation, or cross-host correlation. It does not
kill processes, block IPs, delete files, disable accounts, restart services, or
change firewall/registry state.

Try it:
https://github.com/SEc-123/open-investigator

Website:
https://www.arvantacyber.com/open-investigator/

I would love feedback from incident responders, security engineers, SREs, and
people who operate production Java/Linux/Windows services.
```

Shorter LinkedIn variant:

```text
I published Open Investigator: a local, read-only AI server investigator for
Linux and Windows incident response.

The AI gets sealed investigation tools, not raw shell. It can collect evidence
from auth, accounts, process, network, persistence, web logs, Java services,
recent files, containers, packages, and history, then write report.md/report.json.

Apache-2.0 repo:
https://github.com/SEc-123/open-investigator

Website:
https://www.arvantacyber.com/open-investigator/
```

## X thread

Post 1:

```text
I published Open Investigator: an Apache-2.0 local AI server investigator for
Linux and Windows incident response.

It gives AI sealed read-only tools instead of raw shell.

https://github.com/SEc-123/open-investigator
```

Post 2:

```text
Start from weak clues:

- suspicious IP
- login anomaly
- WebShell clue
- Java service anomaly
- persistence clue
- vague "this host looks wrong"

Open Investigator turns that into local evidence collection and report output.
```

Post 3:

```text
Every run creates case artifacts:

- case.json
- evidence.jsonl
- commands.log
- report.json
- report.md

The goal is an auditable first-pass investigation, not a chat summary.
```

Post 4:

```text
Safety boundary:

- no host isolation
- no IP blocking
- no process killing
- no file deletion
- no account disabling
- no service restart
- no firewall/registry changes

It investigates. It does not remediate.
```

Post 5:

```text
Java memory-shell checks are layered:

1. default low-impact outer checks
2. explicit --java-deep -m inv internal JVM diagnostics
3. explicit --heap-dump / --jfr-dump artifacts

The ordinary read-only shell path cannot bypass these gates.
```

Post 6:

```text
Try it:

git clone https://github.com/SEc-123/open-investigator.git
cd open-investigator
cargo build --release
./target/release/oi scan -s 7d

Feedback from IR, DFIR, blue team, SRE, and Java operators is very welcome.
```

## Product Hunt

Use Product Hunt when the demo/readme/screenshots are ready and a personal
maker account is warmed up. Do not launch from a company/branded account.

Name:

```text
Open Investigator
```

Tagline:

```text
Local read-only AI server investigation for incident response
```

Description:

```text
Open Investigator is an Apache-2.0 CLI that lets an AI investigator collect
local Linux/Windows host evidence through sealed read-only tools and produce an
auditable incident report. Start from an IP, account, path, web root, Java
service, process, or vague anomaly. The runtime records evidence.jsonl,
commands.log, report.json, and report.md.
```

Maker comment:

```text
Hi Product Hunt, I built Open Investigator to explore a safer pattern for
AI-assisted server incident response.

The key design choice: AI gets a sealed investigation toolbox, not raw shell and
not remediation authority.

It can inspect auth, accounts, processes, network, persistence, services, web
logs, Java process clues, memory-shell outer indicators, recent files,
containers, packages, and command history. Every run creates case artifacts:
evidence.jsonl, commands.log, report.json, and report.md.

It deliberately does not isolate hosts, block IPs, kill processes, delete files,
disable accounts, restart services, or change firewall/registry state.

Open source repo:
https://github.com/SEc-123/open-investigator

I would love feedback from incident responders, security engineers, SREs, and
people who operate production Linux/Windows/Java servers.
```

Media checklist:

- `assets/open-investigator-mark.svg`
- terminal screenshot of `oi scan -s 7d`
- screenshot of a sample `.oi/cases/<case-id>/report.md`
- short demo video: install, run scan, open report

## Email outreach

Subject:

```text
Feedback request: local read-only AI server investigator
```

Body:

```text
Hi <name>,

I published Open Investigator, an Apache-2.0 local AI server investigator:

https://github.com/SEc-123/open-investigator

The design is intentionally bounded: the AI can call sealed read-only tools for
auth, process, network, persistence, web, Java, recent-file, package, container,
and history evidence, then produce evidence.jsonl/report.md/report.json. It does
not remediate or mutate the host.

I am looking for practitioner feedback, especially on:

- whether the read-only boundary is strict enough
- which collectors are missing
- whether the report format is useful for handoff
- what would make you comfortable trying it on a non-production host

No ask for promotion or voting. Just feedback if this overlaps your work.

Thanks,
<name>
```
