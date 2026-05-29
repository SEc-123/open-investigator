# How to use a local AI investigator for read-only server incident response

Incident response often starts with weak, incomplete clues:

- "This host looks strange."
- "Did `1.2.3.4` attack this server?"
- "There may be a WebShell."
- "A Java service might have memory-shell indicators."
- "Root logged in at a weird time."

The hard part is not running one command. The hard part is deciding what to look
at next, keeping evidence tied to the case, and avoiding accidental production
changes while the investigation is still uncertain.

Open Investigator is an Apache-2.0 command-line project built for that first
pass. It runs on the host being investigated, gives AI a sealed set of read-only
investigation tools, records evidence, and produces a report.

Repository:

```text
https://github.com/SEc-123/open-investigator
```

Website:

```text
https://www.arvantacyber.com/open-investigator/
```

## The model

Open Investigator is not an EDR or SOAR platform. It does not isolate hosts,
block IPs, kill processes, delete files, disable accounts, restart services, or
change firewall or registry state.

Its job is narrower:

```text
incident clue -> read-only host evidence -> AI-guided follow-up -> report
```

The runtime exposes a bounded tool catalog to the model:

```text
oi_ioc_find
oi_auth_check
oi_acct_snap
oi_proc_snap
oi_net_snap
oi_per_snap
oi_svc_snap
oi_web_check
oi_java_check
oi_mem_check
oi_file_recent
oi_container_check
oi_hist_check
oi_linux_deep
oi_windows_deep
oi_pkg_check
```

In safe mode, the AI cannot call raw OS commands. In investigator mode, it can
request `oi_ro_run`, but that path is still filtered by a read-only command
policy and fully audited.

Every run creates case artifacts:

```text
.oi/cases/<case-id>/
  case.json
  evidence.jsonl
  commands.log
  report.json
  report.md
```

That gives the response team something to review instead of a loose terminal
scrollback.

## Install and configure

Build from source:

```bash
git clone https://github.com/SEc-123/open-investigator.git
cd open-investigator
cargo build --release
```

The binary is:

```bash
./target/release/oi
```

Optional AI configuration:

```bash
export OPEN_INVESTIGATOR_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"
export OPEN_INVESTIGATOR_MODEL="gpt-4.1-mini"
```

Without an API key, deterministic guardrail collectors still run. With an API
key, Open Investigator runs the AI-guided tool loop.

## Workflow 1: broad server triage

Use this when the only clue is "something is wrong":

```bash
oi scan -s 7d
```

This gathers a first-pass picture across host profile, logs, authentication,
accounts, processes, network, persistence, web activity, Java services,
containers, packages, command history, recent files, and deeper platform checks.

Expected result:

- suspicious findings with severity and confidence
- timeline-like evidence
- evidence gaps
- a readable `report.md`
- structured `report.json` for downstream use

## Workflow 2: ask a natural-language investigation question

You can start with the case as an operator would describe it:

```bash
oi ask "Suspect this web server was compromised. Focus on nginx, Java processes, recent logins, and persistence over the last 14 days." -s 14d
```

The AI turns that into a plan, calls sealed tools, observes the results, and
continues until it can produce an evidence-grounded answer.

This is the main difference from a fixed scanner. If a suspicious IP appears in
web logs, the next useful step may be process context, network context, file
changes, and persistence. If failed logins are followed by a successful login,
the next useful step may be account context and shell history. The loop can
branch from evidence.

## Workflow 3: suspicious IP

```bash
oi ip 1.2.3.4 -s 7d
```

This is for questions like:

```text
Did this IP touch the host? Did it login? Did it hit web paths? Is it still
connected? Did it relate to a process or persistence clue?
```

The investigation looks across IOC search, auth evidence, web logs, network
connections, process context, persistence, and services.

## Workflow 4: WebShell and web anomaly

```bash
oi web -s 14d
oi web --root /var/www/html -s 14d
```

Useful evidence includes:

- suspicious web requests
- upload and POST behavior
- command-execution keywords
- recently modified web files
- web-user shell processes
- outbound network context
- suspicious JSP, PHP, ASP, JAR, WAR, or CLASS changes

The output is not "clean or infected" magic. It is an evidence package that
shows what was observed and where manual confirmation is still needed.

## Workflow 5: Java service and memory-shell clues

Default Java checks are intentionally low impact:

```bash
oi java -s 14d
oi mem -s 14d
```

They inspect Java process command lines, JVM options, `-javaagent`, `-agentlib`,
JDWP, `Xbootclasspath`, `jps`, `jcmd VM.command_line`, web logs, recent Java/web
file changes, and related process/network context.

If a production team approves deeper JVM inspection:

```bash
oi mem -s 14d -m inv --java-deep
oi java -s 14d -m inv --java-deep
```

Heavy artifacts are a separate explicit decision:

```bash
oi mem -s 14d -m inv --java-deep --heap-dump
oi mem -s 14d -m inv --java-deep --jfr-dump
```

Open Investigator blocks ordinary `oi sh` or AI `oi_ro_run` from bypassing
these gates to create heap or JFR dumps.

## What this can achieve

Open Investigator can shorten the first-pass investigation loop:

- collect common host evidence without hand-building a case folder
- ask follow-up questions based on observed evidence
- keep AI actions constrained to an investigation toolbox
- preserve evidence IDs and command audit records
- create a report that another responder can review
- surface gaps instead of pretending certainty

It is especially useful when the first responder has a clue but not a full
hypothesis yet.

## What it deliberately does not do

Open Investigator does not:

- remediate
- isolate hosts
- kill suspicious processes
- delete web shells
- disable users
- change services
- block IPs
- modify firewall rules
- replace EDR
- correlate across a fleet

Those actions belong in existing response systems and human-approved playbooks.

## Try it

Build it and run a safe scan on a non-production host first:

```bash
git clone https://github.com/SEc-123/open-investigator.git
cd open-investigator
cargo build --release
./target/release/oi scan -s 7d
```

Then inspect:

```bash
oi case ls
oi rep
```

Feedback and collector contributions are welcome:

```text
oi@arvantacyber.com
https://github.com/SEc-123/open-investigator/issues
```
