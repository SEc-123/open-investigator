# What safety boundary should an AI incident investigation tool have?

AI can help incident responders move from a weak clue to a concrete evidence
plan. It can also become dangerous quickly if it is allowed to improvise on a
production host.

Open Investigator takes a narrow position: AI should start as a local,
read-only investigator.

Repository:

```text
https://github.com/SEc-123/open-investigator
```

Relevant page:

```text
https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/
```

## The problem

Incident response starts under uncertainty:

- a suspicious IP appears in logs
- a Java service looks strange
- a WebShell may exist
- root logged in at an unusual time
- a server "looks wrong" but nobody has a full hypothesis

This is exactly where AI planning can help. The model can decide that the next
useful evidence is auth context, process context, recent files, web logs,
network state, persistence, or Java process metadata.

But the same uncertainty makes mutation risky. Before the team understands the
case, the AI should not delete files, restart services, kill processes, disable
accounts, or block IPs.

## The boundary

Open Investigator gives the model sealed investigation tools:

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

In safe mode, the AI cannot call raw OS commands.

In investigator mode, it can request `oi_ro_run`, but that command path is
filtered by a read-only policy and logged. Commands that mutate the host are
blocked.

## What this enables

The model can still do useful work:

- start from an IP, user, path, process, web root, Java service, or vague clue
- collect evidence across multiple host surfaces
- branch based on observations
- record evidence IDs and command audit entries
- produce `report.md` and `report.json`
- explain which evidence is missing

The point is not to replace a responder. The point is to shorten the first-pass
evidence collection loop while keeping every action reviewable.

## What this refuses to do

Open Investigator does not:

- isolate hosts
- block IPs
- kill suspicious processes
- delete WebShells
- disable users
- restart services
- change firewall rules
- edit the registry
- install agents
- replace EDR, SIEM, or SOAR

Those are response actions, not first-pass investigation actions.

## Java memory-shell example

Java investigations show why the boundary matters.

Default Java checks are low impact:

```bash
oi java -s 14d
oi mem -s 14d
```

They inspect process command lines, JVM options, `-javaagent`, `-agentlib`,
JDWP, `Xbootclasspath`, `jps`, `jcmd VM.command_line`, web logs, recent
Java/web file changes, and related process or network context.

Deeper JVM inspection is explicit:

```bash
oi mem -s 14d -m inv --java-deep
```

Heavy artifacts are separate approvals:

```bash
oi mem -s 14d -m inv --java-deep --heap-dump
oi mem -s 14d -m inv --java-deep --jfr-dump
```

Ordinary `oi sh` and AI `oi_ro_run` cannot bypass those gates to create heap or
JFR dumps.

## A practical trust checklist

Before using any AI incident investigation tool on a real host, ask:

- Can the AI mutate the host?
- Can it run arbitrary shell?
- Are commands and denials logged?
- Are evidence records preserved separately from the summary?
- Are heavy diagnostics explicit?
- Does the report show evidence gaps?
- Can another responder reproduce or challenge the findings?

If the answer is unclear, the tool is not ready for production triage.

## Takeaway

AI incident response tooling should earn trust from the boundary inward. Start
with local evidence collection, sealed tools, audit logs, and explicit
non-goals. Add broader capabilities only when the team can reason about the
risk.

