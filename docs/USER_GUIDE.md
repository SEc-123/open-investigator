# Open Investigator User Guide

## 1. What this tool is

Open Investigator (`oi`) is a local-server AI incident investigation tool. It runs on the server being investigated and performs read-only collection, AI-guided follow-up, correlation, and reporting.

It is built for cases such as:

- “怀疑这台服务器被入侵了”
- “怀疑 1.2.3.4 攻击过这台机器”
- “怀疑有 WebShell”
- “怀疑 Java 服务存在内存马线索”
- “怀疑存在异常登录或持久化”

It investigates the local host only. It does not perform cross-host correlation or execute remediation.

## 2. First-time setup

```bash
oi init
oi doc
```

Show AI configuration:

```bash
oi ai show
```

Optional AI configuration:

```bash
export OPEN_INVESTIGATOR_API_KEY="sk-..."
export OPEN_INVESTIGATOR_MODEL="gpt-4.1-mini"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

Without an API key, the tool still runs deterministic guardrail playbooks. With an API key, the tool runs an AI-first investigation loop.

## 3. How the AI investigates

`oi` does not simply run a fixed script and summarize it. The default execution is:

```text
minimal discovery -> AI chooses tools -> tools collect evidence -> AI chooses next tools -> guardrail baseline -> report
```

The AI receives a sealed OpenAI-compatible function-tool catalog. It calls `oi_*` tools directly; the runtime validates, executes, records evidence, and returns compact observations to the model.

Example AI tool call:

```json
{
  "type": "function",
  "function": {
    "name": "oi_auth_check",
    "arguments": "{\"ip\":\"1.2.3.4\",\"reason\":\"verify whether the suspicious IP appears in login logs\"}"
  }
}
```

The AI can call:

```text
oi_ioc_find, oi_auth_check, oi_acct_snap, oi_proc_snap, oi_net_snap,
oi_per_snap, oi_svc_snap, oi_web_check, oi_java_check, oi_mem_check,
oi_file_recent, oi_container_check, oi_hist_check, oi_linux_deep,
oi_windows_deep, oi_pkg_check
```

In `-m inv` mode only, it may also call:

```text
oi_ro_run
```

`ro.run` is still policy checked and audited.

## 4. Common workflows

### Broad triage

```bash
oi scan -s 7d
```

Use this when you only know “the host seems abnormal”. It covers host profile, logs, authentication, accounts, processes, network, persistence, web, Java, services, containers, packages, history, platform-deep checks, and recent files.

### Natural-language investigation

```bash
oi ask "怀疑这台 Web 服务器被入侵了，重点查 nginx、Java 进程、最近 14 天的登录和持久化" -s 14d
```

The AI decides the investigation path from the question and current evidence.

### Suspicious IP

```bash
oi ip 1.2.3.4 -s 7d
```

Checks logs, auth, web activity, current network connections, processes, persistence, and services related to the IP.

### Login anomaly

```bash
oi login -s 7d
oi login --ip 1.2.3.4 -s 7d
oi login --user root -s 7d
```

Looks for failed logins, successful logins, brute-force patterns, privileged login evidence, account context, and persistence context.

### WebShell

```bash
oi web -s 14d
oi web --root /var/www/html -s 14d
oi web --ip 1.2.3.4 -s 14d
```

Looks for suspicious web requests, POST/upload activity, command-execution keywords, recently modified web files, and process/network context.

### Java and memory-shell peripheral investigation

```bash
oi java -s 14d
oi mem -s 14d
```

Checks Java processes, JVM options, `-javaagent`, `-agentlib`, JDWP, `Xbootclasspath`, `jps`, `jcmd`, suspicious JAR/WAR/CLASS/JSP changes, and memory-shell evidence gaps.

It does **not** perform heap dump or invasive attach by default.

### Persistence

```bash
oi per
```

Linux: cron, systemd, timers, `authorized_keys`, `/etc/cron.*`, `/var/spool/cron`, `ld.so.preload`, SUID indicators.

Windows: scheduled tasks, services, Run/RunOnce registry, startup commands, WMI persistence, PowerShell profile indicators.

### Process and network

```bash
oi ps
oi net
oi net --ip 1.2.3.4
```

`oi net` records current listeners/connections and separately raises evidence for risky exposed listeners such as JDWP `5005`, common backdoor ports like `4444`, Docker TCP `2375`, kubelet `10250`, and JMX/RMI ports.

Package checks use lightweight package-manager queries with fallback diagnostics:

```bash
oi pkg
```

They summarize package inventory and highlight suspicious admin, tunnel, scanner, or mining tools without relying on full `dpkg -l` dumps.

### Controlled read-only shell

```bash
oi sh "ps auxww" -m inv
oi sh "journalctl --since '7 days ago' | grep 1.2.3.4" -m inv
```

`oi sh` is not a raw shell. It is denied in safe mode and validated in investigator mode.

## 5. Reports and cases

List cases:

```bash
oi case ls
```

Print latest report:

```bash
oi rep
```

Print a selected report:

```bash
oi rep case-20260527-103010
```

Case files:

```text
.oi/cases/<case-id>/
  case.json       # investigation input and mode
  evidence.jsonl  # evidence records with evidence_id
  commands.log    # allowed/denied command audit
  report.json     # structured report
  report.md       # human-readable report
```

## 6. Modes

### Safe mode

Default:

```bash
oi scan
```

- no controlled shell
- sealed read-only tools only
- no remediation action

### Investigator mode

```bash
oi scan -m inv
```

- sealed tools
- controlled read-only shell allowed
- every command audited
- dangerous commands denied

## 7. Policy examples

```bash
oi pol test "ps auxww"
oi pol test "journalctl --since '7 days ago' | grep 1.2.3.4"
oi pol test "rm -rf /tmp/x"
oi pol test "systemctl restart nginx"
```

Expected result: read-only commands allowed; modifying/destructive commands denied.

## 8. Operational recommendations

- Start with `oi scan -s 7d`.
- If there is a concrete IP, run `oi ip <ip> -s 7d`.
- For web hosts, run `oi web -s 14d` and include `--root` if known.
- For Java application hosts, run `oi java -s 14d` and `oi mem -s 14d`.
- Use `-m inv` only when sealed tools are not enough.
- Preserve `.oi/cases/<case-id>` as part of the incident record.
