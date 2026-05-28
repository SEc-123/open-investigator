# Open Investigator (`oi`)

[![CI](https://github.com/SEc-123/open-investigator/actions/workflows/ci.yml/badge.svg)](https://github.com/SEc-123/open-investigator/actions/workflows/ci.yml)

Open Investigator is a **local, read-only AI server investigator** for Linux and Windows hosts.

It is designed for one job:

> Given a suspicious host, IP, account, path, web root, Java service, or vague anomaly report, let an AI investigator call sealed read-only tools, collect evidence, correlate findings, and generate an auditable investigation report.

It is not an EDR, SOAR, firewall controller, remediation tool, or cross-host platform. It does not isolate hosts, block IPs, kill processes, delete files, disable accounts, modify services, or change firewall/registry/system state.

## Open source project

Open Investigator is maintained by **Arvanta Cyber Inc**.

- Project feedback: [oi@arvantacyber.com](mailto:oi@arvantacyber.com)
- Website: [arvantacyber.com/open-investigator](https://www.arvantacyber.com/open-investigator)
- Source: [github.com/SEc-123/open-investigator](https://github.com/SEc-123/open-investigator)
- License: [Apache-2.0](LICENSE)

This repository is the open-source edition. Issues and pull requests are welcome for read-only collection coverage, AI tool-loop behavior, report quality, platform compatibility, and documentation.

## Product boundary

This repository contains only the Open Investigator product surface:

```text
open-investigator/
  crates/open-investigator-cli       # `oi` CLI
  crates/open-investigator-runtime   # local read-only AI investigation runtime
  docs/                              # user, architecture, runtime derivation, production docs
  examples/config.toml
  scripts/check.sh
```


## Runtime model

The runtime uses a bounded investigation loop: **agent turn -> tool calls -> tool observations -> more tool calls -> final answer**.

The model sees only Open Investigator tools:

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
oi_java_deep       # only in investigator mode and explicit --java-deep
oi_java_dump       # only when --java-deep plus --heap-dump/--jfr-dump is enabled
oi_file_recent
oi_container_check
oi_hist_check
oi_linux_deep
oi_windows_deep
oi_pkg_check
oi_ro_run          # only in investigator mode
```

`oi_net_snap` records network context and raises separate findings for risky listeners such as exposed JDWP `5005`, common backdoor ports, Docker TCP `2375`, kubelet `10250`, and JMX/RMI ports. `oi_pkg_check` uses lightweight package queries with fallbacks and diagnostics instead of depending on a full package-list dump.

The AI cannot call raw OS commands in safe mode. In investigator mode, `oi_ro_run` is still filtered by a read-only command policy and is fully audited.

## Build

```bash
cd open-investigator
cargo build --release
```

The binary is:

```bash
./target/release/oi
```

## Configure AI

Open Investigator uses an OpenAI-compatible Chat Completions endpoint with function/tool calling.

```bash
export OPEN_INVESTIGATOR_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"
export OPEN_INVESTIGATOR_MODEL="gpt-4.1-mini"
```

`OPENAI_API_KEY` is also accepted as a fallback.

Create a default config:

```bash
oi init
```

Default config path:

```text
~/.open-investigator/config.toml
```

Show configuration:

```bash
oi doc
oi ai show
```

If no API key is configured, deterministic guardrail collectors still run, but AI autonomous tool calling and AI synthesis are skipped.

## Development

Run the same checks used by CI:

```bash
./scripts/check.sh
cargo clippy --workspace -- -D warnings
```

Before opening a pull request, make sure the change stays within the read-only investigation boundary and does not add remediation, destructive shell, browser automation, or unrelated product surfaces.

## Quick use

Full local host investigation:

```bash
oi scan -s 7d
```

Natural-language investigation:

```bash
oi ask "怀疑这台服务器被入侵了，重点查最近 7 天的登录、Web、Java 进程和持久化" -s 7d
```

Suspicious IP:

```bash
oi ip 1.2.3.4 -s 7d
```

Login anomaly:

```bash
oi login -s 7d
oi login --ip 1.2.3.4 -s 7d
oi login --user root -s 7d
```

WebShell / web anomaly:

```bash
oi web -s 14d
oi web --root /var/www/html -s 14d
```

Java anomaly / memory-shell investigation:

```bash
# Default: low-impact peripheral evidence only.
oi java -s 14d
oi mem -s 14d

# JVM internal inspection: thread stacks, class histogram, classloader stats,
# VM flags/properties, and JFR status. This may attach to target JVMs, so it is explicit.
oi mem -s 14d -m inv --java-deep
oi java -s 14d -m inv --java-deep

# Heavy artifacts: write heap/JFR artifacts under .oi/cases/<case-id>/artifacts/jvm/<pid>/.
# Disabled by default; use only when operationally approved.
oi mem -s 14d -m inv --java-deep --heap-dump
oi mem -s 14d -m inv --java-deep --jfr-dump
```

Persistence:

```bash
oi per
```

Process and network:

```bash
oi ps
oi net
oi net --ip 1.2.3.4
```

Container, package, command-history, deeper platform checks:

```bash
oi cont
oi pkg
oi hist
oi deep -s 7d
```

Investigator mode with controlled read-only command fallback:

```bash
oi ask "深入排查这台主机是否存在持久化和 Java 内存马线索" -s 14d -m inv
oi sh "journalctl --since '7 days ago' | grep 1.2.3.4" -m inv
```

Policy testing:

```bash
oi pol test "find /tmp -type f -mtime -7"
oi pol test "rm -rf /tmp/a"
oi pol test "systemctl restart nginx"
```

## Output

Every run creates a case directory:

```text
.oi/cases/<case-id>/
  case.json        # input, mode, time window
  evidence.jsonl   # append-only evidence records with evidence_id
  commands.log     # allowed/denied command audit records
  report.json      # structured report
  report.md        # human-readable report
```

## Safety model

Default mode is `safe`:

```text
- sealed investigator tools only
- no raw shell
- no target-system modification
- writes only to .oi/cases and optional report output
```

`inv` mode adds `oi_ro_run`, but it still blocks commands that delete, modify, kill, restart, install, download, upload, edit registry, change firewall, change accounts, or execute interactive shells.

## Production notes

Run with appropriate read permissions for the host. Some logs require administrator/root rights to read, but the runtime remains logically read-only: it writes only case artifacts and command audit records.

For Java memory-shell investigations, `oi` intentionally performs low-impact peripheral checks by default. It does not heap dump or attach to production JVMs automatically.

When deeper evidence is required, the capability exists but must be explicitly enabled:

- `--java-deep` enables JVM internal inspection such as `Thread.print`, class histogram, classloader stats, VM flags/properties, and JFR status. This can attach to target JVMs and normally requires `-m inv`.
- `--heap-dump` writes a heap dump into the case artifact directory. It requires `--java-deep`.
- `--jfr-dump` attempts to export an existing JFR recording into the case artifact directory. It requires `--java-deep`.

Ordinary `oi sh` / `oi_ro_run` cannot bypass these gates to create heap or JFR dumps; JVM dump commands are blocked by policy and must use the explicit collectors.

## Responsible disclosure

Please report suspected vulnerabilities privately to [oi@arvantacyber.com](mailto:oi@arvantacyber.com). Include the affected version or commit, operating system, exact command used, observed behavior, and redacted case or command excerpts when relevant.
