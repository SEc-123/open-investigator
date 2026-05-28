# `oi` CLI

`oi` is the Open Investigator command-line interface.

Maintained by Arvanta Cyber Inc. Source: <https://github.com/SEc-123/open-investigator>.

## Build

```bash
cargo build --release
```

## Core commands

```bash
oi init
oi doc
oi ai show
oi ask "怀疑这台服务器被入侵了，查最近 7 天" -s 7d
oi scan -s 7d
oi ip 1.2.3.4 -s 7d
oi web -s 14d
oi java -s 14d
oi mem -s 14d
oi mem -s 14d -m inv --java-deep
oi per
oi ps
oi net
oi rep
```

## AI-first behavior

When `OPEN_INVESTIGATOR_API_KEY` is set, `oi` starts with minimal host/log discovery and then lets the AI investigator choose sealed read-only tools. Tool calls and plans are stored in `evidence.jsonl`.

Without an API key, `oi` runs deterministic guardrail playbooks.

## Safe vs inv

Default safe mode:

```bash
oi ask "查异常"
```

Investigator mode with controlled read-only shell:

```bash
oi ask "深入查异常" -m inv
oi sh "journalctl --since '7 days ago' | grep 1.2.3.4" -m inv
```

Dangerous commands are denied and audited.

## Java memory-shell depth

Default `oi java` and `oi mem` stay low-impact. JVM internal inspection requires an explicit gate:

```bash
oi java -s 14d -m inv --java-deep
oi mem -s 14d -m inv --java-deep
```

Heap/JFR artifacts require an additional explicit flag and are written under `.oi/cases/<case-id>/artifacts/jvm/<pid>/`:

```bash
oi mem -s 14d -m inv --java-deep --heap-dump
oi mem -s 14d -m inv --java-deep --jfr-dump
```
