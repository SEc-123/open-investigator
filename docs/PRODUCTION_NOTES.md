# Production Notes

## Recommended operating model

1. Run `oi scan -s 7d` in safe mode.
2. Run focused commands based on the case: `ip`, `login`, `web`, `java`, `per`, `ps`, `net`.
3. Use `-m inv` only when the sealed tools cannot answer a needed question.
4. Preserve the generated case directory as incident evidence.
5. Perform response actions through existing enterprise systems, not through `oi`.

## Privileges

Some sources require elevated privileges:

- Linux: `/var/log/secure`, `/var/log/audit/audit.log`, some cron/systemd/user home paths.
- Windows: Security Event Log, Sysmon, some registry/service/task metadata.

Run with enough privileges to read required logs, but do not grant more than necessary.

## Data sensitivity

Reports can contain IPs, usernames, command lines, paths, history excerpts, and log fragments. Secure `.oi/cases` accordingly.

## AI safety

The AI can request sealed investigation tools. It cannot directly mutate the system. In `inv` mode, any requested `ro.run` command still goes through the read-only policy and is audited.

## Failure modes

- Logs may be absent or rotated.
- Timezones and timestamp formats may differ across sources.
- Attackers may have tampered with host logs.
- Some commands may not exist on minimal systems.
- Windows event fields differ by version and policy.
- Java memory-shell confirmation may require explicitly approved JVM internal inspection or artifact collection.

The report’s evidence gaps section is designed to surface these limitations explicitly.

## Java deep investigation safety

Java memory-shell investigations are layered:

- Default `oi java` / `oi mem` is low-impact and does not attach to JVMs or create dumps.
- `--java-deep -m inv` enables JVM internal inspection. It may attach to JVMs with `jcmd`, `jstack`, or `jmap`; run only when approved for the affected production service.
- `--heap-dump` can create large HPROF files and may pause or pressure the target JVM. It writes under `.oi/cases/<case-id>/artifacts/jvm/<pid>/`.
- `--jfr-dump` attempts to export JFR data if a recording exists.
- Ordinary `oi sh` / `oi_ro_run` cannot create heap/JFR dumps; those commands are policy-blocked and must go through the explicit gated collectors.

Recommended sequence:

```bash
oi mem -s 14d
oi mem -s 14d -m inv --java-deep
oi mem -s 14d -m inv --java-deep --heap-dump   # only when approved
```
