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
- Java memory-shell confirmation may require deeper manual runtime inspection.

The report’s evidence gaps section is designed to surface these limitations explicitly.
