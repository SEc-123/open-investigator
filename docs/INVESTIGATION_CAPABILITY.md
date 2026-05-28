# Investigation Capability Matrix

## Local host coverage

| Area | Capability |
|---|---|
| Host profile | Hostname, OS, kernel/version, timezone, uptime, current user, admin/root status, IPs. |
| Logs | Linux `/var/log/*`, journal-related sources, nginx/apache/httpd/tomcat; Windows Security/System/Application/PowerShell/Sysmon/Defender/TerminalServices/TaskScheduler/IIS. |
| IOC | IP/domain/hash/path/user style searches across discovered logs and selected event channels. |
| Auth | Successful/failed login evidence, brute-force patterns, privileged-login clues, account context. |
| Accounts | Local users, groups, privileged users, authorized keys and admin/sudo indicators. |
| Processes | Command line, parent/child context where available, temp-dir execution, interpreters, web-user shell, Java agents/JDWP. |
| Network | Listeners, outbound connections, remote IP matching, process-related context, and risky debug/admin/backdoor listener scoring. |
| Persistence | cron, systemd/timers, services, scheduled tasks, Run/RunOnce, WMI, authorized_keys, profiles, `ld.so.preload`, SUID. |
| Web | Access/error logs, POST/upload, suspicious keywords, shell paths, recent web-root changes, web process context. |
| Java | Java processes, JVM options, `-javaagent`, `-agentlib`, JDWP, `jps`, `jcmd`, class/JAR/WAR/JSP changes, Java memory-shell outer indicators, and explicit deep JVM internal inspection when enabled. |
| Containers | Docker/CRI/Kubernetes local snapshots if tools exist. |
| Packages | Lightweight Linux/Windows package inventory, suspicious tool matches, and query fallback diagnostics. |
| History | Shell and PowerShell history indicators with basic sensitive-value redaction. |
| Report | Findings, timeline, evidence details, gaps, recommendations. |

## Deliberate exclusions

Open Investigator does not perform:

- host isolation
- IP blocking
- account disabling
- process killing
- service restart/stop/start
- file deletion or cleaning
- firewall changes
- automatic heap dump or full memory dump by default; heap/JFR artifact collection exists but must be explicitly enabled
- cross-host correlation

## Java memory-shell boundary

Open Investigator supports a layered Java memory-shell model:

1. **Default outer investigation**: Java process arguments, `-javaagent`, JDWP, classpath, web logs, recent JSP/JAR/WAR/CLASS changes, process/network context. This is low-impact and runs by default.
2. **Explicit JVM internal investigation**: enabled with `--java-deep -m inv`. It collects thread stacks, class histogram, classloader statistics, VM flags/properties, and JFR status using `jcmd`/`jstack`/`jmap` where available.
3. **Explicit heavy artifact collection**: enabled with `--heap-dump` or `--jfr-dump` in addition to `--java-deep`. Artifacts are written to the case directory and are never created by default.

This gives the project both outer and inner investigation capability without making invasive JVM inspection the default production behavior. Ordinary `oi sh` / `oi_ro_run` cannot bypass the artifact gates to create heap or JFR dumps.

## AI-driven investigation capability

When an API key is configured, the AI can choose tools dynamically from the sealed catalog. This allows a case to branch based on evidence:

- IOC hit in web logs -> web.check, proc.snap, net.snap, file.recent, per.snap.
- Failed logins followed by success -> auth.check, acct.snap, proc.snap, net.snap, per.snap.
- Suspicious Java options -> java.check, mem.check, web.check, file.recent; if explicitly enabled, java.deep and then java.dump for approved heavy artifacts.
- Unknown host anomaly -> auth.check, proc.snap, net.snap, per.snap, svc.snap, file.recent, linux.deep/windows.deep.

Every AI decision is recorded as evidence with the `ai_tool_plan` tag. Every AI-requested tool is recorded with the `ai_tool_request` tag. This makes the investigator loop auditable.
