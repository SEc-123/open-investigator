# Open Investigator Server IR Investigation Report

## 1. Investigation Conclusion

- Case: `case-20260528-221406-816221447`
- Investigation question: Production incident-response drill in safe mode: suspected compromise by 203.0.113.77. Use only safe-mode wrapped tools to investigate authentication, WebShell activity, suspicious processes, persistence, shell history, and network listeners, then provide a risk assessment.
- Rule-based risk level: high
- Confidence: high
- Core assessment: 28 medium/high-risk findings were identified. The core findings include IOC hits for 203.0.113.77 across multiple sources. Total evidence count: 74. Overall risk: high. Confidence: high.

## 2. AI Investigator Overall Assessment

Conclusion: In safe mode, the evidence also supports an initial high-risk, high-confidence assessment. Key evidence includes multiple hits for 203.0.113.77 in authentication and Web logs; failed logins appearing together with a successful root login; suspicious Web-log behavior involving cmd, JNDI, uploads, and path traversal; recent script/JSP/PHP file changes under the Web root; process and low-impact memory perimeter checks finding /tmp-path interpreters and Java agent/JDWP indicators; network checks finding risky listeners on ports 4444 and 5005; persistence checks finding suspicious cron/systemd file content; account checks finding an authorized_keys summary; and shell history containing curl/chmod/bash/nc-related traces. Attack/abnormality chain: authentication, Web, process, network, persistence, account, and command-history evidence corroborate one another, which is sufficient for rapid triage. Evidence gaps: safe mode cannot execute arbitrary read-only commands and did not perform java.deep attach, so its confirmation of JVM internals and file-content details is weaker than inv mode. Recommended manual next steps: export the case, preserve logs and key file hashes, perform targeted verification with inv/--java-deep under authorization, and correlate with EDR, gateway, bastion-host, and application logs to confirm impact scope.

## 3. Investigation Scope

- Host: 09da61e8fadc
- OS: linux
- OS details: Debian GNU/Linux 13 (trixie)
- Time-range parameter: 1d
- Mode: safe
- Checks executed: host.info, logs.find, ai.ioc.find, ai.auth.check, ai.proc.snap, ai.net.snap, ai.web.check, ai.file.recent, ai.per.snap, ai.acct.snap, ai.java.check, ai.hist.check, ai.svc.snap, ai.mem.check, ai.linux.deep, ai.pkg.check, ai.container.check, guardrail.windows.deep

## 4. Key Findings

| ID | Severity | Confidence | Finding | Evidence |
|---|---|---|---|---|
| F-001 | medium | high | IOC hit: 203.0.113.77 | ev-000006 |
| F-002 | medium | high | IOC hit: 203.0.113.77 | ev-000007 |
| F-003 | medium | high | IOC hit: 203.0.113.77 | ev-000008 |
| F-004 | medium | high | IOC hit: 203.0.113.77 | ev-000009 |
| F-005 | medium | high | IOC hit: 203.0.113.77 | ev-000010 |
| F-006 | medium | high | IOC hit: 203.0.113.77 | ev-000011 |
| F-007 | medium | high | IOC hit: 203.0.113.77 | ev-000012 |
| F-008 | high | high | Failed login events | ev-000014 |
| F-009 | medium | medium | Process snapshot | ev-000017 |
| F-010 | high | medium | Suspicious process behavior | ev-000019 |
| F-011 | high | high | Suspicious listening/debug port | ev-000022 |
| F-012 | high | medium | Suspicious Web log activity | ev-000024 |
| F-013 | high | medium | Recent suspicious file changes in Web directory | ev-000025 |
| F-014 | medium | medium | Recent suspicious file changes | ev-000028 |
| F-015 | high | medium | Suspicious persistence file content | ev-000033 |
| F-016 | medium | medium | SSH authorized_keys content review | ev-000036 |
| F-017 | medium | medium | Java process and startup parameters | ev-000038 |
| F-018 | high | medium | JVM 4627 startup parameters | ev-000040 |
| F-019 | medium | low | Suspicious command-history indicators | ev-000043 |
| F-020 | high | medium | Suspicious systemd unit content | ev-000048 |
| F-021 | medium | medium | Java process and startup parameters | ev-000050 |
| F-022 | high | medium | JVM 4627 startup parameters | ev-000052 |
| F-023 | medium | medium | Process snapshot | ev-000054 |
| F-024 | high | medium | Suspicious process behavior | ev-000056 |
| F-025 | high | high | Suspicious listening/debug port | ev-000058 |
| F-026 | medium | medium | Recent files in temporary directories | ev-000067 |
| F-027 | medium | medium | SUID file baseline | ev-000068 |
| F-028 | medium | medium | Suspicious package/tool hit | ev-000071 |

## 5. Timeline

| Time | Event | Source | Evidence ID |
|---|---|---|---|
| 2026-05-28T22:14:24.728931270+00:00 | AI investigator requested tool | ioc.find | ev-000005 |
| 2026-05-28T22:14:24.729072200+00:00 | IOC hit: 203.0.113.77 | /var/log/auth.log | ev-000006 |
| 2026-05-28T22:14:24.729174078+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/access.log | ev-000007 |
| 2026-05-28T22:14:24.729247426+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/error.log | ev-000008 |
| 2026-05-28T22:14:24.729352212+00:00 | IOC hit: 203.0.113.77 | /var/log/apache2/access.log | ev-000009 |
| 2026-05-28T22:14:24.729503936+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/access.log | ev-000010 |
| 2026-05-28T22:14:24.729686835+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/error.log | ev-000011 |
| 2026-05-28T22:14:24.729751260+00:00 | IOC hit: 203.0.113.77 | /var/log/apache2/access.log | ev-000012 |
| 2026-05-28T22:14:24.730100018+00:00 | AI investigator requested tool | auth.check | ev-000013 |
| 2026-05-28T22:14:24.936502950+00:00 | AI investigator requested tool | web.check | ev-000023 |
| 2026-05-28T22:14:24.937330327+00:00 | Suspicious Web log activity | web.check logs | ev-000024 |
| 2026-05-28T22:14:24.939942987+00:00 | Recent suspicious file changes in Web directory | web.check files | ev-000025 |
| 2026-05-28T22:14:41.357247719+00:00 | SSH authorized_keys content review | authorized_keys | ev-000036 |

## 6. Evidence Details

The complete raw evidence is available in `evidence.jsonl`; the complete command audit trail is available in `commands.log`. The table below summarizes the first 120 evidence records.

| Evidence ID | Severity | Confidence | Category | Source | Summary |
|---|---|---|---|---|---|
| ev-000001 | info | high | host | host.info | Host profile: hostname=09da61e8fadc os=linux user=root |
| ev-000002 | info | high | logs | logs.find | Log source discovery: 18 log sources found; 10 currently readable |
| ev-000003 | info | high | ai_agent | ai.loop | AI tool-call loop started: model=chatgpt-manual-bridge-v015 max_rounds=4 max_actions_per_round=5 tool_count=16 mode=safe |
| ev-000004 | info | medium | ai_agent | ai.tool_calls | AI round 1 requested tools: requested_tool_calls=5 |
| ev-000005 | info | medium | ai_agent | ioc.find | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000006 | medium | high | ioc | /var/log/auth.log | IOC hit: 203.0.113.77 — 27 records containing `203.0.113.77` were found in auth.log |
| ev-000007 | medium | high | ioc | /var/log/nginx/access.log | IOC hit: 203.0.113.77 — 4 records containing `203.0.113.77` were found in access.log |
| ev-000008 | medium | high | ioc | /var/log/nginx/error.log | IOC hit: 203.0.113.77 — 1 record containing `203.0.113.77` was found in error.log |
| ev-000009 | medium | high | ioc | /var/log/apache2/access.log | IOC hit: 203.0.113.77 — 1 record containing `203.0.113.77` was found in access.log |
| ev-000010 | medium | high | ioc | /var/log/nginx/access.log | IOC hit: 203.0.113.77 — 4 records containing `203.0.113.77` were found in access.log |
| ev-000011 | medium | high | ioc | /var/log/nginx/error.log | IOC hit: 203.0.113.77 — 1 record containing `203.0.113.77` was found in error.log |
| ev-000012 | medium | high | ioc | /var/log/apache2/access.log | IOC hit: 203.0.113.77 — 1 record containing `203.0.113.77` was found in access.log |
| ev-000013 | info | medium | ai_agent | auth.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000014 | high | high | auth | auth.check | Failed login events: 26 failed-login samples found; high-frequency source count: 1 |
| ev-000015 | low | medium | auth | auth.check | Successful login/session event: 1 successful-login or session-opening sample found |
| ev-000016 | info | medium | ai_agent | proc.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000017 | medium | medium | process | proc.snap | Process snapshot: process snapshot collected; suspicious samples: 4 |
| ev-000018 | low | high | process | proc.snap | Jupyter kernel temporary connection-file noise: one ipykernel temporary connection-file process was identified; this is more likely Notebook/Jupyter/sandbox runtime noise |
| ev-000019 | high | medium | process | proc.snap | Suspicious process behavior: temporary-directory execution, high-risk interpreters, network tools, or Java Agent/JDWP-related process indicators were found |
| ev-000020 | info | medium | ai_agent | net.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000021 | info | medium | network | net.snap | Network connection snapshot: the target IP `203.0.113.77` was not observed in network connections |
| ev-000022 | high | high | network | net.snap risk | Suspicious listening/debug port: 2 suspicious listening/debug ports were found, including 1 high-severity item; core ports: JDWP debug port (5005), common backdoor/reverse-shell port (4444) |
| ev-000023 | info | medium | ai_agent | web.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000024 | high | medium | web | web.check logs | Suspicious Web log activity: 12 suspicious access samples were found in Web/middleware logs |
| ev-000025 | high | medium | web | web.check files | Recent suspicious file changes in Web directory: 6 recently changed script/package files were found under the Web root or middleware directories |
| ev-000026 | info | medium | ai_agent | ai.tool_calls | AI round 2 requested tools: requested_tool_calls=5 |
| ev-000027 | info | medium | ai_agent | file.recent | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000028 | medium | medium | file | file.recent | Recent suspicious file changes: 10 recently changed suspicious files/paths were found in key directories |
| ev-000029 | info | medium | ai_agent | per.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000030 | info | medium | persistence | systemctl list-unit-files --type=service | systemd service files: systemd service files collected; suspicious samples: 0 |
| ev-000031 | info | medium | persistence | systemctl list-timers --all | systemd timers: systemd timers collected; suspicious samples: 0 |
| ev-000032 | info | medium | persistence | crontab -l | Current user crontab: current user crontab collected; suspicious samples: 0 |
| ev-000033 | high | medium | persistence | per.snap filesystem | Suspicious persistence file content: 2 suspicious content samples were found in cron/systemd-related files |
| ev-000034 | info | medium | ai_agent | acct.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000035 | info | high | account | acct.snap | Account and privileged-group snapshot: local account and sudo/wheel group information collected |
| ev-000036 | medium | medium | account | authorized_keys | SSH authorized_keys content review: 1 authorized_keys file/entry summary was found; public key text was hidden, and only the path, line number, key type, restriction options, and permission information were retained |
| ev-000037 | info | medium | ai_agent | java.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000038 | medium | medium | java | java.check process | Java process and startup parameters: Java process found; suspicious/needs-review parameter samples: 1 |
| ev-000039 | info | medium | java | jps -lv | JVM list: JVMs and parameters enumerated via jps |
| ev-000040 | high | medium | java | jcmd 4627 VM.command_line | JVM 4627 startup parameters: JVM 4627 VM.command_line read; suspicious keywords: 1 |
| ev-000041 | info | high | java | java.check limitation | Java memory-resident WebShell investigation boundary: By default, java.check performs only low-impact perimeter checks: process arguments, JVM lists, Web/middleware logs, and recent JSP/JAR/WAR/CLASS changes. To further confirm Filter/Listener/Interceptor/Controller-type memory-resident WebShells, explicitly enable --java-deep for JVM internal diagnostics. Heap/JFR evidence additionally requires --heap-dump or --jfr-dump, which are disabled by default. |
| ev-000042 | info | medium | ai_agent | hist.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000043 | medium | low | history | hist.check | Suspicious command-history indicators: 1 suspicious history-file sample was found in shell/PowerShell history; sensitive tokens were lightly redacted |
| ev-000044 | info | medium | ai_agent | ai.tool_calls | AI round 3 requested tools: requested_tool_calls=5 |
| ev-000045 | info | medium | ai_agent | svc.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000046 | info | medium | service | systemctl list-units --type=service --all | systemd service runtime status: service information collected; suspicious service samples: 0 |
| ev-000047 | info | medium | service | systemctl list-unit-files --type=service | systemd service file status: service information collected; suspicious service samples: 0 |
| ev-000048 | high | medium | service | svc.snap unit-files | Suspicious systemd unit content: 5 suspicious samples were found in systemd unit file bodies |
| ev-000049 | info | medium | ai_agent | mem.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000050 | medium | medium | java | java.check process | Java process and startup parameters: Java process found; suspicious/needs-review parameter samples: 1 |
| ev-000051 | info | medium | java | jps -lv | JVM list: JVMs and parameters enumerated via jps |
| ev-000052 | high | medium | java | jcmd 4627 VM.command_line | JVM 4627 startup parameters: JVM 4627 VM.command_line read; suspicious keywords: 1 |
| ev-000053 | info | high | java | java.check limitation | Java memory-resident WebShell investigation boundary: By default, java.check performs only low-impact perimeter checks: process arguments, JVM lists, Web/middleware logs, and recent JSP/JAR/WAR/CLASS changes. To further confirm Filter/Listener/Interceptor/Controller-type memory-resident WebShells, explicitly enable --java-deep for JVM internal diagnostics. Heap/JFR evidence additionally requires --heap-dump or --jfr-dump, which are disabled by default. |
| ev-000054 | medium | medium | process | proc.snap | Process snapshot: process snapshot collected; suspicious samples: 4 |
| ev-000055 | low | high | process | proc.snap | Jupyter kernel temporary connection-file noise: one ipykernel temporary connection-file process was identified; this is more likely Notebook/Jupyter/sandbox runtime noise |
| ev-000056 | high | medium | process | proc.snap | Suspicious process behavior: temporary-directory execution, high-risk interpreters, network tools, or Java Agent/JDWP-related process indicators were found |
| ev-000057 | info | medium | network | net.snap | Network connection snapshot: current listener and connection state collected |
| ev-000058 | high | high | network | net.snap risk | Suspicious listening/debug port: 2 suspicious listening/debug ports were found, including 1 high-severity item; core ports: JDWP debug port (5005), common backdoor/reverse-shell port (4444) |
| ev-000059 | info | high | memory | mem.check limitation | Low-impact memory investigation boundary: This command collects perimeter evidence of memory anomalies: processes, network, JVM parameters, JVM lists, and recent class/package files. By default, it does not dump memory, inject via attach, or change the target process state. |
| ev-000060 | info | medium | ai_agent | linux.deep | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000061 | info | medium | linux_deep | last -a | Login history via last: Linux deep read-only check; samples requiring review: 0 |
| ev-000062 | info | medium | linux_deep | lastb -a | Failed-login history via lastb: Linux deep read-only check; samples requiring review: 0 |
| ev-000063 | info | medium | linux_deep | auditctl -s | auditd status: Linux deep read-only check; samples requiring review: 0 |
| ev-000064 | info | medium | linux_deep | lsmod | Kernel module list: Linux deep read-only check; samples requiring review: 0 |
| ev-000065 | info | medium | linux_deep | stat /etc/ld.so.preload | ld.so.preload metadata: Linux deep read-only check; samples requiring review: 0 |
| ev-000066 | info | medium | linux_deep | cat /etc/ld.so.preload | ld.so.preload content: Linux deep read-only check; samples requiring review: 0 |
| ev-000067 | medium | medium | linux_deep | find /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -ls | Recent files in temporary directories: Linux deep read-only check; samples requiring review: 12 |
| ev-000068 | medium | medium | linux_deep | find / -xdev -perm -4000 -type f -ls | SUID file baseline: Linux deep read-only check; samples requiring review: 1 |
| ev-000069 | info | medium | ai_agent | pkg.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000070 | info | medium | package | dpkg-query -W | Package asset summary: package assets collected via dpkg-query -W; package count: 1355; truncated=false |
| ev-000071 | medium | medium | package | dpkg-query -W suspicious | Suspicious package/tool hit: 2 security/attack/tunneling/mining tools matched in package assets |
| ev-000072 | info | medium | ai_agent | container.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000073 | info | medium | container | container.check | Container runtime check: no docker/crictl/kubectl command was found, or the current environment is unavailable |
| ev-000074 | info | medium | ai_agent | ai.final | AI investigator interim conclusion: Safe-mode evidence is sufficient to form an initial assessment. Without using a free-form shell, the wrapped tools confirmed that 203.0.113.77 appears in authentication and Web logs, and identified failed logins plus one successful root login, suspicious Web access and recent script-file changes, temporary-directory/Java agent/JDWP processes, suspicious listeners on ports 4444 and 5005, cron/systemd persistence content, authorized_keys, shell history, and system deep-check indicators. Conclusion: risk high; confidence high. Safe mode can support initial triage. JVM internal diagnostics or more detailed path-level review require explicit authorization in inv mode. |

## 7. Evidence Gaps

- A Java memory-resident WebShell cannot be fully confirmed from external logs alone. If the risk is high, manually review thread stacks, class loaders, routing tables, JVM attach-tool output, or EDR memory evidence.

## 8. Recommended Manual Next Steps

- Execute isolation, blocking, or account-control actions through the enterprise EDR, bastion host, or firewall process. This tool does not directly perform remediation.
- Preserve relevant logs, suspicious files, process snapshots, and network connection snapshots to prevent evidence from being overwritten.
- Manually review recently changed files under the Web root and correlate them with access logs to confirm the entry point, upload point, and execution chain.
- Review anomalous login sources, successfully logged-in accounts, post-login activity, and credential-exposure risk.
- Manually review persistence points such as cron, systemd, scheduled tasks, services, Run registry keys, and authorized_keys.
- For anomalous Java processes, review Filter/Listener/Interceptor components, Controller routes, agents, JSP/JAR/WAR changes, and thread stacks in the context of the application.

## 9. Notes

By default, this tool performs only read-only investigation. It does not isolate hosts, block indicators, kill processes, delete files, modify accounts, or change firewall rules. Any remediation actions in this report are manual recommendations only.
