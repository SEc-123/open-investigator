# Open Investigator Server IR Investigation Report

## 1. Investigation Conclusion

- Case: `case-20260528-220921-310179229`
- Investigation question: Production incident-response drill: suspected compromise of this Linux host by 203.0.113.77. Perform a read-only investigation around /tmp/oi_v015_ir_lab, /var/www/html/oi_v015_ir_lab, suspicious Python/Java processes, WebShell activity, SSH logins, persistence, historical commands, and network listeners; do not perform remediation. Finally, assess whether this tool can support rapid decision-making in a real incident-response scenario.
- Rule-based risk level: high
- Confidence: high
- Core assessment: 30 medium/high-risk findings were identified. The core findings include IOC hits for 203.0.113.77 across multiple sources. Total evidence count: 82. Overall risk: high. Confidence: high.

## 2. AI Investigator Overall Assessment

Conclusion: Based on the current evidence, this host shows a multi-stage intrusion or incident-response drill chain. The risk remains high, with high confidence. Key evidence: 203.0.113.77 appears in auth.log, nginx/apache access logs, and error logs; auth.check found 26 failed login events and one successful root login; web.check found suspicious Web access and recent script/JSP/PHP file changes under the Web root; proc.snap found interpreter processes running from /tmp and suspicious Java agent/JDWP-related processes; net.snap found listeners on port 4444, a common backdoor/reverse-shell port, and port 5005, the JDWP debug port; per.snap/svc.snap found suspicious content such as /tmp, C2, and javaagent in cron/systemd unit bodies; acct.snap found an authorized_keys entry summary; hist.check found historical traces involving curl/chmod/bash/nc; java.check/java.deep further confirmed JVM startup parameters and internal diagnostics containing keywords requiring review. Attack/abnormality chain: the external IOC appears in authentication and Web logs, followed by temporary-directory processes, suspicious Web files, persistence files, an SSH key, command history, and Java debug/agent indicators on the host. The evidence is mutually consistent and sufficient to support rapid triage. Evidence gaps: successful outbound communication was not proven; no packet/traffic retrospective analysis was performed; the real impact scope for the business system was not validated. Java deep is an explicit attach-based diagnostic capability and should be used only within an authorized production change window. Recommended manual next steps: before modifying original evidence, export the case, logs, and key file hashes; review the root login source, Web file origin, systemd/cron modification times, and authorized_keys change source; correlate with EDR, gateway, and bastion-host logs to confirm lateral movement and impact scope.

## 3. Investigation Scope

- Host: 09da61e8fadc
- OS: linux
- OS details: Debian GNU/Linux 13 (trixie)
- Time-range parameter: 1d
- Mode: inv
- Checks executed: host.info, logs.find, ai.ioc.find, ai.auth.check, ai.proc.snap, ai.net.snap, ai.web.check, ai.file.recent, ai.per.snap, ai.acct.snap, ai.java.check, ai.hist.check, ai.java.deep, ai.svc.snap, ai.mem.check, ai.linux.deep, ai.ro.run, guardrail.container.check, guardrail.pkg.check, guardrail.windows.deep

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
| F-020 | high | medium | JVM 4627 thread stack and lock information | ev-000046 |
| F-021 | high | medium | JVM 4627 heap class histogram | ev-000047 |
| F-022 | high | medium | JVM 4627 ClassLoader statistics | ev-000048 |
| F-023 | high | medium | JVM 4627 JVM system properties | ev-000049 |
| F-024 | high | medium | JVM 4627 JFR status | ev-000051 |
| F-025 | high | medium | Suspicious systemd unit content | ev-000056 |
| F-026 | medium | medium | Java process and startup parameters | ev-000058 |
| F-027 | high | medium | JVM 4627 startup parameters | ev-000060 |
| F-028 | medium | medium | Process snapshot | ev-000062 |
| F-029 | high | medium | Suspicious process behavior | ev-000064 |
| F-030 | high | high | Suspicious listening/debug port | ev-000066 |

## 5. Timeline

| Time | Event | Source | Evidence ID |
|---|---|---|---|
| 2026-05-28T22:09:37.828786095+00:00 | AI investigator requested tool | ioc.find | ev-000005 |
| 2026-05-28T22:09:37.828952205+00:00 | IOC hit: 203.0.113.77 | /var/log/auth.log | ev-000006 |
| 2026-05-28T22:09:37.829059650+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/access.log | ev-000007 |
| 2026-05-28T22:09:37.829139366+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/error.log | ev-000008 |
| 2026-05-28T22:09:37.829211505+00:00 | IOC hit: 203.0.113.77 | /var/log/apache2/access.log | ev-000009 |
| 2026-05-28T22:09:37.829304249+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/access.log | ev-000010 |
| 2026-05-28T22:09:37.829377943+00:00 | IOC hit: 203.0.113.77 | /var/log/nginx/error.log | ev-000011 |
| 2026-05-28T22:09:37.829495829+00:00 | IOC hit: 203.0.113.77 | /var/log/apache2/access.log | ev-000012 |
| 2026-05-28T22:09:37.829868303+00:00 | AI investigator requested tool | auth.check | ev-000013 |
| 2026-05-28T22:09:38.036944340+00:00 | AI investigator requested tool | web.check | ev-000023 |
| 2026-05-28T22:09:38.037742243+00:00 | Suspicious Web log activity | web.check logs | ev-000024 |
| 2026-05-28T22:09:38.041329197+00:00 | Recent suspicious file changes in Web directory | web.check files | ev-000025 |
| 2026-05-28T22:09:54.550638566+00:00 | SSH authorized_keys content review | authorized_keys | ev-000036 |

## 6. Evidence Details

The complete raw evidence is available in `evidence.jsonl`; the complete command audit trail is available in `commands.log`. The table below summarizes the first 120 evidence records.

| Evidence ID | Severity | Confidence | Category | Source | Summary |
|---|---|---|---|---|---|
| ev-000001 | info | high | host | host.info | Host profile: hostname=09da61e8fadc os=linux user=root |
| ev-000002 | info | high | logs | logs.find | Log source discovery: 18 log sources found; 10 currently readable |
| ev-000003 | info | high | ai_agent | ai.loop | AI tool-call loop started: model=chatgpt-manual-bridge-v015 max_rounds=4 max_actions_per_round=5 tool_count=19 mode=inv |
| ev-000004 | info | medium | ai_agent | ai.tool_calls | AI round 1 requested tools: requested_tool_calls=8 |
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
| ev-000017 | medium | medium | process | proc.snap | Process snapshot: process snapshot collected; suspicious samples: 6 |
| ev-000018 | low | high | process | proc.snap | Jupyter kernel temporary connection-file noise: one ipykernel temporary connection-file process was identified; this is more likely Notebook/Jupyter/sandbox runtime noise |
| ev-000019 | high | medium | process | proc.snap | Suspicious process behavior: temporary-directory execution, high-risk interpreters, network tools, or Java Agent/JDWP-related process indicators were found |
| ev-000020 | info | medium | ai_agent | net.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000021 | info | medium | network | net.snap | Network connection snapshot: the target IP `203.0.113.77` was not observed in network connections |
| ev-000022 | high | high | network | net.snap risk | Suspicious listening/debug port: 2 suspicious listening/debug ports were found, including 1 high-severity item; core ports: common backdoor/reverse-shell port (4444), JDWP debug port (5005) |
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
| ev-000045 | info | medium | ai_agent | java.deep | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000046 | high | medium | java | java.deep pid=4627 Thread.print -l | JVM 4627 thread stack and lock information: JVM internal diagnostic `Thread.print -l` completed; suspicious/needs-review keyword samples: 3 |
| ev-000047 | high | medium | java | java.deep pid=4627 GC.class_histogram | JVM 4627 heap class histogram: JVM internal diagnostic `GC.class_histogram` completed; suspicious/needs-review keyword samples: 7 |
| ev-000048 | high | medium | java | java.deep pid=4627 VM.classloader_stats | JVM 4627 ClassLoader statistics: JVM internal diagnostic `VM.classloader_stats` completed; suspicious/needs-review keyword samples: 3 |
| ev-000049 | high | medium | java | java.deep pid=4627 VM.system_properties | JVM 4627 JVM system properties: JVM internal diagnostic `VM.system_properties` completed; suspicious/needs-review keyword samples: 2 |
| ev-000050 | info | medium | java | java.deep pid=4627 VM.flags | JVM 4627 JVM flags: JVM internal diagnostic `VM.flags` completed; suspicious/needs-review keyword samples: 0 |
| ev-000051 | high | medium | java | java.deep pid=4627 JFR.check | JVM 4627 JFR status: JVM internal diagnostic `JFR.check` completed; suspicious/needs-review keyword samples: 2 |
| ev-000052 | info | high | java | java.deep summary | JVM internal diagnostics completed: Explicitly enabled JVM internal diagnostics were run against one Java PID. This capability attaches to the target JVM and is disabled by default. This run collected only text diagnostic output and did not create a heap/JFR dump unless java.dump was separately enabled. |
| ev-000053 | info | medium | ai_agent | svc.snap | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000054 | info | medium | service | systemctl list-units --type=service --all | systemd service runtime status: service information collected; suspicious service samples: 0 |
| ev-000055 | info | medium | service | systemctl list-unit-files --type=service | systemd service file status: service information collected; suspicious service samples: 0 |
| ev-000056 | high | medium | service | svc.snap unit-files | Suspicious systemd unit content: 5 suspicious samples were found in systemd unit file bodies |
| ev-000057 | info | medium | ai_agent | mem.check | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000058 | medium | medium | java | java.check process | Java process and startup parameters: Java process found; suspicious/needs-review parameter samples: 1 |
| ev-000059 | info | medium | java | jps -lv | JVM list: JVMs and parameters enumerated via jps |
| ev-000060 | high | medium | java | jcmd 4627 VM.command_line | JVM 4627 startup parameters: JVM 4627 VM.command_line read; suspicious keywords: 1 |
| ev-000061 | info | high | java | java.check limitation | Java memory-resident WebShell investigation boundary: By default, java.check performs only low-impact perimeter checks: process arguments, JVM lists, Web/middleware logs, and recent JSP/JAR/WAR/CLASS changes. To further confirm Filter/Listener/Interceptor/Controller-type memory-resident WebShells, explicitly enable --java-deep for JVM internal diagnostics. Heap/JFR evidence additionally requires --heap-dump or --jfr-dump, which are disabled by default. |
| ev-000062 | medium | medium | process | proc.snap | Process snapshot: process snapshot collected; suspicious samples: 6 |
| ev-000063 | low | high | process | proc.snap | Jupyter kernel temporary connection-file noise: one ipykernel temporary connection-file process was identified; this is more likely Notebook/Jupyter/sandbox runtime noise |
| ev-000064 | high | medium | process | proc.snap | Suspicious process behavior: temporary-directory execution, high-risk interpreters, network tools, or Java Agent/JDWP-related process indicators were found |
| ev-000065 | info | medium | network | net.snap | Network connection snapshot: current listener and connection state collected |
| ev-000066 | high | high | network | net.snap risk | Suspicious listening/debug port: 2 suspicious listening/debug ports were found, including 1 high-severity item; core ports: common backdoor/reverse-shell port (4444), JDWP debug port (5005) |
| ev-000067 | info | high | memory | mem.check limitation | Low-impact memory investigation boundary: This command collects perimeter evidence of memory anomalies: processes, network, JVM parameters, JVM lists, and recent class/package files. By default, it does not dump memory, inject via attach, or change the target process state. |
| ev-000068 | info | medium | ai_agent | linux.deep | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000069 | info | medium | linux_deep | last -a | Login history via last: Linux deep read-only check; samples requiring review: 0 |
| ev-000070 | info | medium | linux_deep | lastb -a | Failed-login history via lastb: Linux deep read-only check; samples requiring review: 0 |
| ev-000071 | info | medium | linux_deep | auditctl -s | auditd status: Linux deep read-only check; samples requiring review: 0 |
| ev-000072 | info | medium | linux_deep | lsmod | Kernel module list: Linux deep read-only check; samples requiring review: 0 |
| ev-000073 | info | medium | linux_deep | stat /etc/ld.so.preload | ld.so.preload metadata: Linux deep read-only check; samples requiring review: 0 |
| ev-000074 | info | medium | linux_deep | cat /etc/ld.so.preload | ld.so.preload content: Linux deep read-only check; samples requiring review: 0 |
| ev-000075 | medium | medium | linux_deep | find /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -ls | Recent files in temporary directories: Linux deep read-only check; samples requiring review: 12 |
| ev-000076 | medium | medium | linux_deep | find / -xdev -perm -4000 -type f -ls | SUID file baseline: Linux deep read-only check; samples requiring review: 1 |
| ev-000077 | info | medium | ai_agent | ro.run | AI investigator requested tool: AI requested this read-only investigation tool |
| ev-000078 | info | medium | readonly_shell | ps auxww | AI investigator supplemental read-only command evidence collection: AI requested this read-only investigation tool; allowed=true truncated=false |
| ev-000079 | info | medium | ai_agent | ai.final | AI investigator interim conclusion: the evidence is sufficient to form an initial incident-response assessment. 203.0.113.77 appears in authentication logs, Web access logs, and middleware error logs; auth.check shows 26 failed logins and one successful root login; web.check found logs and recent script files related to WebShell/upload/command parameters/JNDI/path traversal; proc.snap/net.snap found interpreter processes under /tmp, a listener on port 4444, a common backdoor port, and the JDWP debug port 5005; per.snap/svc.snap found cron/systemd unit bodies pointing to /tmp and suspicious parameters; acct.snap found an authorized_keys entry; java.check/java.deep found -javaagent/JDWP and suspicious keywords in JVM internal diagnostics; hist.check found curl/chmod/bash/nc-related historical traces. Overall assessment: this is a high-risk intrusion/drill scene with a multi-signal closed evidence loop. Risk: high. Confidence: high. In this scenario, the current tool can support rapid triage and decision-making: it can plan IOC, authentication, process, network, Web, file, persistence, account, Java deep, and read-only command validation from natural-language leads, and correlate evidence into an attack chain. Limitation: this remains a single-host read-only investigation and cannot replace full EDR timelines, traffic retrospective analysis, or manual review. Java deep causes attach-related impact and should remain explicitly gated. |
| ev-000080 | info | medium | container | container.check | Container runtime check: no docker/crictl/kubectl command was found, or the current environment is unavailable |
| ev-000081 | info | medium | package | dpkg-query -W | Package asset summary: package assets collected via dpkg-query -W; package count: 1355; truncated=false |
| ev-000082 | medium | medium | package | dpkg-query -W suspicious | Suspicious package/tool hit: 2 security/attack/tunneling/mining tools matched in package assets |

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
