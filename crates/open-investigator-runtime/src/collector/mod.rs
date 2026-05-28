use crate::case::CaseContext;
use crate::model::{
    Confidence, EvidenceDraft, HostProfile, LogSource, OsKind, Severity, ToolRunOutput,
};
use crate::runner::CommandRunner;
use crate::store::EvidenceStore;
use crate::util::{
    collect_files_limited, command_exists, extension_lower, file_modified_after, path_string,
    read_to_string_lossy, since_cutoff, truncate_text,
};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub fn collect_host_profile(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
) -> Result<HostProfile> {
    let mut profile = HostProfile::unknown();
    profile.os = OsKind::current();

    if cfg!(windows) {
        let hostname = runner.run_builtin(store, "hostname", "host profile: hostname")?;
        profile.hostname = hostname.stdout.trim().to_string();
        let who = runner.run_builtin(store, "whoami", "host profile: current user")?;
        profile.current_user = Some(who.stdout.trim().to_string());
        let info = runner.run_builtin(
            store,
            "Get-ComputerInfo | Select-Object OsName,OsVersion,WindowsVersion,CsDomain,CsName",
            "host profile: Windows version",
        )?;
        profile.os_pretty = Some(truncate_text(info.stdout.trim(), 500));
        let tz = runner.run_builtin(
            store,
            "Get-TimeZone | Select-Object -ExpandProperty Id",
            "host profile: timezone",
        )?;
        profile.timezone = Some(tz.stdout.trim().to_string());
        let ips = runner.run_builtin(
            store,
            "Get-NetIPAddress | Select-Object IPAddress,AddressFamily,InterfaceAlias",
            "host profile: IP addresses",
        )?;
        profile.ip_addresses = ips
            .stdout
            .lines()
            .filter_map(extract_first_ipish)
            .collect::<Vec<_>>();
    } else {
        let hostname = runner.run_builtin(store, "hostname", "host profile: hostname")?;
        profile.hostname = hostname.stdout.trim().to_string();
        let kernel = runner.run_builtin(store, "uname -a", "host profile: kernel")?;
        profile.kernel = Some(kernel.stdout.trim().to_string());
        profile.os_pretty = linux_pretty_os();
        let tz = runner.run_builtin(store, "date +%Z", "host profile: timezone")?;
        profile.timezone = Some(tz.stdout.trim().to_string());
        let uptime = runner.run_builtin(store, "uptime", "host profile: uptime")?;
        profile.uptime = Some(uptime.stdout.trim().to_string());
        let user = runner.run_builtin(store, "whoami", "host profile: current user")?;
        profile.current_user = Some(user.stdout.trim().to_string());
        let id = runner.run_builtin(store, "id -u", "host profile: privilege check")?;
        profile.is_admin = Some(id.stdout.trim() == "0");
        let ips = runner.run_builtin(
            store,
            "ip -o addr show scope global",
            "host profile: IP addresses",
        )?;
        profile.ip_addresses = ips
            .stdout
            .lines()
            .filter_map(extract_first_ipish)
            .collect::<Vec<_>>();
    }

    store.set_host_name(profile.hostname.clone());
    store.add(EvidenceDraft {
        event_time: None,
        category: "host".to_string(),
        source: "host.info".to_string(),
        title: "主机画像".to_string(),
        summary: format!(
            "hostname={} os={} user={}",
            profile.hostname,
            profile.os,
            profile
                .current_user
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        ),
        raw_excerpt: Some(
            serde_json::to_string_pretty(&profile).unwrap_or_else(|_| "{}".to_string()),
        ),
        tags: vec!["host_profile".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(profile)
}

pub fn discover_logs(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
) -> Result<Vec<LogSource>> {
    let mut sources = Vec::new();
    if cfg!(windows) {
        for channel in windows_channels() {
            sources.push(LogSource {
                name: channel.replace('/', "_"),
                source_type: windows_channel_type(channel).to_string(),
                path: None,
                channel: Some(channel.to_string()),
                exists: true,
                readable: true,
                note: Some("Windows Event Log channel; availability verified lazily".to_string()),
            });
        }
        let iis_paths = ["C:/inetpub/logs/LogFiles", "C:/Windows/System32/LogFiles"];
        for path in iis_paths {
            let p = PathBuf::from(path);
            sources.push(path_source(&p, "iis", p.exists()));
        }
        let wevt =
            runner.run_builtin(store, "wevtutil el", "discover Windows Event Log channels")?;
        if !wevt.stdout.trim().is_empty() {
            store.add(EvidenceDraft {
                event_time: None,
                category: "logs".to_string(),
                source: "wevtutil el".to_string(),
                title: "Windows Event Log 通道发现".to_string(),
                summary: "已枚举 Windows Event Log 通道".to_string(),
                raw_excerpt: Some(truncate_text(&wevt.stdout, 4_000)),
                tags: vec!["log_source".to_string()],
                severity: Severity::Info,
                confidence: Confidence::High,
            })?;
        }
    } else {
        for (path, kind) in linux_log_candidates() {
            let p = PathBuf::from(path);
            sources.push(path_source(&p, kind, p.exists()));
        }
        for root in [
            "/var/log/nginx",
            "/var/log/apache2",
            "/var/log/httpd",
            "/opt/tomcat/logs",
        ] {
            let p = PathBuf::from(root);
            if p.exists() {
                sources.extend(discover_log_files_under(
                    &p,
                    if root.contains("tomcat") {
                        "java_web"
                    } else {
                        "web"
                    },
                ));
            }
        }
    }

    let readable = sources.iter().filter(|item| item.readable).count();
    let raw = serde_json::to_string_pretty(&sources).unwrap_or_else(|_| "[]".to_string());
    store.add(EvidenceDraft {
        event_time: None,
        category: "logs".to_string(),
        source: "logs.find".to_string(),
        title: "日志源发现".to_string(),
        summary: format!(
            "发现 {} 个日志源，其中 {} 个当前可读",
            sources.len(),
            readable
        ),
        raw_excerpt: Some(truncate_text(&raw, 8_000)),
        tags: vec!["log_source".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(sources)
}

pub fn search_ioc(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
    ioc: &str,
    since: &str,
) -> Result<()> {
    let mut total = 0usize;
    for source in sources {
        if let Some(path) = &source.path {
            if !source.readable {
                continue;
            }
            let matches = scan_file_for(path, ioc, 60)?;
            if matches.is_empty() {
                continue;
            }
            total += matches.len();
            let sev = if source.source_type.contains("auth") || source.source_type.contains("web") {
                Severity::Medium
            } else {
                Severity::Low
            };
            store.add(EvidenceDraft {
                event_time: None,
                category: "ioc".to_string(),
                source: path_string(path),
                title: format!("IOC 命中：{ioc}"),
                summary: format!(
                    "{} 中命中 {} 条包含 `{}` 的记录",
                    source.name,
                    matches.len(),
                    ioc
                ),
                raw_excerpt: Some(truncate_text(&matches.join("\n"), 10_000)),
                tags: vec!["ioc_match".to_string(), source.source_type.clone()],
                severity: sev,
                confidence: Confidence::High,
            })?;
        }
    }

    if cfg!(windows) && !ioc.trim().is_empty() {
        let escaped = ioc.replace('\'', "''");
        let cmd = format!(
            "Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {{$_.Message -like '*{escaped}*'}} | Select-Object -First 50 TimeCreated,Id,ProviderName,Message"
        );
        let out = runner.run_builtin(store, &cmd, "search IOC in Windows Security log")?;
        if !out.stdout.trim().is_empty() {
            total += out.stdout.lines().count();
            store.add(EvidenceDraft {
                event_time: None,
                category: "ioc".to_string(),
                source: "Windows Security EventLog".to_string(),
                title: format!("Windows EventLog IOC 命中：{ioc}"),
                summary: format!("Windows Security 日志中出现 `{ioc}`"),
                raw_excerpt: Some(truncate_text(&out.stdout, 10_000)),
                tags: vec!["ioc_match".to_string(), "windows_eventlog".to_string()],
                severity: Severity::Medium,
                confidence: Confidence::Medium,
            })?;
        }
    }

    if total == 0 {
        store.add(EvidenceDraft {
            event_time: None,
            category: "ioc".to_string(),
            source: "ioc.find".to_string(),
            title: format!("未发现 IOC：{ioc}"),
            summary: format!("在已发现的日志源中未找到 `{ioc}`；时间范围参数：{since}"),
            raw_excerpt: None,
            tags: vec!["negative_ioc_search".to_string()],
            severity: Severity::Info,
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn analyze_auth(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
    ip: Option<&str>,
    user: Option<&str>,
    _since: &str,
) -> Result<()> {
    let mut failed_by_ip: HashMap<String, usize> = HashMap::new();
    let mut success_lines = Vec::new();
    let mut failed_lines = Vec::new();
    for source in sources.iter().filter(|s| s.source_type.contains("auth")) {
        let Some(path) = &source.path else {
            continue;
        };
        for line in read_matching_lines(path, 5_000)? {
            let lower = line.to_ascii_lowercase();
            if ip.map(|value| !line.contains(value)).unwrap_or(false) {
                continue;
            }
            if user.map(|value| !line.contains(value)).unwrap_or(false) {
                continue;
            }
            if lower.contains("failed")
                || lower.contains("failure")
                || lower.contains("invalid user")
            {
                if let Some(src) = extract_last_ipv4(&line) {
                    *failed_by_ip.entry(src).or_default() += 1;
                }
                if failed_lines.len() < 100 {
                    failed_lines.push(format!("{}: {}", path.display(), line));
                }
            }
            if lower.contains("accepted")
                || lower.contains("session opened")
                || lower.contains("successful") && success_lines.len() < 100
            {
                success_lines.push(format!("{}: {}", path.display(), line));
            }
        }
    }

    if cfg!(windows) {
        let cmd = "Get-WinEvent -LogName Security -MaxEvents 1200 | Where-Object {$_.Id -in 4624,4625,4648,4672,4720,4728,4732} | Select-Object -First 800 TimeCreated,Id,ProviderName,Message";
        let out = runner.run_builtin(store, cmd, "analyze Windows authentication events")?;
        if !out.stdout.trim().is_empty() {
            store.add(EvidenceDraft {
                event_time: None,
                category: "auth".to_string(),
                source: "Windows Security EventLog".to_string(),
                title: "Windows 登录与权限事件".to_string(),
                summary: "收集 Security 4624/4625/4648/4672/4720/4728/4732 事件用于登录分析"
                    .to_string(),
                raw_excerpt: Some(truncate_text(&out.stdout, 16_000)),
                tags: vec!["auth_events".to_string(), "windows_security".to_string()],
                severity: Severity::Info,
                confidence: Confidence::Medium,
            })?;
        }
    }

    if !failed_lines.is_empty() {
        let high_volume = failed_by_ip.iter().any(|(_, count)| *count >= 20);
        store.add(EvidenceDraft {
            event_time: None,
            category: "auth".to_string(),
            source: "auth.check".to_string(),
            title: "失败登录事件".to_string(),
            summary: format!(
                "发现 {} 条失败登录样本；高频来源数：{}",
                failed_lines.len(),
                failed_by_ip.len()
            ),
            raw_excerpt: Some(truncate_text(&failed_lines.join("\n"), 12_000)),
            tags: vec!["failed_login".to_string(), "bruteforce_check".to_string()],
            severity: if high_volume {
                Severity::High
            } else {
                Severity::Low
            },
            confidence: Confidence::High,
        })?;
    }

    if !success_lines.is_empty() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "auth".to_string(),
            source: "auth.check".to_string(),
            title: "成功登录/会话事件".to_string(),
            summary: format!("发现 {} 条成功登录或会话开启样本", success_lines.len()),
            raw_excerpt: Some(truncate_text(&success_lines.join("\n"), 12_000)),
            tags: vec!["successful_login".to_string()],
            severity: Severity::Low,
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn snapshot_processes(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    let cmd = if cfg!(windows) {
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine"
    } else if cfg!(target_os = "macos") {
        "ps -axo pid,ppid,user,lstart,etime,comm,args"
    } else {
        "ps -eo pid,ppid,user,lstart,etime,comm,args --cols 240"
    };
    let out = runner.run_builtin(store, cmd, "process snapshot")?;
    let suspicious = suspicious_lines(
        &out.stdout,
        &[
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            " nc ",
            "ncat",
            "socat",
            "bash -c",
            "sh -c",
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "curl ",
            "wget ",
            "base64",
            "python -c",
            "perl -e",
            "javaagent",
            "jdwp",
        ],
        120,
    );
    let jupyter_noise = jupyter_kernel_noise_lines(&suspicious);
    let actionable_suspicious = suspicious
        .iter()
        .filter(|line| !jupyter_noise.iter().any(|noise| noise == *line))
        .cloned()
        .collect::<Vec<_>>();
    store.add(EvidenceDraft {
        event_time: None,
        category: "process".to_string(),
        source: "proc.snap".to_string(),
        title: "进程快照".to_string(),
        summary: format!("收集进程快照；可疑样本 {} 条", suspicious.len()),
        raw_excerpt: Some(truncate_text(&out.stdout, 20_000)),
        tags: vec!["process_snapshot".to_string()],
        severity: if actionable_suspicious.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        },
        confidence: Confidence::Medium,
    })?;
    if !jupyter_noise.is_empty() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "process".to_string(),
            source: "proc.snap".to_string(),
            title: "Jupyter kernel 临时连接文件噪声".to_string(),
            summary: format!(
                "识别到 {} 条 ipykernel 临时连接文件进程，更像 Notebook/Jupyter/沙箱运行噪声",
                jupyter_noise.len()
            ),
            raw_excerpt: Some(truncate_text(&jupyter_noise.join("\n"), 8_000)),
            tags: vec![
                "suspicious_process".to_string(),
                "jupyter_noise".to_string(),
            ],
            severity: Severity::Low,
            confidence: Confidence::High,
        })?;
    }
    if !actionable_suspicious.is_empty() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "process".to_string(),
            source: "proc.snap".to_string(),
            title: "可疑进程行为".to_string(),
            summary: "发现临时目录执行、高危解释器、网络工具或 Java Agent/JDWP 等可疑进程线索"
                .to_string(),
            raw_excerpt: Some(truncate_text(&actionable_suspicious.join("\n"), 12_000)),
            tags: vec!["suspicious_process".to_string()],
            severity: Severity::High,
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn snapshot_network(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    ip: Option<&str>,
) -> Result<()> {
    let cmd = if cfg!(windows) {
        "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
    } else if cfg!(target_os = "macos") && command_exists("lsof") {
        "lsof -nP -iTCP -sTCP:LISTEN"
    } else if cfg!(target_os = "macos") {
        "netstat -anv -p tcp"
    } else if command_exists("ss") {
        "ss -antup"
    } else {
        "netstat -antup"
    };
    let out = runner.run_builtin(store, cmd, "network snapshot")?;
    record_command_diagnostic(store, "network", "net.snap diagnostic", &out)?;
    let mut interesting = Vec::new();
    for line in out.stdout.lines() {
        if ip.map(|value| line.contains(value)).unwrap_or(false) {
            interesting.push(line.to_string());
            continue;
        }
        if (line.contains("ESTAB") || line.contains("ESTABLISHED") || line.contains("LISTEN"))
            && interesting.len() < 200
        {
            interesting.push(line.to_string());
        }
    }
    let ioc_hit = ip.map(|value| out.stdout.contains(value)).unwrap_or(false);
    let risky_listeners = risky_network_listeners(&out.stdout);
    store.add(EvidenceDraft {
        event_time: None,
        category: "network".to_string(),
        source: "net.snap".to_string(),
        title: "网络连接快照".to_string(),
        summary: if let Some(value) = ip {
            format!(
                "网络连接中{}命中目标 IP `{}`",
                if ioc_hit { "" } else { "未" },
                value
            )
        } else {
            "收集当前监听与连接状态".to_string()
        },
        raw_excerpt: Some(truncate_text(&interesting.join("\n"), 14_000)),
        tags: if ioc_hit {
            vec!["network_ioc_match".to_string()]
        } else {
            vec!["network_snapshot".to_string()]
        },
        severity: if ioc_hit {
            Severity::High
        } else {
            Severity::Info
        },
        confidence: Confidence::Medium,
    })?;
    if !risky_listeners.is_empty() {
        let severity = risky_listeners
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info);
        let tags = merge_network_tags(&risky_listeners);
        let raw = risky_listeners
            .iter()
            .map(|finding| finding.line.clone())
            .collect::<Vec<_>>()
            .join("\n");
        let summary = summarize_network_findings(&risky_listeners);
        store.add(EvidenceDraft {
            event_time: None,
            category: "network".to_string(),
            source: "net.snap risk".to_string(),
            title: "可疑监听/调试端口".to_string(),
            summary,
            raw_excerpt: Some(truncate_text(&raw, 14_000)),
            tags,
            severity,
            confidence: Confidence::High,
        })?;
    }
    Ok(())
}

pub fn snapshot_accounts(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if cfg!(windows) {
        for (cmd, title) in [
            ("Get-LocalUser", "本地用户"),
            ("Get-LocalGroupMember Administrators", "本地管理员组成员"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            if !out.stdout.trim().is_empty() {
                store.add(EvidenceDraft::info(
                    "account",
                    cmd,
                    title,
                    &truncate_text(&out.stdout, 1_000),
                ))?;
            }
        }
    } else {
        let passwd = runner.run_builtin(store, "getent passwd", "account snapshot: passwd")?;
        let sudo =
            runner.run_builtin(store, "getent group sudo", "account snapshot: sudo group")?;
        let wheel =
            runner.run_builtin(store, "getent group wheel", "account snapshot: wheel group")?;
        let mut raw = String::new();
        raw.push_str("[passwd]\n");
        raw.push_str(&passwd.stdout);
        raw.push_str("\n[sudo]\n");
        raw.push_str(&sudo.stdout);
        raw.push_str("\n[wheel]\n");
        raw.push_str(&wheel.stdout);
        store.add(EvidenceDraft {
            event_time: None,
            category: "account".to_string(),
            source: "acct.snap".to_string(),
            title: "账号与高权限组快照".to_string(),
            summary: "收集本地账号、sudo/wheel 组信息".to_string(),
            raw_excerpt: Some(truncate_text(&raw, 14_000)),
            tags: vec!["account_snapshot".to_string()],
            severity: Severity::Info,
            confidence: Confidence::High,
        })?;
        let auth_keys = find_authorized_keys();
        if !auth_keys.is_empty() {
            store.add(EvidenceDraft {
                event_time: None,
                category: "account".to_string(),
                source: "authorized_keys".to_string(),
                title: "SSH authorized_keys 发现".to_string(),
                summary: format!(
                    "发现 {} 个 authorized_keys 文件，建议复核是否存在攻击者公钥",
                    auth_keys.len()
                ),
                raw_excerpt: Some(auth_keys.join("\n")),
                tags: vec!["ssh_key_persistence".to_string()],
                severity: Severity::Medium,
                confidence: Confidence::Medium,
            })?;
        }
    }
    Ok(())
}

pub fn snapshot_persistence(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if cfg!(windows) {
        let commands = [
            ("Get-ScheduledTask", "Windows 计划任务"),
            ("Get-Service", "Windows 服务"),
            (
                "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                "Run 注册表 HKLM",
            ),
            (
                "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                "Run 注册表 HKCU",
            ),
        ];
        for (cmd, title) in commands {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &[
                    "temp",
                    "appdata",
                    "powershell",
                    "cmd.exe",
                    "wscript",
                    "http",
                ],
                80,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "persistence".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集 {}；可疑样本 {} 条", title, sus.len()),
                raw_excerpt: Some(truncate_text(
                    &if sus.is_empty() {
                        out.stdout
                    } else {
                        sus.join("\n")
                    },
                    12_000,
                )),
                tags: vec!["persistence_snapshot".to_string()],
                severity: if sus.is_empty() {
                    Severity::Info
                } else {
                    Severity::High
                },
                confidence: Confidence::Medium,
            })?;
        }
    } else {
        for (cmd, title) in [
            (
                "systemctl list-unit-files --type=service",
                "systemd 服务文件",
            ),
            ("systemctl list-timers --all", "systemd timers"),
            ("crontab -l", "当前用户 crontab"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &[
                    "/tmp/",
                    "/var/tmp/",
                    "/dev/shm/",
                    "curl",
                    "wget",
                    "nc ",
                    "bash -c",
                    "base64",
                ],
                80,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "persistence".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集 {}；可疑样本 {} 条", title, sus.len()),
                raw_excerpt: Some(truncate_text(
                    &if sus.is_empty() {
                        out.stdout
                    } else {
                        sus.join("\n")
                    },
                    12_000,
                )),
                tags: vec!["persistence_snapshot".to_string()],
                severity: if sus.is_empty() {
                    Severity::Info
                } else {
                    Severity::High
                },
                confidence: Confidence::Medium,
            })?;
        }
        let roots = [
            PathBuf::from("/etc/cron.d"),
            PathBuf::from("/etc/cron.daily"),
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/var/spool/cron"),
        ];
        let files = collect_files_limited(&roots, 3, 250);
        let mut sus = Vec::new();
        for file in files {
            if let Ok(raw) = read_to_string_lossy(&file, 120_000) {
                if raw.contains("/tmp/")
                    || raw.contains("curl")
                    || raw.contains("wget")
                    || raw.contains("/dev/shm/")
                {
                    sus.push(format!(
                        "{}\n{}",
                        file.display(),
                        truncate_text(&raw, 1_200)
                    ));
                }
            }
        }
        if !sus.is_empty() {
            store.add(EvidenceDraft {
                event_time: None,
                category: "persistence".to_string(),
                source: "per.snap filesystem".to_string(),
                title: "可疑持久化文件内容".to_string(),
                summary: format!("cron/systemd 相关文件中发现 {} 个可疑内容样本", sus.len()),
                raw_excerpt: Some(truncate_text(&sus.join("\n---\n"), 12_000)),
                tags: vec!["persistence_suspicious".to_string()],
                severity: Severity::High,
                confidence: Confidence::Medium,
            })?;
        }
    }
    Ok(())
}

pub fn analyze_web(
    store: &mut EvidenceStore,
    sources: &[LogSource],
    ctx: &CaseContext,
) -> Result<()> {
    let mut suspicious = Vec::new();
    let needles = [
        "post ",
        "upload",
        ".php",
        ".jsp",
        ".jspx",
        ".asp",
        ".aspx",
        "shell",
        "cmd=",
        "exec",
        "base64",
        "../",
        "/etc/passwd",
        "jndi:",
        "behinder",
        "godzilla",
        "冰蝎",
        "哥斯拉",
    ];
    for source in sources
        .iter()
        .filter(|s| s.source_type.contains("web") || s.source_type.contains("java"))
    {
        if let Some(path) = &source.path {
            for line in read_matching_lines(path, 8_000)? {
                let lower = line.to_ascii_lowercase();
                if ctx
                    .ioc
                    .as_ref()
                    .map(|ioc| !line.contains(ioc))
                    .unwrap_or(false)
                    && !needles.iter().any(|n| lower.contains(n))
                {
                    continue;
                }
                if needles.iter().any(|n| lower.contains(n))
                    || ctx
                        .ioc
                        .as_ref()
                        .map(|ioc| line.contains(ioc))
                        .unwrap_or(false)
                {
                    suspicious.push(format!("{}: {}", path.display(), line));
                }
                if suspicious.len() >= 160 {
                    break;
                }
            }
        }
    }
    if !suspicious.is_empty() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "web".to_string(),
            source: "web.check logs".to_string(),
            title: "Web 日志可疑行为".to_string(),
            summary: format!("Web/中间件日志中发现 {} 条可疑访问样本", suspicious.len()),
            raw_excerpt: Some(truncate_text(&suspicious.join("\n"), 16_000)),
            tags: vec!["web_suspicious".to_string(), "webshell_check".to_string()],
            severity: Severity::High,
            confidence: Confidence::Medium,
        })?;
    }

    let mut roots = default_web_roots();
    if let Some(root) = &ctx.web_root {
        roots.insert(0, root.clone());
    }
    let cutoff = since_cutoff(&ctx.since);
    let mut changed = Vec::new();
    for file in collect_files_limited(&roots, 6, 4_000) {
        if !file_modified_after(&file, cutoff) {
            continue;
        }
        let ext = extension_lower(&file).unwrap_or_default();
        if [
            "php", "jsp", "jspx", "asp", "aspx", "war", "jar", "class", "sh", "py",
        ]
        .contains(&ext.as_str())
        {
            changed.push(path_string(&file));
        }
        if changed.len() >= 200 {
            break;
        }
    }
    if !changed.is_empty() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "web".to_string(),
            source: "web.check files".to_string(),
            title: "Web 目录近期可疑文件变化".to_string(),
            summary: format!(
                "Web 根目录或中间件目录中发现 {} 个近期变化的脚本/包文件",
                changed.len()
            ),
            raw_excerpt: Some(truncate_text(&changed.join("\n"), 12_000)),
            tags: vec!["web_recent_file".to_string(), "webshell_check".to_string()],
            severity: Severity::High,
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn analyze_java(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    let proc_cmd = if cfg!(windows) {
        "Get-CimInstance Win32_Process | Where-Object {$_.Name -like '*java*'} | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine"
    } else if cfg!(target_os = "macos") {
        "ps -axo pid,ppid,user,lstart,etime,comm,args"
    } else {
        "ps -eo pid,ppid,user,lstart,etime,comm,args --cols 260"
    };
    let out = runner.run_builtin(store, proc_cmd, "java process survey")?;
    record_command_diagnostic(store, "java", "java.check diagnostic", &out)?;
    let java_processes = java_process_lines(&out.stdout).join("\n");
    if java_processes.trim().is_empty() {
        store.add(EvidenceDraft::info(
            "java",
            "java.check",
            "Java 进程检查",
            "未在进程快照中发现明显 Java 进程",
        ))?;
        return Ok(());
    }
    let sus = suspicious_lines(
        &java_processes,
        &[
            "-javaagent",
            "-agentlib",
            "jdwp",
            "xbootclasspath",
            "springloaded",
            "arthas",
            "jrebel",
            "attach",
            "tomcat",
            "jetty",
            "weblogic",
        ],
        120,
    );
    store.add(EvidenceDraft {
        event_time: None,
        category: "java".to_string(),
        source: "java.check process".to_string(),
        title: "Java 进程与启动参数".to_string(),
        summary: format!("发现 Java 进程；可疑/需复核参数样本 {} 条", sus.len()),
        raw_excerpt: Some(truncate_text(&java_processes, 18_000)),
        tags: vec!["java_process".to_string()],
        severity: if sus.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        },
        confidence: Confidence::Medium,
    })?;

    if command_exists("jps") {
        let jps = runner.run_builtin(store, "jps -lv", "java jps process list")?;
        record_command_diagnostic(store, "java", "java.check diagnostic", &jps)?;
        if !jps.stdout.trim().is_empty() {
            store.add(EvidenceDraft {
                event_time: None,
                category: "java".to_string(),
                source: "jps -lv".to_string(),
                title: "JVM 列表".to_string(),
                summary: "通过 jps 枚举 JVM 与参数".to_string(),
                raw_excerpt: Some(truncate_text(&jps.stdout, 10_000)),
                tags: vec!["java_jvm_list".to_string()],
                severity: Severity::Info,
                confidence: Confidence::Medium,
            })?;
        }
    }

    if command_exists("jcmd") {
        for pid in extract_pids_from_java_output(&java_processes)
            .into_iter()
            .take(5)
        {
            let cmd = format!("jcmd {pid} VM.command_line");
            let jcmd = runner.run_builtin(store, &cmd, "java VM.command_line")?;
            record_command_diagnostic(store, "java", "java.check diagnostic", &jcmd)?;
            let keywords = suspicious_lines(
                &jcmd.stdout,
                &[
                    "javaagent",
                    "agentlib",
                    "jdwp",
                    "xbootclasspath",
                    "attach",
                    "memshell",
                    "behinder",
                    "godzilla",
                ],
                40,
            );
            if !jcmd.stdout.trim().is_empty() {
                store.add(EvidenceDraft {
                    event_time: None,
                    category: "java".to_string(),
                    source: cmd,
                    title: format!("JVM {pid} 启动参数"),
                    summary: format!(
                        "读取 JVM {pid} VM.command_line；可疑关键词 {} 条",
                        keywords.len()
                    ),
                    raw_excerpt: Some(truncate_text(&jcmd.stdout, 8_000)),
                    tags: vec!["java_jcmd".to_string()],
                    severity: if keywords.is_empty() {
                        Severity::Info
                    } else {
                        Severity::High
                    },
                    confidence: Confidence::Medium,
                })?;
            }
        }
    }

    store.add(EvidenceDraft {
        event_time: None,
        category: "java".to_string(),
        source: "java.check limitation".to_string(),
        title: "Java 内存马调查边界".to_string(),
        summary: "默认 java.check 只做低扰动外围检查：进程参数、JVM 列表、Web/中间件日志、近期 JSP/JAR/WAR/CLASS 变化。需要进一步确认 Filter/Listener/Interceptor/Controller 型内存马时，可显式启用 --java-deep 进入 JVM 内部诊断；需要 heap/JFR 证据时还必须额外启用 --heap-dump 或 --jfr-dump，默认不开启。".to_string(),
        raw_excerpt: None,
        tags: vec!["java_memshell_gap".to_string(), "evidence_gap".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(())
}

pub fn recent_files(store: &mut EvidenceStore, ctx: &CaseContext) -> Result<()> {
    let cutoff = since_cutoff(&ctx.since);
    let roots = if let Some(path) = &ctx.path {
        vec![path.clone()]
    } else if cfg!(windows) {
        vec![
            PathBuf::from("C:/Windows/Temp"),
            PathBuf::from("C:/Users"),
            PathBuf::from("C:/ProgramData"),
            PathBuf::from("C:/inetpub/wwwroot"),
        ]
    } else {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/www"),
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/usr/local/bin"),
        ]
    };
    let mut changed = Vec::new();
    for file in collect_files_limited(&roots, 6, 6_000) {
        if !file_modified_after(&file, cutoff) {
            continue;
        }
        let path = path_string(&file);
        let ext = extension_lower(&file).unwrap_or_default();
        let suspicious_ext = [
            "sh", "py", "pl", "php", "jsp", "jspx", "asp", "aspx", "jar", "war", "class", "so",
            "dll", "exe",
        ]
        .contains(&ext.as_str());
        let suspicious_path = path.contains("/tmp/")
            || path.contains("/dev/shm/")
            || path.contains("/Temp/")
            || path.contains("AppData");
        if suspicious_ext || suspicious_path {
            changed.push(path);
        }
        if changed.len() >= 250 {
            break;
        }
    }
    store.add(EvidenceDraft {
        event_time: None,
        category: "file".to_string(),
        source: "file.recent".to_string(),
        title: "近期可疑文件变化".to_string(),
        summary: format!(
            "在重点目录中发现 {} 个近期变化的可疑文件/路径",
            changed.len()
        ),
        raw_excerpt: Some(truncate_text(&changed.join("\n"), 14_000)),
        tags: vec!["recent_file".to_string()],
        severity: if changed.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        },
        confidence: Confidence::Medium,
    })?;
    Ok(())
}

pub fn snapshot_services(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if cfg!(windows) {
        for (cmd, title) in [
            (
                "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName",
                "Windows 服务详情",
            ),
            ("Get-Service | Select-Object Name,DisplayName,Status,StartType", "Windows 服务状态"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &["temp", "appdata", "powershell", "cmd.exe", "wscript", "cscript", "rundll32", "http", "-enc", "base64"],
                100,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "service".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集服务信息；可疑服务样本 {} 条", sus.len()),
                raw_excerpt: Some(truncate_text(&if sus.is_empty() { out.stdout } else { sus.join("\n") }, 14_000)),
                tags: vec!["service_snapshot".to_string()],
                severity: if sus.is_empty() { Severity::Info } else { Severity::High },
                confidence: Confidence::Medium,
            })?;
        }
    } else {
        for (cmd, title) in [
            (
                "systemctl list-units --type=service --all",
                "systemd 服务运行状态",
            ),
            (
                "systemctl list-unit-files --type=service",
                "systemd 服务文件状态",
            ),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &[
                    "/tmp/",
                    "/var/tmp/",
                    "/dev/shm/",
                    "curl",
                    "wget",
                    "nc ",
                    "bash -c",
                    "base64",
                    "python -c",
                ],
                100,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "service".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集服务信息；可疑服务样本 {} 条", sus.len()),
                raw_excerpt: Some(truncate_text(
                    &if sus.is_empty() {
                        out.stdout
                    } else {
                        sus.join("\n")
                    },
                    14_000,
                )),
                tags: vec!["service_snapshot".to_string()],
                severity: if sus.is_empty() {
                    Severity::Info
                } else {
                    Severity::High
                },
                confidence: Confidence::Medium,
            })?;
        }
    }
    Ok(())
}

pub fn analyze_container(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    let mut ran = false;
    if command_exists("docker") {
        ran = true;
        for (cmd, title) in [
            ("docker ps --no-trunc", "Docker 容器列表"),
            ("docker images --digests", "Docker 镜像列表"),
            ("docker network ls", "Docker 网络列表"),
            ("docker volume ls", "Docker 卷列表"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &[
                    "privileged",
                    "host",
                    "/var/run/docker.sock",
                    "latest",
                    "crypt",
                    "miner",
                    "xmrig",
                    "/tmp/",
                    "curl",
                    "wget",
                ],
                100,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "container".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集容器运行时信息；可疑样本 {} 条", sus.len()),
                raw_excerpt: Some(truncate_text(
                    &if sus.is_empty() {
                        out.stdout
                    } else {
                        sus.join("\n")
                    },
                    12_000,
                )),
                tags: vec!["container_snapshot".to_string()],
                severity: if sus.is_empty() {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Medium,
            })?;
        }
    }
    if command_exists("crictl") {
        ran = true;
        for (cmd, title) in [
            ("crictl ps -a", "CRI 容器列表"),
            ("crictl images", "CRI 镜像列表"),
            ("crictl pods", "CRI Pod 列表"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            store.add(EvidenceDraft {
                event_time: None,
                category: "container".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: "收集 CRI 运行时只读信息".to_string(),
                raw_excerpt: Some(truncate_text(&out.stdout, 12_000)),
                tags: vec!["container_snapshot".to_string(), "cri".to_string()],
                severity: Severity::Info,
                confidence: Confidence::Medium,
            })?;
        }
    }
    if command_exists("kubectl") {
        ran = true;
        for (cmd, title) in [
            ("kubectl get pods -A -o wide", "Kubernetes Pod 列表"),
            ("kubectl get events -A", "Kubernetes 事件"),
        ] {
            let out = runner.run_builtin(store, cmd, title)?;
            let sus = suspicious_lines(
                &out.stdout,
                &[
                    "crash",
                    "backoff",
                    "error",
                    "failed",
                    "privileged",
                    "hostpath",
                    "crypt",
                    "miner",
                    "xmrig",
                ],
                100,
            );
            store.add(EvidenceDraft {
                event_time: None,
                category: "container".to_string(),
                source: cmd.to_string(),
                title: title.to_string(),
                summary: format!("收集 Kubernetes 只读信息；可疑样本 {} 条", sus.len()),
                raw_excerpt: Some(truncate_text(
                    &if sus.is_empty() {
                        out.stdout
                    } else {
                        sus.join("\n")
                    },
                    12_000,
                )),
                tags: vec!["container_snapshot".to_string(), "kubernetes".to_string()],
                severity: if sus.is_empty() {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Medium,
            })?;
        }
    }
    if !ran {
        store.add(EvidenceDraft::info(
            "container",
            "container.check",
            "容器运行时检查",
            "未发现 docker/crictl/kubectl 命令或当前环境不可用",
        ))?;
    }
    Ok(())
}

pub fn analyze_history(store: &mut EvidenceStore) -> Result<()> {
    let roots = if cfg!(windows) {
        let mut paths = Vec::new();
        if let Ok(appdata) = std::env::var("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
            );
        }
        paths
    } else {
        let mut paths = vec![
            PathBuf::from("/root/.bash_history"),
            PathBuf::from("/root/.zsh_history"),
        ];
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                paths.push(entry.path().join(".bash_history"));
                paths.push(entry.path().join(".zsh_history"));
                paths.push(entry.path().join(".mysql_history"));
            }
        }
        paths
    };
    let mut hits = Vec::new();
    for path in roots {
        if !path.exists() {
            continue;
        }
        let Ok(raw) = read_to_string_lossy(&path, 600_000) else {
            continue;
        };
        let mut local = Vec::new();
        for line in raw.lines().rev().take(2_000) {
            let lower = line.to_ascii_lowercase();
            if [
                "curl",
                "wget",
                "nc ",
                "ncat",
                "bash -c",
                "python -c",
                "perl -e",
                "base64",
                "chmod +x",
                "/tmp/",
                "/dev/shm/",
                "powershell",
                "downloadstring",
                "invoke-expression",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            {
                local.push(redact_sensitive_line(line));
            }
            if local.len() >= 60 {
                break;
            }
        }
        if !local.is_empty() {
            hits.push(format!(
                "{}\n{}",
                path.display(),
                local.into_iter().rev().collect::<Vec<_>>().join("\n")
            ));
        }
    }
    store.add(EvidenceDraft {
        event_time: None,
        category: "history".to_string(),
        source: "hist.check".to_string(),
        title: "命令历史可疑线索".to_string(),
        summary: format!(
            "在 shell/PowerShell 历史中发现 {} 个可疑历史文件样本；敏感令牌已做简单脱敏",
            hits.len()
        ),
        raw_excerpt: Some(truncate_text(&hits.join("\n---\n"), 14_000)),
        tags: vec![
            "history_check".to_string(),
            "sensitive_redacted".to_string(),
        ],
        severity: if hits.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        },
        confidence: Confidence::Low,
    })?;
    Ok(())
}

pub fn analyze_linux_deep(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if cfg!(windows) {
        return Ok(());
    }
    for (cmd, title, needles) in [
        (
            "last -a",
            "登录历史 last",
            vec!["still logged in", "root", "pts/", "ssh"],
        ),
        (
            "lastb -a",
            "失败登录历史 lastb",
            vec!["root", "ssh", "pts/"],
        ),
        (
            "auditctl -s",
            "auditd 状态",
            vec!["enabled", "backlog", "lost"],
        ),
        (
            "lsmod",
            "内核模块列表",
            vec!["hide", "rootkit", "diamorphine", "reptile"],
        ),
        (
            "stat /etc/ld.so.preload",
            "ld.so.preload 元数据",
            vec!["/etc/ld.so.preload"],
        ),
        (
            "cat /etc/ld.so.preload",
            "ld.so.preload 内容",
            vec![".so", "/tmp", "/dev/shm"],
        ),
        (
            "find /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -ls",
            "临时目录近期文件",
            vec!["/tmp/", "/var/tmp/", "/dev/shm/"],
        ),
        (
            "find / -xdev -perm -4000 -type f -ls",
            "SUID 文件基线",
            vec!["/tmp/", "/dev/shm/", "bash", "sh"],
        ),
    ] {
        let out = runner.run_builtin(store, cmd, title)?;
        let needle_refs = needles.to_vec();
        let sus = suspicious_lines(&out.stdout, &needle_refs, 80);
        store.add(EvidenceDraft {
            event_time: None,
            category: "linux_deep".to_string(),
            source: cmd.to_string(),
            title: title.to_string(),
            summary: format!("Linux 深度只读检查；命中需复核样本 {} 条", sus.len()),
            raw_excerpt: Some(truncate_text(
                &if sus.is_empty() {
                    out.stdout
                } else {
                    sus.join("\n")
                },
                12_000,
            )),
            tags: vec!["linux_deep".to_string()],
            severity: if sus.is_empty() {
                Severity::Info
            } else {
                Severity::Medium
            },
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn analyze_windows_deep(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    for (cmd, title, needles) in [
        (
            "Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 1200 | Where-Object {$_.Id -in 4103,4104} | Select-Object -First 800 TimeCreated,Id,ProviderName,Message",
            "PowerShell 4103/4104",
            vec!["encodedcommand", "downloadstring", "invoke-expression", "iex", "frombase64string", "new-object net.webclient"],
        ),
        (
            "Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1200 | Where-Object {$_.Id -in 1,3,7,11,22} | Select-Object -First 800 TimeCreated,Id,ProviderName,Message",
            "Sysmon 关键事件",
            vec!["powershell", "cmd.exe", "rundll32", "mshta", "regsvr32", "temp", "appdata", "http"],
        ),
        (
            "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name,Query,EventNamespace",
            "WMI EventFilter 持久化",
            vec!["powershell", "cmd", "http", "script"],
        ),
        (
            "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Select-Object Name,CommandLineTemplate,ExecutablePath",
            "WMI CommandLineEventConsumer 持久化",
            vec!["powershell", "cmd", "http", "script", "temp"],
        ),
        (
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User",
            "启动项 Win32_StartupCommand",
            vec!["powershell", "cmd", "temp", "appdata", "http"],
        ),
        ("Get-MpComputerStatus", "Microsoft Defender 状态", vec!["false", "disabled", "error"]),
    ] {
        let out = runner.run_builtin(store, cmd, title)?;
        let needle_refs = needles.to_vec();
        let sus = suspicious_lines(&out.stdout, &needle_refs, 80);
        store.add(EvidenceDraft {
            event_time: None,
            category: "windows_deep".to_string(),
            source: cmd.to_string(),
            title: title.to_string(),
            summary: format!("Windows 深度只读检查；命中需复核样本 {} 条", sus.len()),
            raw_excerpt: Some(truncate_text(&if sus.is_empty() { out.stdout } else { sus.join("\n") }, 14_000)),
            tags: vec!["windows_deep".to_string()],
            severity: if sus.is_empty() { Severity::Info } else { Severity::Medium },
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn analyze_packages(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    if cfg!(windows) {
        let cmd = "Get-ItemProperty HKLM:/Software/Microsoft/Windows/CurrentVersion/Uninstall/* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate";
        let out = runner.run_builtin(store, cmd, "Windows installed programs")?;
        record_package_diagnostic(store, &out)?;
        let records = parse_package_records(&out.stdout);
        record_package_inventory(store, cmd, &records, out.truncated)?;
        record_suspicious_packages(store, cmd, &records)?;
    } else if command_exists("dpkg-query") || command_exists("dpkg") {
        let result = run_dpkg_package_query(store, runner)?;
        let records = parse_package_records(&result.output.stdout);
        record_package_inventory(store, result.source, &records, result.output.truncated)?;
        record_suspicious_packages(store, result.source, &records)?;
    } else if command_exists("rpm") {
        let result = run_rpm_package_query(store, runner)?;
        let records = parse_package_records(&result.output.stdout);
        record_package_inventory(store, result.source, &records, result.output.truncated)?;
        record_suspicious_packages(store, result.source, &records)?;
    } else {
        store.add(EvidenceDraft {
            event_time: None,
            category: "package".to_string(),
            source: "pkg.check".to_string(),
            title: "包管理器检查".to_string(),
            summary: "未发现支持的包管理器（dpkg-query/dpkg/rpm），跳过包资产枚举".to_string(),
            raw_excerpt: None,
            tags: vec![
                "package_check".to_string(),
                "package_diagnostic".to_string(),
            ],
            severity: Severity::Info,
            confidence: Confidence::Medium,
        })?;
    }
    Ok(())
}

pub fn memory_low_impact(store: &mut EvidenceStore, runner: &mut CommandRunner) -> Result<()> {
    analyze_java(store, runner)?;
    memory_low_impact_without_java(store, runner)
}

pub fn memory_low_impact_without_java(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
) -> Result<()> {
    snapshot_processes(store, runner)?;
    snapshot_network(store, runner, None)?;
    store.add(EvidenceDraft {
        event_time: None,
        category: "memory".to_string(),
        source: "mem.check limitation".to_string(),
        title: "低扰动内存调查边界".to_string(),
        summary: "本命令收集内存异常的外围证据：进程、网络、JVM 参数、JVM 列表、近期类/包文件。默认不 dump 内存、不 attach 注入、不改变目标进程状态。".to_string(),
        raw_excerpt: None,
        tags: vec!["memory_low_impact".to_string(), "evidence_gap".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(())
}

/// Deep JVM internal inspection for Java memory-shell investigations.
///
/// This collector is intentionally gated by CaseContext. It can attach to the
/// target JVM with jcmd/jstack/jmap and may have operational impact, so it is
/// never enabled by default. It does not create heap/JFR dump files; artifact
/// creation is handled separately by `java_dump_artifacts` and requires an
/// additional explicit flag.
pub fn analyze_java_deep(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    ctx: &CaseContext,
    pid_filter: Option<&str>,
) -> Result<()> {
    if !ctx.java_deep_allowed() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java.deep gate".to_string(),
            title: "JVM 内部诊断未启用".to_string(),
            summary:
                "java.deep 已被请求，但当前 case 未显式开启 --java-deep；默认只执行低扰动外围检查。"
                    .to_string(),
            raw_excerpt: None,
            tags: vec!["java_deep_disabled".to_string(), "safety_gate".to_string()],
            severity: Severity::Info,
            confidence: Confidence::High,
        })?;
        return Ok(());
    }
    if ctx.java_deep_requires_inv && !ctx.mode.allows_readonly_shell() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java.deep gate".to_string(),
            title: "JVM 内部诊断需要 investigator 模式".to_string(),
            summary:
                "java.deep 需要 -m inv，以避免 safe 模式下对生产 JVM 进行 attach/jcmd 级别检查。"
                    .to_string(),
            raw_excerpt: None,
            tags: vec![
                "java_deep_requires_inv".to_string(),
                "safety_gate".to_string(),
            ],
            severity: Severity::Low,
            confidence: Confidence::High,
        })?;
        return Ok(());
    }

    let pids = java_target_pids(store, runner, pid_filter, ctx.java_deep_max_pids)?;
    if pids.is_empty() {
        store.add(EvidenceDraft::info(
            "java",
            "java.deep",
            "JVM 内部诊断",
            "未发现可用于深度 JVM 诊断的 Java PID",
        ))?;
        return Ok(());
    }

    let mut inspected = 0usize;
    for pid in pids {
        inspected += 1;
        if command_exists("jcmd") {
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "Thread.print -l",
                "线程栈与锁信息",
                &[
                    "ApplicationFilterChain",
                    "javax.servlet",
                    "jakarta.servlet",
                    "Filter",
                    "Listener",
                    "Interceptor",
                    "Controller",
                    "ClassLoader",
                    "defineClass",
                    "TemplatesImpl",
                    "bcel",
                    "ognl",
                    "Unsafe",
                    "behinder",
                    "godzilla",
                    "rebeyond",
                    "cmd.exe",
                    "/bin/sh",
                    "powershell",
                ],
            )?;
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "GC.class_histogram",
                "堆类直方图",
                &[
                    "Filter",
                    "Servlet",
                    "Listener",
                    "Interceptor",
                    "Controller",
                    "ClassLoader",
                    "TemplatesImpl",
                    "BCEL",
                    "CGLIB",
                    "Enhancer",
                    "Proxy",
                    "groovy",
                    "ognl",
                    "springframework",
                    "catalina",
                ],
            )?;
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "VM.classloader_stats",
                "ClassLoader 统计",
                &[
                    "WebappClassLoader",
                    "LaunchedURLClassLoader",
                    "URLClassLoader",
                    "ClassLoader",
                    "catalina",
                    "springframework",
                ],
            )?;
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "VM.system_properties",
                "JVM 系统属性",
                &[
                    "java.class.path",
                    "java.library.path",
                    "catalina.base",
                    "weblogic",
                    "jetty",
                    "spring",
                    "tomcat",
                ],
            )?;
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "VM.flags",
                "JVM flags",
                &[
                    "EnableDynamicAgentLoading",
                    "DisableAttachMechanism",
                    "TraceClassLoading",
                    "FlightRecorder",
                ],
            )?;
            run_jvm_internal_probe(
                store,
                runner,
                &pid,
                "JFR.check",
                "JFR 状态",
                &["Recording", "running", "duration", "settings"],
            )?;
        } else {
            if command_exists("jstack") {
                let out =
                    runner.run_builtin(store, &format!("jstack -l {pid}"), "java deep jstack")?;
                record_java_internal_output(
                    store,
                    &pid,
                    "jstack -l",
                    "线程栈与锁信息",
                    &out.stdout,
                    &out.stderr,
                    &[
                        "ApplicationFilterChain",
                        "javax.servlet",
                        "jakarta.servlet",
                        "Filter",
                        "Listener",
                        "Interceptor",
                        "ClassLoader",
                        "defineClass",
                        "TemplatesImpl",
                        "behinder",
                        "godzilla",
                        "cmd.exe",
                        "/bin/sh",
                    ],
                )?;
            }
            if command_exists("jmap") {
                let out = runner.run_builtin(
                    store,
                    &format!("jmap -histo {pid}"),
                    "java deep jmap histogram",
                )?;
                record_java_internal_output(
                    store,
                    &pid,
                    "jmap -histo",
                    "堆类直方图",
                    &out.stdout,
                    &out.stderr,
                    &[
                        "Filter",
                        "Servlet",
                        "Listener",
                        "Interceptor",
                        "Controller",
                        "ClassLoader",
                        "TemplatesImpl",
                        "BCEL",
                        "CGLIB",
                    ],
                )?;
            }
        }
    }

    store.add(EvidenceDraft {
        event_time: None,
        category: "java".to_string(),
        source: "java.deep summary".to_string(),
        title: "JVM 内部诊断已完成".to_string(),
        summary: format!("已对 {inspected} 个 Java PID 执行显式启用的 JVM 内部诊断。该能力会 attach 到目标 JVM，默认关闭；本次仅收集文本型诊断输出，不创建 heap/JFR dump，除非另外启用 java.dump。"),
        raw_excerpt: None,
        tags: vec!["java_deep".to_string(), "jvm_internal".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(())
}

/// Explicit JVM artifact collection. This may create large files and can have
/// operational impact; it is gated by --java-deep plus --heap-dump/--jfr-dump.
pub fn java_dump_artifacts(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    ctx: &CaseContext,
    pid_filter: Option<&str>,
) -> Result<()> {
    if !ctx.java_deep_allowed() || !ctx.java_artifacts_allowed() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java.dump gate".to_string(),
            title: "JVM 重型证据采集未启用".to_string(),
            summary:
                "java.dump 需要显式开启 --java-deep，并至少开启 --heap-dump 或 --jfr-dump。默认不创建 JVM dump。"
                    .to_string(),
            raw_excerpt: None,
            tags: vec!["java_dump_disabled".to_string(), "safety_gate".to_string()],
            severity: Severity::Info,
            confidence: Confidence::High,
        })?;
        return Ok(());
    }
    if ctx.java_deep_requires_inv && !ctx.mode.allows_readonly_shell() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java.dump gate".to_string(),
            title: "JVM 重型证据采集需要 investigator 模式".to_string(),
            summary: "heap/JFR dump 可能影响生产 JVM，必须使用 -m inv 并显式开启对应开关。"
                .to_string(),
            raw_excerpt: None,
            tags: vec![
                "java_dump_requires_inv".to_string(),
                "safety_gate".to_string(),
            ],
            severity: Severity::Low,
            confidence: Confidence::High,
        })?;
        return Ok(());
    }
    if !command_exists("jcmd") {
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java.dump".to_string(),
            title: "缺少 jcmd，无法创建 JVM artifact".to_string(),
            summary: "未发现 jcmd；无法执行 GC.heap_dump 或 JFR.dump。".to_string(),
            raw_excerpt: None,
            tags: vec!["java_dump_missing_jcmd".to_string()],
            severity: Severity::Low,
            confidence: Confidence::High,
        })?;
        return Ok(());
    }

    let pids = java_target_pids(store, runner, pid_filter, ctx.java_deep_max_pids)?;
    for pid in pids {
        let artifact_dir = ctx.case_dir.join("artifacts").join("jvm").join(&pid);
        fs::create_dir_all(&artifact_dir)?;

        let thread_out = runner.run_builtin(
            store,
            &format!("jcmd {pid} Thread.print -l"),
            "java artifact thread print",
        )?;
        let thread_path = artifact_dir.join("thread-print.txt");
        write_artifact_text(&thread_path, &thread_out.stdout)?;
        add_artifact_evidence(
            store,
            &pid,
            "thread-print",
            &thread_path,
            "JVM thread dump text artifact written to case directory",
        )?;

        let hist_out = runner.run_builtin(
            store,
            &format!("jcmd {pid} GC.class_histogram"),
            "java artifact class histogram",
        )?;
        let hist_path = artifact_dir.join("class-histogram.txt");
        write_artifact_text(&hist_path, &hist_out.stdout)?;
        add_artifact_evidence(
            store,
            &pid,
            "class-histogram",
            &hist_path,
            "JVM class histogram text artifact written to case directory",
        )?;

        if ctx.java_heap_dump {
            let heap_path = artifact_dir.join("heap.hprof");
            let cmd = format!("jcmd {pid} GC.heap_dump {}", shell_quote_path(&heap_path));
            let out = runner.run_diagnostic_artifact(store, &cmd, "explicit JVM heap dump")?;
            store.add(EvidenceDraft {
                event_time: None,
                category: "java".to_string(),
                source: cmd,
                title: format!("JVM {pid} heap dump artifact"),
                summary: format!(
                    "显式开启 --heap-dump 后创建 heap dump；exit={:?} path={}",
                    out.exit_code,
                    heap_path.display()
                ),
                raw_excerpt: Some(truncate_text(
                    &format!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr),
                    8_000,
                )),
                tags: vec![
                    "java_heap_dump".to_string(),
                    "artifact".to_string(),
                    "high_impact".to_string(),
                ],
                severity: Severity::High,
                confidence: Confidence::High,
            })?;
        }

        if ctx.java_jfr_dump {
            let jfr_path = artifact_dir.join("recording.jfr");
            let check = runner.run_builtin(
                store,
                &format!("jcmd {pid} JFR.check"),
                "java JFR check before dump",
            )?;
            let cmd = format!(
                "jcmd {pid} JFR.dump filename={}",
                shell_quote_path(&jfr_path)
            );
            let out = runner.run_diagnostic_artifact(store, &cmd, "explicit JVM JFR dump")?;
            store.add(EvidenceDraft {
                event_time: None,
                category: "java".to_string(),
                source: cmd,
                title: format!("JVM {pid} JFR dump artifact"),
                summary: format!(
                    "显式开启 --jfr-dump 后尝试导出 JFR；exit={:?} path={}",
                    out.exit_code,
                    jfr_path.display()
                ),
                raw_excerpt: Some(truncate_text(
                    &format!(
                        "JFR.check:\n{}\nstdout:\n{}\nstderr:\n{}",
                        check.stdout, out.stdout, out.stderr
                    ),
                    10_000,
                )),
                tags: vec![
                    "java_jfr_dump".to_string(),
                    "artifact".to_string(),
                    "high_impact".to_string(),
                ],
                severity: Severity::Medium,
                confidence: Confidence::Medium,
            })?;
        }
    }
    Ok(())
}

fn java_target_pids(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    pid_filter: Option<&str>,
    max_pids: usize,
) -> Result<Vec<String>> {
    if let Some(pid) = pid_filter.map(str::trim).filter(|pid| !pid.is_empty()) {
        if pid.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok(vec![pid.to_string()]);
        }
        store.add(EvidenceDraft {
            event_time: None,
            category: "java".to_string(),
            source: "java pid filter".to_string(),
            title: "忽略非法 Java PID 参数".to_string(),
            summary: format!("PID `{pid}` 不是纯数字，已忽略。"),
            raw_excerpt: None,
            tags: vec!["java_pid_invalid".to_string()],
            severity: Severity::Low,
            confidence: Confidence::High,
        })?;
    }
    let proc_cmd = if cfg!(windows) {
        "Get-CimInstance Win32_Process | Where-Object {$_.Name -like '*java*'} | Select-Object ProcessId,Name,CommandLine"
    } else if cfg!(target_os = "macos") {
        "ps -axo pid,ppid,user,lstart,etime,comm,args"
    } else {
        "ps -eo pid,ppid,user,lstart,etime,comm,args --cols 260"
    };
    let out = runner.run_builtin(store, proc_cmd, "java pid discovery")?;
    let java_lines = java_process_lines(&out.stdout).join("\n");
    let mut pids = extract_pids_from_java_output(&java_lines);
    pids.sort();
    pids.dedup();
    pids.truncate(max_pids.max(1));
    Ok(pids)
}

fn run_jvm_internal_probe(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    pid: &str,
    jcmd_action: &str,
    title: &str,
    keywords: &[&str],
) -> Result<()> {
    let cmd = format!("jcmd {pid} {jcmd_action}");
    let out = runner.run_builtin(store, &cmd, title)?;
    record_java_internal_output(
        store,
        pid,
        jcmd_action,
        title,
        &out.stdout,
        &out.stderr,
        keywords,
    )
}

fn record_java_internal_output(
    store: &mut EvidenceStore,
    pid: &str,
    source: &str,
    title: &str,
    stdout: &str,
    stderr: &str,
    keywords: &[&str],
) -> Result<()> {
    if stdout.trim().is_empty() && stderr.trim().is_empty() {
        return Ok(());
    }
    let raw = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    let hits = suspicious_lines(stdout, keywords, 80);
    store.add(EvidenceDraft {
        event_time: None,
        category: "java".to_string(),
        source: format!("java.deep pid={pid} {source}"),
        title: format!("JVM {pid} {title}"),
        summary: format!(
            "JVM 内部诊断 `{source}` 完成；可疑/需复核关键词样本 {} 条",
            hits.len()
        ),
        raw_excerpt: Some(truncate_text(
            &if hits.is_empty() {
                raw
            } else {
                hits.join("\n")
            },
            20_000,
        )),
        tags: vec!["java_deep".to_string(), "jvm_internal".to_string()],
        severity: if hits.is_empty() {
            Severity::Info
        } else {
            Severity::High
        },
        confidence: Confidence::Medium,
    })?;
    Ok(())
}

fn write_artifact_text(path: &Path, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

fn add_artifact_evidence(
    store: &mut EvidenceStore,
    pid: &str,
    artifact: &str,
    path: &Path,
    summary: &str,
) -> Result<()> {
    store.add(EvidenceDraft {
        event_time: None,
        category: "java".to_string(),
        source: path.display().to_string(),
        title: format!("JVM {pid} {artifact} artifact"),
        summary: summary.to_string(),
        raw_excerpt: Some(path.display().to_string()),
        tags: vec!["java_artifact".to_string(), artifact.to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;
    Ok(())
}

fn shell_quote_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if cfg!(windows) {
        format!("\"{}\"", raw.replace('"', ""))
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

pub fn record_readonly_command_output(
    store: &mut EvidenceStore,
    out: &crate::model::ToolRunOutput,
    reason: &str,
) -> Result<()> {
    let raw = format!(
        "$ {}\nexit={:?}\nstdout:\n{}\nstderr:\n{}",
        out.command, out.exit_code, out.stdout, out.stderr
    );
    store.add(EvidenceDraft {
        event_time: None,
        category: "readonly_shell".to_string(),
        source: out.command.clone(),
        title: "AI 调查员只读命令补充取证".to_string(),
        summary: format!(
            "{}；allowed={} truncated={}",
            reason, out.allowed, out.truncated
        ),
        raw_excerpt: Some(truncate_text(&raw, 16_000)),
        tags: vec!["ai_tool_call".to_string(), "readonly_shell".to_string()],
        severity: if out.allowed {
            Severity::Info
        } else {
            Severity::Low
        },
        confidence: Confidence::Medium,
    })?;
    Ok(())
}

fn redact_sensitive_line(line: &str) -> String {
    let mut out = Vec::new();
    for part in line.split_whitespace() {
        let lower = part.to_ascii_lowercase();
        let redacted = lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("token")
            || lower.contains("secret")
            || lower.contains("apikey")
            || lower.contains("api_key")
            || lower.starts_with("sk-");
        if redacted {
            out.push("[REDACTED]".to_string());
        } else {
            out.push(part.to_string());
        }
    }
    out.join(" ")
}

fn linux_pretty_os() -> Option<String> {
    let raw = fs::read_to_string("/etc/os-release").ok()?;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn linux_log_candidates() -> &'static [(&'static str, &'static str)] {
    &[
        ("/var/log/auth.log", "auth"),
        ("/var/log/secure", "auth"),
        ("/var/log/syslog", "system"),
        ("/var/log/messages", "system"),
        ("/var/log/audit/audit.log", "audit"),
        ("/var/log/cron", "cron"),
        ("/var/log/nginx/access.log", "web"),
        ("/var/log/nginx/error.log", "web"),
        ("/var/log/apache2/access.log", "web"),
        ("/var/log/apache2/error.log", "web"),
        ("/var/log/httpd/access_log", "web"),
        ("/var/log/httpd/error_log", "web"),
        ("/opt/tomcat/logs/catalina.out", "java_web"),
    ]
}

fn windows_channels() -> &'static [&'static str] {
    &[
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
    ]
}

fn windows_channel_type(channel: &str) -> &'static str {
    if channel.contains("PowerShell") {
        "powershell"
    } else if channel.contains("Sysmon") {
        "sysmon"
    } else if channel == "Security" {
        "auth"
    } else {
        "eventlog"
    }
}

fn path_source(path: &Path, kind: &str, exists: bool) -> LogSource {
    let readable = exists && File::open(path).is_ok();
    LogSource {
        name: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("log")
            .to_string(),
        source_type: kind.to_string(),
        path: Some(path.to_path_buf()),
        channel: None,
        exists,
        readable,
        note: None,
    }
}

fn discover_log_files_under(root: &Path, kind: &str) -> Vec<LogSource> {
    collect_files_limited(&[root.to_path_buf()], 3, 500)
        .into_iter()
        .filter(|p| {
            let name = p
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            name.ends_with(".log")
                || name.contains("access")
                || name.contains("error")
                || name.contains("catalina")
        })
        .map(|p| path_source(&p, kind, true))
        .collect()
}

fn scan_file_for(path: &Path, needle: &str, limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let Ok(file) = File::open(path) else {
        return Ok(out);
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(std::result::Result::ok) {
        if line.contains(needle) {
            out.push(line);
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}

fn read_matching_lines(path: &Path, limit: usize) -> Result<Vec<String>> {
    let mut tail = VecDeque::with_capacity(limit.min(10_000));
    let Ok(file) = File::open(path) else {
        return Ok(Vec::new());
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(std::result::Result::ok) {
        if tail.len() >= limit {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    Ok(tail.into_iter().collect())
}

fn suspicious_lines(raw: &str, needles: &[&str], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        if needles
            .iter()
            .any(|needle| lower.contains(&needle.to_ascii_lowercase()))
        {
            out.push(line.to_string());
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkEndpoint {
    state: String,
    local_addr: String,
    local_port: u16,
    line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkRiskFinding {
    port: u16,
    label: &'static str,
    severity: Severity,
    tags: Vec<String>,
    line: String,
}

fn risky_network_listeners(raw: &str) -> Vec<NetworkRiskFinding> {
    raw.lines()
        .filter_map(parse_network_endpoint)
        .filter(|endpoint| endpoint.state.contains("LISTEN"))
        .filter_map(|endpoint| classify_network_endpoint(&endpoint))
        .collect()
}

fn parse_network_endpoint(line: &str) -> Option<NetworkEndpoint> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(endpoint) = parse_windows_network_endpoint(trimmed) {
        return Some(endpoint);
    }
    parse_unix_network_endpoint(trimmed)
}

fn parse_unix_network_endpoint(line: &str) -> Option<NetworkEndpoint> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let state_idx = parts.iter().position(|part| {
        matches!(
            normalize_network_state(part).as_str(),
            "LISTEN" | "ESTAB" | "ESTABLISHED"
        )
    })?;
    let state = parts.get(state_idx)?.to_ascii_uppercase();
    let endpoint = parts
        .iter()
        .skip(state_idx + 1)
        .find_map(|part| parse_endpoint(part))
        .or_else(|| {
            parts
                .iter()
                .take(state_idx)
                .rev()
                .find_map(|part| parse_endpoint(part))
        })?;
    Some(NetworkEndpoint {
        state,
        local_addr: endpoint.0,
        local_port: endpoint.1,
        line: line.to_string(),
    })
}

fn normalize_network_state(value: &str) -> String {
    value.trim_matches(['(', ')']).to_ascii_uppercase()
}

fn parse_windows_network_endpoint(line: &str) -> Option<NetworkEndpoint> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let state_idx = parts
        .iter()
        .position(|part| matches!(part.to_ascii_uppercase().as_str(), "LISTEN" | "LISTENING"))?;
    if state_idx < 2 {
        return None;
    }
    let port = parts.get(state_idx - 1)?.parse::<u16>().ok()?;
    let addr = parts.get(state_idx - 2)?.to_string();
    Some(NetworkEndpoint {
        state: "LISTEN".to_string(),
        local_addr: addr,
        local_port: port,
        line: line.to_string(),
    })
}

fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let trimmed = value
        .trim_matches(['"', '\'', '[', ']'])
        .trim_start_matches("TCP")
        .trim()
        .trim_end_matches(',')
        .trim();
    if trimmed.is_empty() || !trimmed.contains(':') {
        return parse_dot_endpoint(trimmed);
    }
    let (addr, port_text) = trimmed.rsplit_once(':')?;
    let port = port_text.trim_matches('*').parse::<u16>().ok()?;
    let addr = addr
        .trim_matches(['[', ']'])
        .trim_start_matches("::ffff:")
        .to_string();
    Some((addr, port))
}

fn parse_dot_endpoint(value: &str) -> Option<(String, u16)> {
    let (addr, port_text) = value.rsplit_once('.')?;
    let port = port_text.parse::<u16>().ok()?;
    let looks_ipv4 = addr.chars().filter(|ch| *ch == '.').count() == 3;
    let wildcard = addr == "*";
    if !looks_ipv4 && !wildcard {
        return None;
    }
    Some((addr.to_string(), port))
}

fn classify_network_endpoint(endpoint: &NetworkEndpoint) -> Option<NetworkRiskFinding> {
    let profile = risk_port_profile(endpoint.local_port)?;
    let exposed = is_exposed_address(&endpoint.local_addr);
    let severity = if exposed {
        profile.exposed_severity
    } else {
        profile.loopback_severity
    };
    let mut tags = vec!["network_suspicious_listener".to_string()];
    tags.extend(profile.tags.iter().map(|tag| tag.to_string()));
    if exposed {
        tags.push("network_exposed_listener".to_string());
    } else {
        tags.push("network_loopback_listener".to_string());
    }
    Some(NetworkRiskFinding {
        port: endpoint.local_port,
        label: profile.label,
        severity,
        tags,
        line: endpoint.line.clone(),
    })
}

#[derive(Debug, Clone, Copy)]
struct RiskPortProfile {
    port: u16,
    label: &'static str,
    tags: &'static [&'static str],
    exposed_severity: Severity,
    loopback_severity: Severity,
}

fn risk_port_profile(port: u16) -> Option<RiskPortProfile> {
    risk_port_profiles()
        .iter()
        .find(|profile| profile.port == port)
        .copied()
}

fn risk_port_profiles() -> &'static [RiskPortProfile] {
    &[
        RiskPortProfile {
            port: 5005,
            label: "JDWP 调试端口",
            tags: &["jdwp_exposed", "debug_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
        RiskPortProfile {
            port: 4444,
            label: "常见后门/反连端口",
            tags: &["backdoor_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::High,
        },
        RiskPortProfile {
            port: 5555,
            label: "常见后门/调试端口",
            tags: &["backdoor_port", "debug_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
        RiskPortProfile {
            port: 31337,
            label: "常见后门端口",
            tags: &["backdoor_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::High,
        },
        RiskPortProfile {
            port: 1337,
            label: "常见后门端口",
            tags: &["backdoor_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::High,
        },
        RiskPortProfile {
            port: 2375,
            label: "Docker 未加密远程 API",
            tags: &["admin_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
        RiskPortProfile {
            port: 10250,
            label: "Kubelet API 端口",
            tags: &["admin_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
        RiskPortProfile {
            port: 1099,
            label: "JMX/RMI 端口",
            tags: &["admin_port", "debug_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
        RiskPortProfile {
            port: 9010,
            label: "JMX/RMI 端口",
            tags: &["admin_port", "debug_port"],
            exposed_severity: Severity::High,
            loopback_severity: Severity::Medium,
        },
    ]
}

fn is_exposed_address(addr: &str) -> bool {
    let value = addr.trim().to_ascii_lowercase();
    !(value.is_empty()
        || value == "127.0.0.1"
        || value == "localhost"
        || value == "::1"
        || value == "[::1]")
}

fn merge_network_tags(findings: &[NetworkRiskFinding]) -> Vec<String> {
    let mut tags = Vec::new();
    for finding in findings {
        for tag in &finding.tags {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }
    }
    tags
}

fn summarize_network_findings(findings: &[NetworkRiskFinding]) -> String {
    let high = findings
        .iter()
        .filter(|finding| finding.severity >= Severity::High)
        .count();
    let labels = findings
        .iter()
        .take(8)
        .map(|finding| format!("{}({})", finding.label, finding.port))
        .collect::<Vec<_>>()
        .join("、");
    format!(
        "发现 {} 条可疑监听/调试端口，其中 high {} 条；核心端口：{}",
        findings.len(),
        high,
        labels
    )
}

#[derive(Debug, Clone)]
struct PackageQueryResult {
    source: &'static str,
    output: ToolRunOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageRecord {
    name: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SuspiciousPackage {
    record: PackageRecord,
    tag: &'static str,
    severity: Severity,
}

fn run_dpkg_package_query(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
) -> Result<PackageQueryResult> {
    if command_exists("dpkg-query") {
        let cmd = "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'";
        let out = runner.run_builtin(store, cmd, "Debian package inventory")?;
        record_package_diagnostic(store, &out)?;
        if command_succeeded(&out) {
            return Ok(PackageQueryResult {
                source: "dpkg-query -W",
                output: out,
            });
        }
    }

    let fallback = "dpkg --get-selections";
    let out = runner.run_builtin(store, fallback, "Debian package selection inventory")?;
    record_package_diagnostic(store, &out)?;
    if command_succeeded(&out) {
        return Ok(PackageQueryResult {
            source: "dpkg --get-selections",
            output: out,
        });
    }

    let targeted = suspicious_package_profiles()
        .iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>()
        .join(" ");
    let cmd = format!("dpkg -s {targeted}");
    let out = runner.run_builtin(store, &cmd, "Debian suspicious package probes")?;
    record_package_diagnostic(store, &out)?;
    Ok(PackageQueryResult {
        source: "dpkg -s suspicious-tools",
        output: out,
    })
}

fn run_rpm_package_query(
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
) -> Result<PackageQueryResult> {
    let cmd = "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'";
    let out = runner.run_builtin(store, cmd, "RPM package inventory")?;
    record_package_diagnostic(store, &out)?;
    if command_succeeded(&out) {
        return Ok(PackageQueryResult {
            source: "rpm -qa --qf",
            output: out,
        });
    }

    let fallback = "rpm -qa";
    let out = runner.run_builtin(store, fallback, "RPM package inventory fallback")?;
    record_package_diagnostic(store, &out)?;
    Ok(PackageQueryResult {
        source: "rpm -qa",
        output: out,
    })
}

fn command_succeeded(out: &ToolRunOutput) -> bool {
    out.allowed && out.exit_code == Some(0) && !out.stdout.trim().is_empty()
}

fn parse_package_records(raw: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    let mut pending_dpkg_status = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Desired=") || trimmed.starts_with('|') {
            continue;
        }
        if trimmed.starts_with("Package:") {
            let name = trimmed.trim_start_matches("Package:").trim();
            if !name.is_empty() {
                out.push(PackageRecord {
                    name: name.to_string(),
                    version: None,
                });
            }
            continue;
        }
        if trimmed.contains(':') && !trimmed.contains('\t') {
            continue;
        }
        if trimmed.starts_with("Status:") {
            pending_dpkg_status = trimmed.contains("install ok installed");
            continue;
        }
        if trimmed.starts_with("ii ") || pending_dpkg_status {
            let parts = trimmed.split_whitespace().collect::<Vec<_>>();
            if parts.len() >= 2 && parts[0] == "ii" {
                out.push(PackageRecord {
                    name: parts[1].to_string(),
                    version: parts.get(2).map(|item| item.to_string()),
                });
                pending_dpkg_status = false;
                continue;
            }
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if let Some(name) = parts.first() {
            let clean = name.trim_matches(':');
            if clean
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | ':'))
            {
                out.push(PackageRecord {
                    name: clean.to_string(),
                    version: parts.get(1).map(|item| item.to_string()),
                });
            }
        }
    }
    dedupe_package_records(out)
}

fn dedupe_package_records(records: Vec<PackageRecord>) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for record in records {
        if !out
            .iter()
            .any(|item: &PackageRecord| item.name == record.name)
        {
            out.push(record);
        }
    }
    out
}

fn record_package_inventory(
    store: &mut EvidenceStore,
    source: &str,
    records: &[PackageRecord],
    truncated: bool,
) -> Result<()> {
    let sample = records
        .iter()
        .take(120)
        .map(|record| match &record.version {
            Some(version) => format!("{}\t{}", record.name, version),
            None => record.name.clone(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    store.add(EvidenceDraft {
        event_time: None,
        category: "package".to_string(),
        source: source.to_string(),
        title: "包资产摘要".to_string(),
        summary: format!(
            "通过 {} 收集包资产；包数量 {}；truncated={}",
            source,
            records.len(),
            truncated
        ),
        raw_excerpt: Some(truncate_text(&sample, 12_000)),
        tags: vec!["package_check".to_string(), "package_inventory".to_string()],
        severity: Severity::Info,
        confidence: Confidence::Medium,
    })?;
    Ok(())
}

fn record_suspicious_packages(
    store: &mut EvidenceStore,
    source: &str,
    records: &[PackageRecord],
) -> Result<()> {
    let findings = suspicious_packages(records);
    if findings.is_empty() {
        return Ok(());
    }
    let severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info);
    let mut tags = vec![
        "package_check".to_string(),
        "suspicious_package".to_string(),
    ];
    for finding in &findings {
        let tag = finding.tag.to_string();
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    let raw = findings
        .iter()
        .map(|finding| match &finding.record.version {
            Some(version) => format!("{}\t{}", finding.record.name, version),
            None => finding.record.name.clone(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    store.add(EvidenceDraft {
        event_time: None,
        category: "package".to_string(),
        source: format!("{source} suspicious"),
        title: "可疑包/工具命中".to_string(),
        summary: format!("包资产中命中 {} 个安全/攻击/隧道/挖矿工具", findings.len()),
        raw_excerpt: Some(truncate_text(&raw, 12_000)),
        tags,
        severity,
        confidence: Confidence::Medium,
    })?;
    Ok(())
}

fn suspicious_packages(records: &[PackageRecord]) -> Vec<SuspiciousPackage> {
    let mut out = Vec::new();
    for record in records {
        let normalized = normalize_package_name(&record.name);
        for profile in suspicious_package_profiles() {
            if normalized == profile.name || normalized.contains(profile.name) {
                out.push(SuspiciousPackage {
                    record: record.clone(),
                    tag: profile.tag,
                    severity: profile.severity,
                });
                break;
            }
        }
    }
    out
}

fn normalize_package_name(name: &str) -> String {
    name.split(':').next().unwrap_or(name).to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy)]
struct SuspiciousPackageProfile {
    name: &'static str,
    tag: &'static str,
    severity: Severity,
}

fn suspicious_package_profiles() -> &'static [SuspiciousPackageProfile] {
    &[
        SuspiciousPackageProfile {
            name: "xmrig",
            tag: "miner_tool",
            severity: Severity::High,
        },
        SuspiciousPackageProfile {
            name: "masscan",
            tag: "scanner_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "nmap",
            tag: "scanner_tool",
            severity: Severity::Low,
        },
        SuspiciousPackageProfile {
            name: "netcat",
            tag: "network_tool",
            severity: Severity::Low,
        },
        SuspiciousPackageProfile {
            name: "netcat-openbsd",
            tag: "network_tool",
            severity: Severity::Low,
        },
        SuspiciousPackageProfile {
            name: "netcat-traditional",
            tag: "network_tool",
            severity: Severity::Low,
        },
        SuspiciousPackageProfile {
            name: "ncat",
            tag: "network_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "socat",
            tag: "network_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "frp",
            tag: "tunnel_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "chisel",
            tag: "tunnel_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "ligolo",
            tag: "tunnel_tool",
            severity: Severity::Medium,
        },
        SuspiciousPackageProfile {
            name: "sshpass",
            tag: "credential_risk_tool",
            severity: Severity::Low,
        },
    ]
}

fn record_package_diagnostic(store: &mut EvidenceStore, out: &ToolRunOutput) -> Result<()> {
    let failed = !out.allowed || out.exit_code.map(|code| code != 0).unwrap_or(true);
    if !failed && !out.truncated {
        return Ok(());
    }
    let mut detail = format!(
        "包查询命令 `{}` 诊断：allowed={} exit={:?} truncated={} reason={}",
        out.command, out.allowed, out.exit_code, out.truncated, out.reason
    );
    if !out.stderr.trim().is_empty() {
        detail.push_str(" stderr=");
        detail.push_str(out.stderr.trim());
    }
    store.add(EvidenceDraft {
        event_time: None,
        category: "package".to_string(),
        source: "pkg.check diagnostic".to_string(),
        title: "包查询诊断".to_string(),
        summary: detail.clone(),
        raw_excerpt: Some(truncate_text(&detail, 8_000)),
        tags: vec![
            "package_check".to_string(),
            "package_diagnostic".to_string(),
        ],
        severity: Severity::Low,
        confidence: Confidence::High,
    })?;
    Ok(())
}

fn java_process_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .filter(|line| is_java_process_line(line))
        .map(ToString::to_string)
        .collect()
}

fn is_java_process_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("java") {
        return false;
    }
    if lower.contains("open-investigator") || lower.contains("target/debug/oi") {
        return false;
    }
    lower.split_whitespace().any(|token| {
        let token = token.trim_matches(['"', '\'']);
        let name = token.rsplit(['/', '\\']).next().unwrap_or(token);
        name == "java"
            || name == "java.exe"
            || name == "jsvc"
            || name == "jsvc.exe"
            || name.starts_with("java ")
            || name.starts_with("java-")
    })
}

fn jupyter_kernel_noise_lines(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| is_jupyter_kernel_noise(line))
        .cloned()
        .collect()
}

fn is_jupyter_kernel_noise(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("ipykernel_launcher")
        && lower.contains(" -f ")
        && extract_ipykernel_connection_path(line)
            .as_deref()
            .map(is_probable_kernel_connection_file)
            .unwrap_or(false)
}

fn extract_ipykernel_connection_path(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "-f" {
            return parts
                .next()
                .map(|value| value.trim_matches(['\'', '"']).to_string());
        }
    }
    None
}

fn is_probable_kernel_connection_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let in_temp = lower.starts_with("/tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.starts_with("/dev/shm/")
        || lower.contains("/appdata/local/temp/")
        || lower.contains("\\appdata\\local\\temp\\");
    if !in_temp || !lower.ends_with(".json") {
        return false;
    }
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    let Some(obj) = value.as_object() else {
        return false;
    };
    [
        "shell_port",
        "iopub_port",
        "stdin_port",
        "control_port",
        "hb_port",
    ]
    .iter()
    .all(|key| obj.get(*key).and_then(|v| v.as_i64()).is_some())
        && obj.get("key").is_some()
        && obj.get("transport").is_some()
}

fn record_command_diagnostic(
    store: &mut EvidenceStore,
    category: &str,
    source: &str,
    out: &ToolRunOutput,
) -> Result<()> {
    let failed = !out.allowed
        || out.exit_code.map(|code| code != 0).unwrap_or(true)
        || out
            .stderr
            .contains("[open-investigator] command timed out and was killed");
    if !failed {
        return Ok(());
    }
    let exit = out
        .exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal/unknown".to_string());
    let mut detail = format!(
        "命令 `{}` 执行异常：allowed={} exit={} reason={}",
        out.command, out.allowed, exit, out.reason
    );
    if !out.stderr.trim().is_empty() {
        detail.push_str(" stderr=");
        detail.push_str(out.stderr.trim());
    }
    store.add(EvidenceDraft {
        event_time: None,
        category: category.to_string(),
        source: source.to_string(),
        title: "只读命令诊断".to_string(),
        summary: detail.clone(),
        raw_excerpt: Some(truncate_text(&detail, 8_000)),
        tags: vec!["command_diagnostic".to_string()],
        severity: Severity::Low,
        confidence: Confidence::High,
    })?;
    Ok(())
}

fn extract_first_ipish(line: &str) -> Option<String> {
    for part in line.split_whitespace() {
        let value = part.trim_matches(|c: char| {
            c == ',' || c == ';' || c == '(' || c == ')' || c == '[' || c == ']'
        });
        if value.chars().filter(|ch| *ch == '.').count() == 3 || value.contains(':') {
            return Some(value.split('/').next().unwrap_or(value).to_string());
        }
    }
    None
}

fn extract_last_ipv4(line: &str) -> Option<String> {
    let mut last = None;
    for part in line.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if part.chars().filter(|ch| *ch == '.').count() == 3 {
            last = Some(part.to_string());
        }
    }
    last
}

fn find_authorized_keys() -> Vec<String> {
    let mut roots = vec![PathBuf::from("/root/.ssh")];
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            roots.push(entry.path().join(".ssh"));
        }
    }
    collect_files_limited(&roots, 2, 100)
        .into_iter()
        .filter(|p| p.file_name().and_then(|v| v.to_str()) == Some("authorized_keys"))
        .map(|p| path_string(&p))
        .collect()
}

fn default_web_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![PathBuf::from("C:/inetpub/wwwroot")]
    } else {
        vec![
            PathBuf::from("/var/www"),
            PathBuf::from("/usr/share/nginx/html"),
            PathBuf::from("/opt/tomcat/webapps"),
            PathBuf::from("/srv/www"),
        ]
    }
}

fn extract_pids_from_java_output(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in raw.lines() {
        for token in line.split_whitespace() {
            if token.chars().all(|c| c.is_ascii_digit()) {
                out.push(token.to_string());
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        is_jupyter_kernel_noise, parse_package_records, read_matching_lines,
        risky_network_listeners, scan_file_for, suspicious_packages, PackageRecord,
    };
    use crate::model::Severity;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn missing_log_file_scans_as_empty() {
        let path = Path::new("/definitely/not/a/real/open-investigator.log");

        let ioc_matches = scan_file_for(path, "1.2.3.4", 10).expect("scan missing file");
        let tail = read_matching_lines(path, 10).expect("read missing file");

        assert!(ioc_matches.is_empty());
        assert!(tail.is_empty());
    }

    #[test]
    fn recognizes_jupyter_kernel_connection_noise() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = Path::new("/tmp").join(format!("tmp{suffix}.json"));
        fs::write(
            &path,
            r#"{
              "shell_port": 57127,
              "iopub_port": 57128,
              "stdin_port": 57129,
              "control_port": 57130,
              "hb_port": 57131,
              "ip": "127.0.0.1",
              "key": "redacted",
              "transport": "tcp",
              "signature_scheme": "hmac-sha256",
              "kernel_name": ""
            }"#,
        )
        .expect("write kernel connection file");
        let line = format!(
            "123 1 user python /opt/pyvenv/bin/python -m ipykernel_launcher -f {}",
            path.display()
        );

        assert!(is_jupyter_kernel_noise(&line));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn java_process_filter_ignores_oi_command_text() {
        let raw = "\
123 1 user Thu Jan 1 00:00:00 1970 00:00.00 oi target/debug/oi java -s 14d
456 1 app Thu Jan 1 00:00:00 1970 00:00.00 java /usr/bin/java -jar app.jar";

        let lines = super::java_process_lines(raw);

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("/usr/bin/java -jar app.jar"));
    }

    #[test]
    fn exposed_jdwp_listener_is_high_risk() {
        let raw = "tcp LISTEN 0 4096 0.0.0.0:5005 0.0.0.0:* users:((\"java\",pid=100,fd=12))";

        let findings = risky_network_listeners(raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].tags.contains(&"jdwp_exposed".to_string()));
    }

    #[test]
    fn loopback_jdwp_listener_is_medium_risk() {
        let raw = "tcp LISTEN 0 4096 127.0.0.1:5005 0.0.0.0:* users:((\"java\",pid=100,fd=12))";

        let findings = risky_network_listeners(raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0]
            .tags
            .contains(&"network_loopback_listener".to_string()));
    }

    #[test]
    fn backdoor_listener_is_high_risk() {
        let raw = "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:((\"sh\",pid=44,fd=3))";

        let findings = risky_network_listeners(raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].tags.contains(&"backdoor_port".to_string()));
    }

    #[test]
    fn common_web_and_ssh_listeners_are_not_risk_findings() {
        let raw = "\
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*";

        assert!(risky_network_listeners(raw).is_empty());
    }

    #[test]
    fn parses_lsof_listener_format() {
        let raw = "nc 95415 user 3u IPv4 0x123 0t0 TCP 127.0.0.1:5005 (LISTEN)";

        let findings = risky_network_listeners(raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].port, 5005);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn parses_macos_netstat_dot_endpoint_format() {
        let raw = "tcp4 0 0 127.0.0.1.4444 *.* LISTEN 0 0 0";

        let findings = risky_network_listeners(raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].port, 4444);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn parses_package_inventory_and_finds_suspicious_tools() {
        let raw = "\
openssh-server\t1:9.6p1
xmrig\t6.21.0
socat\t1.7.4
curl\t8.5.0";

        let records = parse_package_records(raw);
        let findings = suspicious_packages(&records);

        assert_eq!(records.len(), 4);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|item| item.record.name == "xmrig" && item.severity == Severity::High));
        assert!(findings
            .iter()
            .any(|item| item.record.name == "socat" && item.tag == "network_tool"));
    }

    #[test]
    fn parses_dpkg_status_probe_output() {
        let raw = "\
Package: nmap
Status: install ok installed
Version: 7.94";

        let records = parse_package_records(raw);

        assert_eq!(
            records,
            vec![PackageRecord {
                name: "nmap".to_string(),
                version: None
            }]
        );
    }
}
