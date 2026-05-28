use crate::case::CaseContext;
use crate::collector;
use crate::model::{Confidence, EvidenceDraft, LogSource, Severity};
use crate::runner::CommandRunner;
use crate::store::EvidenceStore;
use crate::util::truncate_text;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub args: &'static str,
    pub description: &'static str,
    pub inv_only: bool,
}

/// The sealed investigation tool catalog exposed to the AI investigator.
///
/// These are not raw OS commands. They are investigator actions. Each action
/// maps to bounded, read-only collectors and writes structured evidence.
pub fn tool_specs(include_inv_tools: bool) -> Vec<ToolSpec> {
    let mut tools = vec![
        ToolSpec { name: "ioc.find", args: r#"{"ioc":"1.2.3.4","type":"ip|domain|hash|path|user"}"#, description: "Search discovered logs and important local evidence sources for an IOC.", inv_only: false },
        ToolSpec { name: "auth.check", args: r#"{"ip":"optional","user":"optional"}"#, description: "Analyze authentication events: failed/successful logins, brute-force hints, privileged logins, account changes.", inv_only: false },
        ToolSpec { name: "acct.snap", args: "{}", description: "Collect local users, privileged groups, sudo/admin context, SSH authorized_keys indicators.", inv_only: false },
        ToolSpec { name: "proc.snap", args: "{}", description: "Collect process snapshot and suspicious command-line tags: web-user shell, temp execution, interpreters, Java agent/JDWP.", inv_only: false },
        ToolSpec { name: "net.snap", args: r#"{"ip":"optional"}"#, description: "Collect network listeners/connections and correlate a remote IP when provided.", inv_only: false },
        ToolSpec { name: "per.snap", args: "{}", description: "Collect persistence/autostart evidence: cron, systemd, timers, scheduled tasks, services, Run/RunOnce, authorized_keys.", inv_only: false },
        ToolSpec { name: "svc.snap", args: "{}", description: "Collect service/daemon state and suspicious service paths or commands.", inv_only: false },
        ToolSpec { name: "web.check", args: r#"{"ip":"optional","root":"optional web root"}"#, description: "Analyze web logs, WebShell indicators, uploads, suspicious POSTs, web-root recent script/package changes.", inv_only: false },
        ToolSpec { name: "java.check", args: "{}", description: "Analyze Java process command lines, -javaagent/-agentlib/JDWP/Xbootclasspath, jps/jcmd metadata, Java memory-shell peripheral clues.", inv_only: false },
        ToolSpec { name: "mem.check", args: "{}", description: "Low-impact memory anomaly peripheral checks without heap/memory dump or invasive attach.", inv_only: false },
        ToolSpec { name: "file.recent", args: r#"{"path":"optional root path"}"#, description: "Find recent suspicious file changes in temp, web roots, service directories, user/profile locations.", inv_only: false },
        ToolSpec { name: "container.check", args: "{}", description: "Collect local Docker/CRI/Kubernetes read-only evidence: containers, images, pods, logs metadata.", inv_only: false },
        ToolSpec { name: "hist.check", args: "{}", description: "Inspect shell/PowerShell history indicators with simple secret redaction.", inv_only: false },
        ToolSpec { name: "linux.deep", args: "{}", description: "Linux deep read-only checks: auditd, lastb, lsmod, ld.so.preload, SUID, suspicious temp locations.", inv_only: false },
        ToolSpec { name: "windows.deep", args: "{}", description: "Windows deep read-only checks: PowerShell logs, Sysmon, WMI persistence, Defender, Startup.", inv_only: false },
        ToolSpec { name: "pkg.check", args: "{}", description: "Collect package/program inventory and suspicious admin/offensive tools.", inv_only: false },
    ];
    if include_inv_tools {
        tools.push(ToolSpec { name: "ro.run", args: r#"{"command":"readonly command"}"#, description: "Investigator-mode fallback for a specific read-only OS command. It must pass policy and is fully audited.", inv_only: true });
    }
    tools
}

pub fn tool_catalog_text(ctx: &CaseContext) -> String {
    tool_specs(ctx.mode.allows_readonly_shell())
        .into_iter()
        .map(|tool| {
            let scope = if tool.inv_only { "inv-only" } else { "safe" };
            format!(
                "{} args:{} [{}] - {}",
                tool.name, tool.args, scope, tool.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn tool_catalog_json(ctx: &CaseContext) -> Value {
    let items = tool_specs(ctx.mode.allows_readonly_shell())
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "args": tool.args,
                "description": tool.description,
                "inv_only": tool.inv_only,
            })
        })
        .collect::<Vec<_>>();
    Value::Array(items)
}

/// OpenAI-compatible function-tool definitions exposed to the model.
///
/// Chat-completions tool names cannot rely on dots, so the public AI tool names
/// are `oi_*`. They are normalized back to the internal dotted investigator
/// actions before execution.
pub fn chat_tool_definitions(ctx: &CaseContext) -> Vec<Value> {
    tool_specs(ctx.mode.allows_readonly_shell())
        .into_iter()
        .map(|tool| {
            let name = chat_tool_name(tool.name);
            json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": format!("{} Internal action: {}. Args example: {}", tool.description, tool.name, tool.args),
                    "parameters": common_tool_parameters(tool.name),
                }
            })
        })
        .collect()
}

fn chat_tool_name(name: &str) -> String {
    format!("oi_{}", name.replace('.', "_"))
}

fn common_tool_parameters(tool: &str) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "reason".to_string(),
        json!({"type":"string", "description":"Why this evidence is needed now."}),
    );
    properties.insert(
        "since".to_string(),
        json!({"type":"string", "description":"Optional time window such as 24h, 7d, 14d."}),
    );
    properties.insert("ioc".to_string(), json!({"type":"string", "description":"IOC value such as IP, domain, path, hash, user, or keyword."}));
    properties.insert(
        "type".to_string(),
        json!({"type":"string", "description":"IOC type: ip, domain, hash, path, user, keyword."}),
    );
    properties.insert(
        "ip".to_string(),
        json!({"type":"string", "description":"Optional IP filter."}),
    );
    properties.insert(
        "user".to_string(),
        json!({"type":"string", "description":"Optional user/account filter."}),
    );
    properties.insert(
        "path".to_string(),
        json!({"type":"string", "description":"Optional local path to inspect."}),
    );
    properties.insert(
        "web_root".to_string(),
        json!({"type":"string", "description":"Optional web root path."}),
    );
    properties.insert(
        "root".to_string(),
        json!({"type":"string", "description":"Alias for web_root."}),
    );
    properties.insert(
        "limit".to_string(),
        json!({"type":"integer", "description":"Optional maximum result count."}),
    );
    if tool == "ro.run" {
        properties.insert("command".to_string(), json!({"type":"string", "description":"A specific read-only OS command. It will be policy checked and audited."}));
    }
    json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false,
    })
}

pub fn normalize_tool_name(tool: &str) -> String {
    match tool.trim().to_ascii_lowercase().as_str() {
        "oi_ioc_find" => "ioc.find".to_string(),
        "oi_auth_check" => "auth.check".to_string(),
        "oi_acct_snap" => "acct.snap".to_string(),
        "oi_proc_snap" => "proc.snap".to_string(),
        "oi_net_snap" => "net.snap".to_string(),
        "oi_per_snap" => "per.snap".to_string(),
        "oi_svc_snap" => "svc.snap".to_string(),
        "oi_web_check" => "web.check".to_string(),
        "oi_java_check" => "java.check".to_string(),
        "oi_mem_check" => "mem.check".to_string(),
        "oi_file_recent" => "file.recent".to_string(),
        "oi_container_check" => "container.check".to_string(),
        "oi_hist_check" => "hist.check".to_string(),
        "oi_linux_deep" => "linux.deep".to_string(),
        "oi_windows_deep" => "windows.deep".to_string(),
        "oi_pkg_check" => "pkg.check".to_string(),
        "oi_ro_run" => "ro.run".to_string(),
        "logs.search" | "search.ioc" | "ioc.search" | "log.search" => "ioc.find".to_string(),
        "auth" | "auth.analyze" | "login" | "login.check" => "auth.check".to_string(),
        "process" | "process.snapshot" | "proc" | "ps" => "proc.snap".to_string(),
        "network" | "network.snapshot" | "net" => "net.snap".to_string(),
        "account" | "accounts" | "account.snapshot" | "acct" => "acct.snap".to_string(),
        "persistence" | "persistence.snapshot" | "persist" | "per" => "per.snap".to_string(),
        "service" | "services" | "service.snapshot" | "svc" => "svc.snap".to_string(),
        "web" | "webshell" | "web.analyze" => "web.check".to_string(),
        "java" | "jvm" | "java.analyze" => "java.check".to_string(),
        "memory" | "mem" => "mem.check".to_string(),
        "file" | "recent_files" | "file.recent_changes" => "file.recent".to_string(),
        "container" | "docker" | "k8s" => "container.check".to_string(),
        "history" | "hist" => "hist.check".to_string(),
        "package" | "pkg" => "pkg.check".to_string(),
        "readonly.run" | "shell" | "sh" => "ro.run".to_string(),
        other => other.to_string(),
    }
}

pub fn execute_tool_action(
    tool: &str,
    args: &Value,
    reason: &str,
    ctx: &CaseContext,
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
) -> Result<()> {
    store.add(EvidenceDraft {
        event_time: None,
        category: "ai_agent".to_string(),
        source: tool.to_string(),
        title: "AI 调查员请求工具".to_string(),
        summary: reason.to_string(),
        raw_excerpt: Some(truncate_text(&args.to_string(), 4_000)),
        tags: vec!["ai_tool_request".to_string(), tool.to_string()],
        severity: Severity::Info,
        confidence: Confidence::Medium,
    })?;

    match tool {
        "ioc.find" => {
            let ioc = arg_string(args, "ioc").or_else(|| ctx.ioc.clone());
            if let Some(ioc) = ioc {
                collector::search_ioc(store, runner, sources, &ioc, &ctx.since)?;
            } else {
                add_missing_arg(store, tool, "ioc")?;
            }
        }
        "auth.check" => collector::analyze_auth(
            store,
            runner,
            sources,
            arg_string(args, "ip").as_deref().or(ctx.ioc.as_deref()),
            arg_string(args, "user").as_deref(),
            &ctx.since,
        )?,
        "acct.snap" => collector::snapshot_accounts(store, runner)?,
        "proc.snap" => collector::snapshot_processes(store, runner)?,
        "net.snap" => collector::snapshot_network(
            store,
            runner,
            arg_string(args, "ip").as_deref().or(ctx.ioc.as_deref()),
        )?,
        "per.snap" => collector::snapshot_persistence(store, runner)?,
        "svc.snap" => collector::snapshot_services(store, runner)?,
        "web.check" => {
            let mut local = ctx.clone();
            if let Some(ip) = arg_string(args, "ip") {
                local.ioc = Some(ip);
                local.ioc_type = Some("ip".to_string());
            }
            if let Some(root) = arg_string(args, "root").or_else(|| arg_string(args, "web_root")) {
                local.web_root = Some(PathBuf::from(root));
            }
            collector::analyze_web(store, sources, &local)?;
        }
        "java.check" => collector::analyze_java(store, runner)?,
        "mem.check" => collector::memory_low_impact(store, runner)?,
        "file.recent" => {
            let mut local = ctx.clone();
            if let Some(path) = arg_string(args, "path") {
                local.path = Some(PathBuf::from(path));
            }
            collector::recent_files(store, &local)?;
        }
        "container.check" => collector::analyze_container(store, runner)?,
        "hist.check" => collector::analyze_history(store)?,
        "linux.deep" => collector::analyze_linux_deep(store, runner)?,
        "windows.deep" => collector::analyze_windows_deep(store, runner)?,
        "pkg.check" => collector::analyze_packages(store, runner)?,
        "ro.run" => {
            let Some(command) = arg_string(args, "command") else {
                add_missing_arg(store, tool, "command")?;
                return Ok(());
            };
            let out = runner.run_ro(store, &command, reason)?;
            collector::record_readonly_command_output(store, &out, reason)?;
        }
        _ => {
            store.add(EvidenceDraft {
                event_time: None,
                category: "ai_agent".to_string(),
                source: tool.to_string(),
                title: "AI 请求了未知工具".to_string(),
                summary: format!("忽略未知工具：{}", tool),
                raw_excerpt: Some(truncate_text(&args.to_string(), 4_000)),
                tags: vec!["unknown_ai_tool".to_string()],
                severity: Severity::Info,
                confidence: Confidence::Medium,
            })?;
        }
    }
    Ok(())
}

fn add_missing_arg(store: &mut EvidenceStore, tool: &str, arg: &str) -> Result<()> {
    store.add(EvidenceDraft {
        event_time: None,
        category: "ai_agent".to_string(),
        source: tool.to_string(),
        title: "AI 工具调用缺少参数".to_string(),
        summary: format!("工具 `{}` 缺少必需参数 `{}`", tool, arg),
        raw_excerpt: None,
        tags: vec!["ai_tool_argument_error".to_string()],
        severity: Severity::Low,
        confidence: Confidence::High,
    })?;
    Ok(())
}

fn arg_string(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}
