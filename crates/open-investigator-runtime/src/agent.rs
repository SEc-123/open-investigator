use crate::case::CaseContext;
use crate::config::OiConfig;
use crate::model::{Confidence, Evidence, EvidenceDraft, LogSource, Severity};
use crate::runner::CommandRunner;
use crate::store::EvidenceStore;
use crate::tools::{
    chat_tool_definitions, execute_tool_action, normalize_tool_name, tool_catalog_text,
};
use crate::util::truncate_text;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Map, Value};
use std::time::Duration;

/// Runtime-derived AI tool loop for Open Investigator.
///
/// This module keeps the original runtime shape that made the source project
/// useful: a model turn can call tools, the runtime executes those tools, the
/// tool observations are appended back into the model context, and the model can
/// continue with additional tool calls. What is removed is the original product
/// surface: code editing, patching, project search, apps, web search, and
/// response actions. The only registered tools are Open Investigator read-only
/// investigation tools.
///
/// Loop shape:
/// 1. Build system/user messages with the case goal and sealed tool catalog.
/// 2. Call an OpenAI-compatible chat-completions endpoint with function tools.
/// 3. Validate every requested tool against the sealed catalog.
/// 4. Execute the tool through the Open Investigator dispatcher.
/// 5. Write evidence and command audit records.
/// 6. Return tool observations to the model and continue until final answer or
///    configured loop budget is reached.
pub async fn run_ai_investigation_loop(
    cfg: &OiConfig,
    ctx: &CaseContext,
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
) -> Result<Vec<String>> {
    if !cfg.ai_enabled || !cfg.ai_planning_enabled || !ctx.ai_enabled {
        return Ok(Vec::new());
    }
    if cfg.api_key().is_none() {
        store.add(EvidenceDraft {
            event_time: None,
            category: "ai_agent".to_string(),
            source: "ai.config".to_string(),
            title: "AI 调查员未启用".to_string(),
            summary: "未发现 API key，已跳过 AI 自主工具调用；将使用确定性 guardrail 调查流程。"
                .to_string(),
            raw_excerpt: None,
            tags: vec!["ai_disabled_no_key".to_string()],
            severity: Severity::Info,
            confidence: Confidence::High,
        })?;
        return Ok(Vec::new());
    }

    let mut executed_tools = Vec::new();
    let max_rounds = cfg.ai_max_rounds.clamp(1, 16);
    let max_actions = cfg.ai_max_actions_per_round.clamp(1, 16);
    let mut messages = initial_messages(ctx);
    let tools = chat_tool_definitions(ctx);

    store.add(EvidenceDraft {
        event_time: None,
        category: "ai_agent".to_string(),
        source: "ai.loop".to_string(),
        title: "AI 工具调用循环启动".to_string(),
        summary: format!(
            "model={} max_rounds={} max_actions_per_round={} tool_count={} mode={}",
            cfg.planning_model(),
            max_rounds,
            max_actions,
            tools.len(),
            ctx.mode
        ),
        raw_excerpt: Some(truncate_text(&tool_catalog_text(ctx), 16_000)),
        tags: vec!["ai_tool_loop_start".to_string()],
        severity: Severity::Info,
        confidence: Confidence::High,
    })?;

    for round in 0..max_rounds {
        let response = request_assistant_message(cfg, &messages, &tools).await;
        let message = match response {
            Ok(message) => message,
            Err(err) => {
                store.add(EvidenceDraft {
                    event_time: None,
                    category: "ai_agent".to_string(),
                    source: "ai.provider".to_string(),
                    title: "AI 工具循环请求失败".to_string(),
                    summary: format!("第 {} 轮 AI 请求失败：{}", round + 1, err),
                    raw_excerpt: None,
                    tags: vec!["ai_provider_error".to_string()],
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                })?;
                break;
            }
        };

        let tool_calls = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        if tool_calls.is_empty() {
            let content = assistant_content_text(&message);
            if !content.trim().is_empty() {
                store.add(EvidenceDraft {
                    event_time: None,
                    category: "ai_agent".to_string(),
                    source: "ai.final".to_string(),
                    title: "AI 调查员阶段性结论".to_string(),
                    summary: truncate_text(&content, 1_000),
                    raw_excerpt: Some(truncate_text(&content, 24_000)),
                    tags: vec!["ai_final_message".to_string()],
                    severity: Severity::Info,
                    confidence: Confidence::Medium,
                })?;
            }
            break;
        }

        messages.push(message.clone());

        store.add(EvidenceDraft {
            event_time: None,
            category: "ai_agent".to_string(),
            source: "ai.tool_calls".to_string(),
            title: format!("AI 第 {} 轮请求工具", round + 1),
            summary: format!("requested_tool_calls={}", tool_calls.len()),
            raw_excerpt: Some(truncate_text(
                &serde_json::to_string_pretty(&tool_calls).unwrap_or_default(),
                16_000,
            )),
            tags: vec!["ai_tool_calls".to_string()],
            severity: Severity::Info,
            confidence: Confidence::Medium,
        })?;

        for (idx, call) in tool_calls.iter().enumerate() {
            let tool_call_id = call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("oi-tool-call")
                .to_string();
            let function = call.get("function").cloned().unwrap_or_else(|| json!({}));
            let raw_name = function
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = parse_tool_arguments(function.get("arguments"));
            let tool = normalize_tool_name(&raw_name);

            if idx >= max_actions {
                let content = json!({
                    "status": "skipped_by_runtime_budget",
                    "tool": tool,
                    "reason": "ai_max_actions_per_round exceeded",
                });
                messages.push(tool_message(&tool_call_id, &content));
                continue;
            }

            let before = store.load_evidence()?.len();
            let reason = args
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("AI requested this read-only investigation tool");

            let result =
                match execute_tool_action(&tool, &args, reason, ctx, store, runner, sources) {
                    Ok(()) => {
                        executed_tools.push(tool.clone());
                        let after = store.load_evidence()?;
                        let new_evidence: Vec<Evidence> = after.into_iter().skip(before).collect();
                        json!({
                            "status": "ok",
                            "requested_tool": raw_name,
                            "normalized_tool": tool,
                            "new_evidence": evidence_observation(&new_evidence),
                        })
                    }
                    Err(err) => {
                        store.add(EvidenceDraft {
                            event_time: None,
                            category: "ai_agent".to_string(),
                            source: tool.clone(),
                            title: "AI 工具调用失败".to_string(),
                            summary: format!("{}: {}", reason, err),
                            raw_excerpt: Some(truncate_text(&args.to_string(), 4_000)),
                            tags: vec!["ai_tool_error".to_string()],
                            severity: Severity::Low,
                            confidence: Confidence::Medium,
                        })?;
                        json!({
                            "status": "error",
                            "requested_tool": raw_name,
                            "normalized_tool": tool,
                            "error": err.to_string(),
                        })
                    }
                };

            messages.push(tool_message(&tool_call_id, &result));
        }
    }

    Ok(executed_tools)
}

fn initial_messages(ctx: &CaseContext) -> Vec<Value> {
    let system = r#"你是 Open Investigator 的本机只读服务器应急调查员。

目标：根据用户问题，自主调用封装好的只读调查工具，像高级应急响应调查员一样逐步定位本机 server 异常。

强制边界：
- 你只能使用提供的工具。不要臆造工具。
- 不要要求或执行隔离主机、封禁 IP、杀进程、删除文件、禁用账号、修改注册表、修改防火墙、安装软件、下载脚本、重启服务等处置动作。
- safe 模式没有自由命令；inv 模式下 oi_ro_run 仍受只读策略拦截。
- 所有结论必须来自 evidence。证据不足必须说明证据不足。

调查策略：
- 不要机械调用所有工具；先根据问题选择最高价值工具。
- 可疑 IP：优先 ioc/auth/web/net/proc/per。
- 登录异常：优先 auth/acct/per/proc/net。
- WebShell：优先 web/file/proc/net/java。
- Java 内存马线索：优先 java/mem/web/proc/file/net；默认不要 heap dump，不要 attach，不要改 JVM。
- 通用主机异常：覆盖 auth/acct/proc/net/per/svc/web/java/file/deep。
- 当你认为证据足以形成报告时，停止调用工具并输出最终中文调查结论。
"#;

    let user = format!(
        "case_id={case_id}\ncommand={command}\nmode={mode}\nsince={since}\nquestion={question}\nioc={ioc:?}\nweb_root={web_root:?}\npath={path:?}\n\n请使用工具自主调查。先判断最该查什么，再根据工具结果继续缩小范围。",
        case_id = ctx.case_id,
        command = ctx.command,
        mode = ctx.mode,
        since = ctx.since,
        question = ctx.question,
        ioc = &ctx.ioc,
        web_root = &ctx.web_root,
        path = &ctx.path,
    );

    vec![
        json!({"role":"system", "content": system}),
        json!({"role":"user", "content": user}),
    ]
}

async fn request_assistant_message(
    cfg: &OiConfig,
    messages: &[Value],
    tools: &[Value],
) -> Result<Value> {
    let api_key = cfg.api_key().context("missing API key")?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {api_key}")).context("build auth header")?,
    );

    let endpoint = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
    let body = json!({
        "model": cfg.planning_model(),
        "temperature": cfg.ai_planning_temperature,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
    });

    let value: Value = reqwest::Client::new()
        .post(endpoint)
        .timeout(Duration::from_secs(cfg.ai_request_timeout_seconds.max(10)))
        .headers(headers)
        .json(&body)
        .send()
        .await
        .context("send AI tool-loop request")?
        .error_for_status()
        .context("AI provider returned non-success status")?
        .json()
        .await
        .context("parse AI tool-loop response")?;

    value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .cloned()
        .context("AI response missing choices[0].message")
}

fn parse_tool_arguments(arguments: Option<&Value>) -> Value {
    match arguments {
        Some(Value::String(raw)) => {
            serde_json::from_str(raw).unwrap_or_else(|_| json!({"_raw_arguments": raw}))
        }
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(other) => json!({"_raw_arguments": other}),
        None => Value::Object(Map::new()),
    }
}

fn tool_message(tool_call_id: &str, content: &Value) -> Value {
    json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": truncate_text(&serde_json::to_string(content).unwrap_or_else(|_| "{}".to_string()), 64_000),
    })
}

fn evidence_observation(evidence: &[Evidence]) -> Value {
    let items = evidence
        .iter()
        .take(40)
        .map(|ev| {
            json!({
                "id": ev.id,
                "category": ev.category,
                "source": ev.source,
                "title": ev.title,
                "summary": truncate_text(&ev.summary, 1_000),
                "severity": ev.severity,
                "confidence": ev.confidence,
                "tags": ev.tags,
            })
        })
        .collect::<Vec<_>>();
    Value::Array(items)
}

fn assistant_content_text(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}
