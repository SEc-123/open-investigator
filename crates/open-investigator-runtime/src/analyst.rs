use crate::config::OiConfig;
use crate::model::{Evidence, InvestigationReport};
use crate::util::truncate_text;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;
use std::time::Duration;

pub async fn synthesize_with_ai(
    cfg: &OiConfig,
    draft: &InvestigationReport,
    evidence: &[Evidence],
) -> Result<Option<String>> {
    if !cfg.ai_enabled {
        return Ok(None);
    }
    let Some(api_key) = cfg.api_key() else {
        return Ok(None);
    };

    let evidence_excerpt = evidence
        .iter()
        .take(80)
        .map(|ev| {
            format!(
                "{} [{} {}] {} :: {} :: {}",
                ev.id, ev.severity, ev.confidence, ev.category, ev.title, ev.summary
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let system = r#"你是 Open Investigator 的只读服务器应急调查员。
你只能根据提供的 evidence 和 report draft 下结论。
必须区分：已证实、可疑、证据不足。
不要声称已经执行隔离、封禁、杀进程、删文件、禁用账号或改配置。
输出中文，结构固定：结论、关键证据、攻击/异常链路、证据缺口、建议人工下一步。"#;
    let user = format!(
        "调查报告草稿：\n{}\n\n证据摘要：\n{}",
        truncate_text(
            &serde_json::to_string_pretty(draft).context("serialize draft report")?,
            30_000
        ),
        truncate_text(&evidence_excerpt, 20_000)
    );

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let token = format!("Bearer {api_key}");
    if let Ok(value) = HeaderValue::from_str(&token) {
        headers.insert(AUTHORIZATION, value);
    }

    let endpoint = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
    let body = json!({
        "model": cfg.synthesis_model(),
        "temperature": cfg.ai_synthesis_temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]
    });

    let client = reqwest::Client::new();
    let value: serde_json::Value = client
        .post(endpoint)
        .timeout(Duration::from_secs(cfg.ai_request_timeout_seconds.max(10)))
        .headers(headers)
        .json(&body)
        .send()
        .await
        .context("send OpenAI-compatible chat completion request")?
        .error_for_status()
        .context("AI provider returned non-success status")?
        .json()
        .await
        .context("parse AI provider response")?;

    let content = value
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .map(str::trim)
        .filter(|content| !content.is_empty())
        .map(ToString::to_string);

    Ok(content)
}
