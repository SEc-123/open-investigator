use crate::config::OiConfig;
use crate::model::{Evidence, InvestigationReport, Severity};
use crate::report::AiRiskAdjustment;
use crate::util::truncate_text;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct AiSynthesisResult {
    pub text: Option<String>,
    pub risk_adjustment: Option<AiRiskAdjustment>,
}

pub async fn synthesize_with_ai(
    cfg: &OiConfig,
    draft: &InvestigationReport,
    evidence: &[Evidence],
) -> Result<AiSynthesisResult> {
    if !cfg.ai_enabled {
        return Ok(AiSynthesisResult::default());
    }
    let Some(api_key) = cfg.api_key() else {
        return Ok(AiSynthesisResult::default());
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
输出 JSON 对象，不要输出 markdown fence。字段固定：
{
  "ai_synthesis": "中文综合判断，结构为：结论、关键证据、攻击/异常链路、证据缺口、建议人工下一步。",
  "ai_adjusted_risk": "info|low|medium|high|critical|null",
  "ai_risk_rationale": "如建议调整风险，给出不超过 200 字理由；否则为空字符串。"
}
ai_adjusted_risk 是对 report draft.risk 的调查员建议，只能根据 evidence 建议降级、维持或升级；证据不足时不要升级。"#;
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

    Ok(parse_ai_synthesis(content, draft.risk))
}

fn parse_ai_synthesis(content: Option<String>, rule_risk: Severity) -> AiSynthesisResult {
    let Some(content) = content else {
        return AiSynthesisResult::default();
    };
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return AiSynthesisResult::default();
    }

    if let Some(parsed) = parse_structured_response(trimmed, rule_risk) {
        return parsed;
    }

    AiSynthesisResult {
        text: Some(trimmed.to_string()),
        risk_adjustment: None,
    }
}

fn parse_structured_response(raw: &str, rule_risk: Severity) -> Option<AiSynthesisResult> {
    let value = serde_json::from_str::<StructuredAiSynthesis>(raw).ok()?;
    let text = value
        .ai_synthesis
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty());
    let adjusted = value
        .ai_adjusted_risk
        .as_deref()
        .and_then(parse_severity)
        .filter(|risk| *risk != rule_risk);
    let rationale = value
        .ai_risk_rationale
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty());
    let risk_adjustment = adjusted.map(|risk| AiRiskAdjustment {
        risk,
        rationale: rationale.unwrap_or_else(|| "AI 综合判断建议调整规则风险。".to_string()),
    });

    Some(AiSynthesisResult {
        text,
        risk_adjustment,
    })
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        "null" | "none" | "" => None,
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct StructuredAiSynthesis {
    ai_synthesis: Option<String>,
    ai_adjusted_risk: Option<String>,
    ai_risk_rationale: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::parse_ai_synthesis;
    use crate::model::Severity;

    #[test]
    fn parses_structured_ai_risk_adjustment() {
        let raw = r#"{
          "ai_synthesis": "结论：更像环境噪声。",
          "ai_adjusted_risk": "low",
          "ai_risk_rationale": "Jupyter kernel connection file 已被验证。"
        }"#;

        let parsed = parse_ai_synthesis(Some(raw.to_string()), Severity::High);

        assert_eq!(parsed.text.as_deref(), Some("结论：更像环境噪声。"));
        let adjustment = parsed.risk_adjustment.expect("adjustment");
        assert_eq!(adjustment.risk, Severity::Low);
        assert_eq!(
            adjustment.rationale,
            "Jupyter kernel connection file 已被验证。"
        );
    }

    #[test]
    fn keeps_plain_text_synthesis_when_json_parse_fails() {
        let parsed = parse_ai_synthesis(Some("结论：证据不足。".to_string()), Severity::High);

        assert_eq!(parsed.text.as_deref(), Some("结论：证据不足。"));
        assert!(parsed.risk_adjustment.is_none());
    }
}
