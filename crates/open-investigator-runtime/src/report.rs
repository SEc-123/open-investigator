use crate::case::CaseContext;
use crate::model::{
    Confidence, Evidence, EvidenceSummary, Finding, HostProfile, InvestigationReport, Severity,
    TimelineEvent,
};
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::Path;

pub fn build_report(
    ctx: &CaseContext,
    host: HostProfile,
    evidence: &[Evidence],
    scope: Vec<String>,
    ai_synthesis: Option<String>,
    ai_risk_adjustment: Option<AiRiskAdjustment>,
) -> InvestigationReport {
    let risk = evidence
        .iter()
        .map(|item| item.severity)
        .max()
        .unwrap_or(Severity::Info);
    let confidence = if evidence
        .iter()
        .any(|item| item.confidence == Confidence::High && item.severity >= Severity::High)
    {
        Confidence::High
    } else if evidence
        .iter()
        .any(|item| item.severity >= Severity::Medium)
    {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let findings = build_findings(evidence);
    let timeline = build_timeline(evidence);
    let gaps = build_gaps(evidence);
    let recommendations = build_recommendations(evidence, risk, ai_risk_adjustment.as_ref());
    let evidence_summaries = build_evidence_summaries(evidence);
    let conclusion = conclusion_text(risk, confidence, &findings, evidence);

    InvestigationReport {
        case_id: ctx.case_id.clone(),
        question: ctx.question.clone(),
        mode: ctx.mode,
        started_at: ctx.started_at,
        generated_at: Utc::now(),
        host,
        since: ctx.since.clone(),
        scope,
        conclusion,
        risk,
        ai_adjusted_risk: ai_risk_adjustment.as_ref().map(|item| item.risk),
        ai_risk_rationale: ai_risk_adjustment.map(|item| item.rationale),
        confidence,
        findings,
        timeline,
        evidence_count: evidence.len(),
        evidence_summaries,
        gaps,
        recommendations,
        ai_synthesis,
    }
}

pub fn write_report_files(
    report: &InvestigationReport,
    case_dir: &Path,
    output: Option<&Path>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("serialize report json")?;
    fs::write(case_dir.join("report.json"), json)
        .with_context(|| format!("write {}", case_dir.join("report.json").display()))?;
    let md = to_markdown(report);
    fs::write(case_dir.join("report.md"), &md)
        .with_context(|| format!("write {}", case_dir.join("report.md").display()))?;
    if let Some(path) = output {
        fs::write(path, &md).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

pub fn to_markdown(report: &InvestigationReport) -> String {
    let mut out = String::new();
    out.push_str("# Open Investigator Server IR 调查报告\n\n");
    out.push_str("## 1. 调查结论\n\n");
    out.push_str(&format!("- Case：`{}`\n", report.case_id));
    out.push_str(&format!("- 调查问题：{}\n", report.question));
    out.push_str(&format!("- 规则风险等级：{}\n", report.risk));
    if let Some(ai_risk) = report.ai_adjusted_risk {
        out.push_str(&format!("- AI 调整建议：{}\n", ai_risk));
        if let Some(rationale) = &report.ai_risk_rationale {
            out.push_str(&format!(
                "- AI 调整理由：{}\n",
                rationale.replace('\n', " ")
            ));
        }
    }
    out.push_str(&format!("- 置信度：{}\n", report.confidence));
    out.push_str(&format!("- 核心判断：{}\n\n", report.conclusion));
    if let Some(ai) = &report.ai_synthesis {
        out.push_str("## 2. AI 调查员综合判断\n\n");
        out.push_str(ai.trim());
        out.push_str("\n\n");
    }
    out.push_str("## 3. 调查范围\n\n");
    out.push_str(&format!("- 主机：{}\n", report.host.hostname));
    out.push_str(&format!("- OS：{}\n", report.host.os));
    if let Some(pretty) = &report.host.os_pretty {
        out.push_str(&format!("- OS 详情：{}\n", pretty.replace('\n', " ")));
    }
    out.push_str(&format!("- 时间范围参数：{}\n", report.since));
    out.push_str(&format!("- 模式：{}\n", report.mode));
    if !report.scope.is_empty() {
        out.push_str(&format!("- 已执行检查：{}\n", report.scope.join(", ")));
    }
    out.push('\n');

    out.push_str("## 4. 关键发现\n\n");
    if report.findings.is_empty() {
        out.push_str("未形成中高风险发现。\n\n");
    } else {
        out.push_str("| 编号 | 严重性 | 置信度 | 发现 | 证据 |\n");
        out.push_str("|---|---|---|---|---|\n");
        for finding in &report.findings {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                finding.id,
                finding.severity,
                finding.confidence,
                escape_table(&finding.title),
                escape_table(&finding.evidence_ids.join(", "))
            ));
        }
        out.push('\n');
    }

    out.push_str("## 5. 时间线\n\n");
    if report.timeline.is_empty() {
        out.push_str("未提取到带时间戳的关键证据。\n\n");
    } else {
        out.push_str("| 时间 | 事件 | 来源 | 证据 ID |\n");
        out.push_str("|---|---|---|---|\n");
        for event in report.timeline.iter().take(80) {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                escape_table(&event.time),
                escape_table(&event.title),
                escape_table(&event.source),
                event.evidence_id
            ));
        }
        out.push('\n');
    }

    out.push_str("## 6. 证据详情\n\n");
    out.push_str("完整原始证据见 `evidence.jsonl`；完整命令审计见 `commands.log`。以下为前 120 条证据摘要。\n\n");
    out.push_str("| 证据 ID | 严重性 | 置信度 | 分类 | 来源 | 摘要 |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for ev in report.evidence_summaries.iter().take(120) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            ev.id,
            ev.severity,
            ev.confidence,
            escape_table(&ev.category),
            escape_table(&ev.source),
            escape_table(&format!("{}：{}", ev.title, ev.summary))
        ));
    }
    if report.evidence_summaries.is_empty() {
        out.push_str("| - | info | low | - | - | 未采集到证据；请检查权限或日志源。 |\n");
    }
    out.push('\n');

    out.push_str("## 7. 证据缺口\n\n");
    if report.gaps.is_empty() {
        out.push_str("- 当前未记录明确证据缺口。\n\n");
    } else {
        for gap in &report.gaps {
            out.push_str(&format!("- {}\n", gap));
        }
        out.push('\n');
    }

    out.push_str("## 8. 建议人工下一步\n\n");
    for rec in &report.recommendations {
        out.push_str(&format!("- {}\n", rec));
    }
    out.push('\n');
    out.push_str("## 9. 说明\n\n");
    out.push_str("本工具默认只执行只读调查，不执行隔离、封禁、杀进程、删文件、改账号、改防火墙等处置动作。报告中的处置项均为人工建议。\n");
    out
}

fn build_evidence_summaries(evidence: &[Evidence]) -> Vec<EvidenceSummary> {
    evidence
        .iter()
        .map(|ev| EvidenceSummary {
            id: ev.id.clone(),
            severity: ev.severity,
            confidence: ev.confidence,
            category: ev.category.clone(),
            source: ev.source.clone(),
            title: ev.title.clone(),
            summary: ev.summary.clone(),
            tags: ev.tags.clone(),
        })
        .collect()
}

fn build_findings(evidence: &[Evidence]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ev in evidence
        .iter()
        .filter(|item| item.severity >= Severity::Medium)
        .take(30)
    {
        let id = format!("F-{:03}", findings.len() + 1);
        findings.push(Finding {
            id,
            severity: ev.severity,
            confidence: ev.confidence,
            title: ev.title.clone(),
            summary: ev.summary.clone(),
            evidence_ids: vec![ev.id.clone()],
            tags: ev.tags.clone(),
        });
    }
    findings
}

fn build_timeline(evidence: &[Evidence]) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    for ev in evidence {
        if let Some(time) = &ev.event_time {
            out.push(TimelineEvent {
                time: time.clone(),
                title: ev.title.clone(),
                source: ev.source.clone(),
                evidence_id: ev.id.clone(),
            });
        } else if ev
            .tags
            .iter()
            .any(|tag| tag.contains("ioc") || tag.contains("web") || tag.contains("auth"))
        {
            out.push(TimelineEvent {
                time: ev.collected_at.to_rfc3339(),
                title: ev.title.clone(),
                source: ev.source.clone(),
                evidence_id: ev.id.clone(),
            });
        }
    }
    out.sort_by(|a, b| a.time.cmp(&b.time));
    out
}

fn build_gaps(evidence: &[Evidence]) -> Vec<String> {
    let mut gaps = Vec::new();
    if !evidence.iter().any(|ev| ev.category == "logs") {
        gaps.push("未完成日志源发现，结论覆盖面不足。".to_string());
    }
    if evidence
        .iter()
        .any(|ev| ev.tags.iter().any(|tag| tag == "java_memshell_gap"))
    {
        gaps.push("Java 内存马无法仅凭外部日志完全确认；如风险较高，建议人工结合线程栈、类加载器、路由表、JVM attach 工具或 EDR 内存证据复核。".to_string());
    }
    if !evidence.iter().any(|ev| ev.category == "auth") {
        gaps.push("未发现或未读取认证日志，无法充分判断登录链路。".to_string());
    }
    if evidence
        .iter()
        .any(|ev| ev.tags.iter().any(|tag| tag == "ai_planning_error"))
    {
        gaps.push(
            "AI 追加调查规划失败；当前报告仍包含确定性 playbook 的证据，但缺少模型驱动的补充追问。"
                .to_string(),
        );
    }
    gaps
}

fn build_recommendations(
    evidence: &[Evidence],
    risk: Severity,
    ai_risk_adjustment: Option<&AiRiskAdjustment>,
) -> Vec<String> {
    let mut recs = Vec::new();
    if let Some(adjustment) = ai_risk_adjustment {
        recs.push(format!(
            "人工复核 AI 风险调整建议（{}）：{}",
            adjustment.risk, adjustment.rationale
        ));
    }
    if risk >= Severity::High {
        recs.push(
            "在企业现有 EDR/堡垒机/防火墙中按流程执行隔离、封禁或账号管控；本工具不直接执行处置。"
                .to_string(),
        );
        recs.push("保全相关日志、可疑文件、进程快照和网络连接快照，避免证据被覆盖。".to_string());
    }
    if evidence.iter().any(|ev| {
        ev.tags
            .iter()
            .any(|tag| tag.contains("webshell") || tag.contains("web_"))
    }) {
        recs.push(
            "人工复核 Web 根目录近期变化文件，并关联访问日志确认入口、上传点和执行链。".to_string(),
        );
    }
    if evidence.iter().any(|ev| {
        ev.tags
            .iter()
            .any(|tag| tag.contains("failed_login") || tag.contains("successful_login"))
    }) {
        recs.push("复核异常登录来源、成功登录账号、登录后行为和凭据泄露风险。".to_string());
    }
    if evidence
        .iter()
        .any(|ev| ev.tags.iter().any(|tag| tag.contains("persistence")))
    {
        recs.push(
            "人工复核 cron/systemd/计划任务/服务/Run 注册表/authorized_keys 等持久化点。"
                .to_string(),
        );
    }
    if evidence
        .iter()
        .any(|ev| ev.tags.iter().any(|tag| tag.contains("java")))
    {
        recs.push("Java 进程异常需结合应用上下文复核 Filter/Listener/Interceptor、Controller 路由、Agent、JSP/JAR/WAR 变化与线程栈。".to_string());
    }
    if recs.is_empty() {
        recs.push("未发现明确高风险证据；如仍怀疑异常，扩大时间范围或使用 `-m inv` 允许受控只读命令补充验证。".to_string());
    }
    recs
}

fn conclusion_text(
    risk: Severity,
    confidence: Confidence,
    findings: &[Finding],
    evidence: &[Evidence],
) -> String {
    if findings.is_empty() {
        return format!(
            "未在当前证据范围内形成中高风险发现；总体风险 {}，置信度 {}。",
            risk, confidence
        );
    }
    let top = findings
        .iter()
        .take(3)
        .map(|f| f.title.clone())
        .collect::<Vec<_>>()
        .join("；");
    format!(
        "发现 {} 个中高风险线索，核心包括：{}。总证据数 {}，总体风险 {}，置信度 {}。",
        findings.len(),
        top,
        evidence.len(),
        risk,
        confidence
    )
}

fn escape_table(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiRiskAdjustment {
    pub risk: Severity,
    pub rationale: String,
}

#[cfg(test)]
mod tests {
    use super::{build_report, to_markdown, AiRiskAdjustment};
    use crate::case::CaseContext;
    use crate::config::OiConfig;
    use crate::model::{Confidence, EvidenceDraft, HostProfile, InvestigationMode, Severity};
    use crate::store::EvidenceStore;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn report_keeps_rule_risk_when_ai_adjusts_risk() {
        let mut cfg = OiConfig::default();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        cfg.case_dir = std::env::temp_dir().join(format!("oi-report-test-{suffix}"));
        let ctx = CaseContext::new(&cfg, "scan", "test", "7d", InvestigationMode::Safe);
        let mut store = EvidenceStore::new(&ctx).expect("store");
        let ev = store
            .add(EvidenceDraft {
                event_time: None,
                category: "process".to_string(),
                source: "proc.snap".to_string(),
                title: "可疑进程行为".to_string(),
                summary: "发现临时目录解释器线索".to_string(),
                raw_excerpt: None,
                tags: vec!["suspicious_process".to_string()],
                severity: Severity::High,
                confidence: Confidence::Medium,
            })
            .expect("evidence");
        let adjustment = AiRiskAdjustment {
            risk: Severity::Low,
            rationale: "更像 Jupyter 沙箱噪声".to_string(),
        };

        let report = build_report(
            &ctx,
            HostProfile::unknown(),
            &[ev],
            vec!["guardrail.proc.snap".to_string()],
            Some("AI synthesis".to_string()),
            Some(adjustment),
        );

        assert_eq!(report.risk, Severity::High);
        assert_eq!(report.ai_adjusted_risk, Some(Severity::Low));
        assert_eq!(
            report.ai_risk_rationale.as_deref(),
            Some("更像 Jupyter 沙箱噪声")
        );
        let md = to_markdown(&report);
        assert!(md.contains("规则风险等级：high"));
        assert!(md.contains("AI 调整建议：low"));
        let _ = fs::remove_dir_all(cfg.case_dir);
    }
}
