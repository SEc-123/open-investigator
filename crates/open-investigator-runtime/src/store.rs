use crate::case::CaseContext;
use crate::model::{CommandRecord, Evidence, EvidenceDraft};
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct EvidenceStore {
    case_id: String,
    host_name: String,
    case_dir: PathBuf,
    evidence_path: PathBuf,
    commands_path: PathBuf,
    next_evidence: usize,
}

impl EvidenceStore {
    pub fn new(ctx: &CaseContext) -> Result<Self> {
        ctx.prepare()?;
        let evidence_path = ctx.case_dir.join("evidence.jsonl");
        let commands_path = ctx.case_dir.join("commands.log");
        touch(&evidence_path)?;
        touch(&commands_path)?;
        Ok(Self {
            case_id: ctx.case_id.clone(),
            host_name: "unknown".to_string(),
            case_dir: ctx.case_dir.clone(),
            evidence_path,
            commands_path,
            next_evidence: 1,
        })
    }

    pub fn case_dir(&self) -> &Path {
        &self.case_dir
    }

    pub fn set_host_name(&mut self, host_name: impl Into<String>) {
        let value = host_name.into();
        if !value.trim().is_empty() {
            self.host_name = value;
        }
    }

    pub fn add(&mut self, draft: EvidenceDraft) -> Result<Evidence> {
        let id = format!("ev-{number:06}", number = self.next_evidence);
        self.next_evidence += 1;
        let evidence = Evidence {
            id,
            case_id: self.case_id.clone(),
            host: self.host_name.clone(),
            collected_at: Utc::now(),
            event_time: draft.event_time,
            category: draft.category,
            source: draft.source,
            title: draft.title,
            summary: draft.summary,
            raw_excerpt: draft.raw_excerpt,
            tags: draft.tags,
            severity: draft.severity,
            confidence: draft.confidence,
        };
        append_json_line(&self.evidence_path, &evidence)?;
        Ok(evidence)
    }

    pub fn record_command(&self, record: &CommandRecord) -> Result<()> {
        append_json_line(&self.commands_path, record)
    }

    pub fn load_evidence(&self) -> Result<Vec<Evidence>> {
        let raw = fs::read_to_string(&self.evidence_path)
            .with_context(|| format!("read {}", self.evidence_path.display()))?;
        let mut out = Vec::new();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Evidence>(line) {
                out.push(value);
            }
        }
        Ok(out)
    }
}

fn touch(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("touch {}", path.display()))?;
    Ok(())
}

fn append_json_line<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let raw = serde_json::to_string(value).context("serialize json line")?;
    writeln!(file, "{raw}").with_context(|| format!("append {}", path.display()))?;
    Ok(())
}
