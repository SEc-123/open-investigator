use crate::config::OiConfig;
use crate::model::InvestigationMode;
use crate::util::now_case_id;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseContext {
    pub case_id: String,
    pub question: String,
    pub command: String,
    pub since: String,
    pub mode: InvestigationMode,
    pub ioc: Option<String>,
    pub ioc_type: Option<String>,
    pub web_root: Option<PathBuf>,
    pub path: Option<PathBuf>,
    pub case_dir: PathBuf,
    pub output: Option<PathBuf>,
    pub ai_enabled: bool,
    pub started_at: DateTime<Utc>,
}

impl CaseContext {
    pub fn new(
        cfg: &OiConfig,
        command: impl Into<String>,
        question: impl Into<String>,
        since: impl Into<String>,
        mode: InvestigationMode,
    ) -> Self {
        let case_id = now_case_id();
        let case_dir = cfg.case_dir.join(&case_id);
        Self {
            case_id,
            question: question.into(),
            command: command.into(),
            since: since.into(),
            mode,
            ioc: None,
            ioc_type: None,
            web_root: None,
            path: None,
            case_dir,
            output: None,
            ai_enabled: cfg.ai_enabled,
            started_at: Utc::now(),
        }
    }

    pub fn with_ioc(mut self, ioc: Option<String>, ioc_type: Option<String>) -> Self {
        self.ioc = ioc;
        self.ioc_type = ioc_type;
        self
    }

    pub fn with_web_root(mut self, web_root: Option<PathBuf>) -> Self {
        self.web_root = web_root;
        self
    }

    pub fn with_path(mut self, path: Option<PathBuf>) -> Self {
        self.path = path;
        self
    }

    pub fn with_output(mut self, output: Option<PathBuf>) -> Self {
        self.output = output;
        self
    }

    pub fn without_ai(mut self) -> Self {
        self.ai_enabled = false;
        self
    }

    pub fn prepare(&self) -> Result<()> {
        fs::create_dir_all(&self.case_dir)
            .with_context(|| format!("create case directory {}", self.case_dir.display()))?;
        let raw = serde_json::to_string_pretty(self).context("serialize case context")?;
        fs::write(self.case_dir.join("case.json"), raw)
            .with_context(|| format!("write {}", self.case_dir.join("case.json").display()))?;
        Ok(())
    }

    pub fn display_target(&self) -> String {
        if let Some(ioc) = &self.ioc {
            return ioc.clone();
        }
        if let Some(path) = &self.path {
            return path.display().to_string();
        }
        "local-server".to_string()
    }
}
