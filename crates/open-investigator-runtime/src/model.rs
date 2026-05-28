use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvestigationMode {
    Safe,
    Inv,
}

impl InvestigationMode {
    pub fn allows_readonly_shell(self) -> bool {
        matches!(self, Self::Inv)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Inv => "inv",
        }
    }
}

impl fmt::Display for InvestigationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InvestigationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "safe" | "s" => Ok(Self::Safe),
            "inv" | "investigator" | "i" => Ok(Self::Inv),
            other => Err(format!("unsupported mode `{other}`; use `safe` or `inv`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsKind {
    Linux,
    Windows,
    Macos,
    Unknown,
}

impl OsKind {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Unknown
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for OsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProfile {
    pub hostname: String,
    pub os: OsKind,
    pub os_pretty: Option<String>,
    pub kernel: Option<String>,
    pub timezone: Option<String>,
    pub uptime: Option<String>,
    pub current_user: Option<String>,
    pub is_admin: Option<bool>,
    pub ip_addresses: Vec<String>,
}

impl HostProfile {
    pub fn unknown() -> Self {
        Self {
            hostname: "unknown".to_string(),
            os: OsKind::current(),
            os_pretty: None,
            kernel: None,
            timezone: None,
            uptime: None,
            current_user: None,
            is_admin: None,
            ip_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub name: String,
    pub source_type: String,
    pub path: Option<PathBuf>,
    pub channel: Option<String>,
    pub exists: bool,
    pub readable: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub case_id: String,
    pub host: String,
    pub collected_at: DateTime<Utc>,
    pub event_time: Option<String>,
    pub category: String,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub raw_excerpt: Option<String>,
    pub tags: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceDraft {
    pub event_time: Option<String>,
    pub category: String,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub raw_excerpt: Option<String>,
    pub tags: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
}

impl EvidenceDraft {
    pub fn info(category: &str, source: &str, title: &str, summary: &str) -> Self {
        Self {
            event_time: None,
            category: category.to_string(),
            source: source.to_string(),
            title: title.to_string(),
            summary: summary.to_string(),
            raw_excerpt: None,
            tags: Vec::new(),
            severity: Severity::Info,
            confidence: Confidence::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: String,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub at: DateTime<Utc>,
    pub command: String,
    pub allowed: bool,
    pub reason: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub stdout_excerpt: Option<String>,
    pub stderr_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub summary: String,
    pub evidence_ids: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub time: String,
    pub title: String,
    pub source: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReport {
    pub case_id: String,
    pub question: String,
    pub mode: InvestigationMode,
    pub started_at: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,
    pub host: HostProfile,
    pub since: String,
    pub scope: Vec<String>,
    pub conclusion: String,
    pub risk: Severity,
    pub confidence: Confidence,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub evidence_count: usize,
    pub evidence_summaries: Vec<EvidenceSummary>,
    pub gaps: Vec<String>,
    pub recommendations: Vec<String>,
    pub ai_synthesis: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRunOutput {
    pub allowed: bool,
    pub command: String,
    pub reason: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}
