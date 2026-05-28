use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

/// Runtime configuration for Open Investigator.
///
/// The important product choice is that AI is used as an *orchestrator* over
/// sealed read-only tools. The model receives an OpenAI-compatible function-tool
/// surface, calls only `oi_*` investigation tools, observes structured evidence,
/// and continues the same tool loop until it can produce a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OiConfig {
    /// Default model for both planning and synthesis unless overridden below.
    pub model: String,
    /// Optional dedicated model for AI tool planning.
    pub planning_model: Option<String>,
    /// Optional dedicated model for final report synthesis.
    pub synthesis_model: Option<String>,
    /// OpenAI-compatible base URL, for example https://api.openai.com/v1.
    pub base_url: String,
    /// Primary environment variable used for the API key.
    pub api_key_env: String,
    /// Local writable case directory. The investigated host is otherwise treated as read-only.
    pub case_dir: PathBuf,
    pub max_commands: usize,
    pub command_timeout_seconds: u64,
    pub max_output_bytes: usize,
    /// Master AI switch. If disabled or no key is present, deterministic playbooks still run.
    pub ai_enabled: bool,
    /// Let the LLM autonomously call sealed follow-up tools through the AI tool loop.
    pub ai_planning_enabled: bool,
    /// Run AI before the deterministic command-specific guardrail playbook.
    /// This is what makes `oi ask` behave like a real investigator rather than a fixed scanner.
    pub ai_first: bool,
    /// After AI finishes, run a minimal guardrail baseline for required coverage.
    /// This prevents a bad model plan from missing critical categories.
    pub ai_guardrail_baseline: bool,
    /// Maximum AI tool-loop rounds per case. Keep bounded for production predictability.
    pub ai_max_rounds: usize,
    /// Maximum tool actions accepted from the AI per round.
    pub ai_max_actions_per_round: usize,
    /// Evidence records included in AI context.
    pub ai_context_evidence_limit: usize,
    /// Character budget for evidence context.
    pub ai_context_char_limit: usize,
    /// Model temperature for the AI tool loop.
    pub ai_planning_temperature: f32,
    /// Model temperature for final synthesis text.
    pub ai_synthesis_temperature: f32,
    /// HTTP timeout for AI provider requests.
    pub ai_request_timeout_seconds: u64,
}

impl Default for OiConfig {
    fn default() -> Self {
        Self {
            model: env::var("OPEN_INVESTIGATOR_MODEL")
                .unwrap_or_else(|_| "gpt-4.1-mini".to_string()),
            planning_model: env::var("OPEN_INVESTIGATOR_PLANNING_MODEL").ok(),
            synthesis_model: env::var("OPEN_INVESTIGATOR_SYNTHESIS_MODEL").ok(),
            base_url: env::var("OPENAI_BASE_URL")
                .or_else(|_| env::var("OPEN_INVESTIGATOR_BASE_URL"))
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            api_key_env: "OPEN_INVESTIGATOR_API_KEY".to_string(),
            case_dir: PathBuf::from(".oi/cases"),
            max_commands: 160,
            command_timeout_seconds: 30,
            max_output_bytes: 2_000_000,
            ai_enabled: true,
            ai_planning_enabled: true,
            ai_first: true,
            ai_guardrail_baseline: true,
            ai_max_rounds: 4,
            ai_max_actions_per_round: 5,
            ai_context_evidence_limit: 120,
            ai_context_char_limit: 36_000,
            ai_planning_temperature: 0.1,
            ai_synthesis_temperature: 0.2,
            ai_request_timeout_seconds: 90,
        }
    }
}

impl OiConfig {
    pub fn config_path() -> PathBuf {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(".open-investigator/config.toml");
        }
        if let Ok(user_profile) = env::var("USERPROFILE") {
            return PathBuf::from(user_profile).join(".open-investigator/config.toml");
        }
        PathBuf::from(".open-investigator/config.toml")
    }

    pub fn load_or_default() -> Self {
        let path = Self::config_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_else(|_| Self::default())
    }

    pub fn write_default() -> Result<PathBuf> {
        let cfg = Self::default();
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(&cfg).context("serialize default config")?;
        fs::write(&path, raw).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    pub fn api_key_available(&self) -> bool {
        self.api_key()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn api_key(&self) -> Option<String> {
        env::var(&self.api_key_env)
            .ok()
            .or_else(|| env::var("OPEN_INVESTIGATOR_API_KEY").ok())
            .or_else(|| env::var("OPENAI_API_KEY").ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub fn planning_model(&self) -> &str {
        self.planning_model.as_deref().unwrap_or(&self.model)
    }

    pub fn synthesis_model(&self) -> &str {
        self.synthesis_model.as_deref().unwrap_or(&self.model)
    }
}
