use crate::config::OiConfig;
use crate::model::{CommandRecord, ToolRunOutput};
use crate::policy::{validate_readonly_command, PolicyDecision, ReadonlyPolicy};
use crate::store::EvidenceStore;
use crate::util::truncate_text;
use anyhow::{Context, Result};
use chrono::Utc;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct CommandRunner {
    policy: ReadonlyPolicy,
    timeout: Duration,
    max_output_bytes: usize,
    max_commands: usize,
    command_count: usize,
}

impl CommandRunner {
    pub fn new(cfg: &OiConfig, policy: ReadonlyPolicy) -> Self {
        Self {
            policy,
            timeout: Duration::from_secs(cfg.command_timeout_seconds),
            max_output_bytes: cfg.max_output_bytes,
            max_commands: cfg.max_commands,
            command_count: 0,
        }
    }

    pub fn run_ro(
        &mut self,
        store: &EvidenceStore,
        command: &str,
        reason: &str,
    ) -> Result<ToolRunOutput> {
        let decision = self.policy.validate(command);
        self.execute(store, command, reason, decision)
    }

    pub fn run_builtin(
        &mut self,
        store: &EvidenceStore,
        command: &str,
        reason: &str,
    ) -> Result<ToolRunOutput> {
        let decision = validate_readonly_command(command);
        self.execute(store, command, reason, decision)
    }

    fn execute(
        &mut self,
        store: &EvidenceStore,
        command: &str,
        reason: &str,
        decision: PolicyDecision,
    ) -> Result<ToolRunOutput> {
        if !decision.allowed {
            let record = CommandRecord {
                at: Utc::now(),
                command: command.to_string(),
                allowed: false,
                reason: decision.reason.clone(),
                exit_code: None,
                duration_ms: None,
                stdout_excerpt: None,
                stderr_excerpt: None,
            };
            store.record_command(&record)?;
            return Ok(ToolRunOutput {
                allowed: false,
                command: command.to_string(),
                reason: decision.reason,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
            });
        }

        if self.command_count >= self.max_commands {
            let reason = format!("command limit reached ({})", self.max_commands);
            let record = CommandRecord {
                at: Utc::now(),
                command: command.to_string(),
                allowed: false,
                reason: reason.clone(),
                exit_code: None,
                duration_ms: None,
                stdout_excerpt: None,
                stderr_excerpt: None,
            };
            store.record_command(&record)?;
            return Ok(ToolRunOutput {
                allowed: false,
                command: command.to_string(),
                reason,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
            });
        }

        self.command_count += 1;
        let start = Instant::now();
        let mut child = shell_command(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn readonly command `{command}`"))?;

        let mut timed_out = false;
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if start.elapsed() >= self.timeout {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let output = child
            .wait_with_output()
            .with_context(|| format!("collect output for `{command}`"))?;
        let duration_ms = start.elapsed().as_millis();
        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if timed_out {
            stderr.push_str("\n[open-investigator] command timed out and was killed");
        }
        let original_len = stdout.len() + stderr.len();
        let stdout_limit = self.max_output_bytes.saturating_mul(3) / 4;
        let stderr_limit = self.max_output_bytes.saturating_sub(stdout_limit);
        stdout = truncate_text(&stdout, stdout_limit);
        stderr = truncate_text(&stderr, stderr_limit);
        let truncated = original_len > stdout.len() + stderr.len();
        let exit_code = output.status.code();

        let record = CommandRecord {
            at: Utc::now(),
            command: command.to_string(),
            allowed: true,
            reason: reason.to_string(),
            exit_code,
            duration_ms: Some(duration_ms),
            stdout_excerpt: Some(truncate_text(&stdout, 4_000)),
            stderr_excerpt: Some(truncate_text(&stderr, 4_000)),
        };
        store.record_command(&record)?;

        Ok(ToolRunOutput {
            allowed: true,
            command: command.to_string(),
            reason: decision.reason,
            exit_code,
            stdout,
            stderr,
            truncated,
        })
    }
}

fn shell_command(command: &str) -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("powershell.exe");
        cmd.arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(command);
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(command);
        cmd
    }
}
