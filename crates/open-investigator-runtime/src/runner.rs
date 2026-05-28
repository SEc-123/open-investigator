use crate::config::OiConfig;
use crate::model::{CommandRecord, ToolRunOutput};
use crate::policy::{validate_readonly_command, PolicyDecision, ReadonlyPolicy};
use crate::store::EvidenceStore;
use crate::util::truncate_text;
use anyhow::{Context, Result};
use chrono::Utc;
use std::io::Read;
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

    /// Run an explicitly opted-in JVM diagnostic artifact command.
    ///
    /// This is intentionally not exposed to the AI as a raw shell primitive. It is
    /// used only by gated Open Investigator collectors after the user enables
    /// deep JVM artifact collection for the case.
    pub fn run_diagnostic_artifact(
        &mut self,
        store: &EvidenceStore,
        command: &str,
        reason: &str,
    ) -> Result<ToolRunOutput> {
        self.execute(
            store,
            command,
            reason,
            PolicyDecision::allow("explicitly enabled diagnostic artifact command"),
        )
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
        let stdout_cap = self.max_output_bytes;
        let stderr_cap = self.max_output_bytes;
        let stdout_reader = child
            .stdout
            .take()
            .map(|stdout| thread::spawn(move || read_limited(stdout, stdout_cap)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|stderr| thread::spawn(move || read_limited(stderr, stderr_cap)));

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

        let status = child
            .wait()
            .with_context(|| format!("collect status for `{command}`"))?;
        let (stdout_bytes, stdout_dropped) = join_reader(stdout_reader);
        let (stderr_bytes, stderr_dropped) = join_reader(stderr_reader);
        let duration_ms = start.elapsed().as_millis();
        let mut stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
        let mut stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
        if timed_out {
            stderr.push_str("\n[open-investigator] command timed out and was killed");
        }
        let original_len = stdout.len() + stderr.len();
        let stdout_limit = self.max_output_bytes.saturating_mul(3) / 4;
        let stderr_limit = self.max_output_bytes.saturating_sub(stdout_limit);
        stdout = truncate_text(&stdout, stdout_limit);
        stderr = truncate_text(&stderr, stderr_limit);
        let truncated =
            stdout_dropped || stderr_dropped || original_len > stdout.len() + stderr.len();
        let exit_code = status.code();

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

fn read_limited<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut dropped = false;
    let mut buf = [0_u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = cap.saturating_sub(out.len());
                if remaining == 0 {
                    dropped = true;
                    continue;
                }
                let take = n.min(remaining);
                out.extend_from_slice(&buf[..take]);
                if take < n {
                    dropped = true;
                }
            }
            Err(_) => {
                dropped = true;
                break;
            }
        }
    }
    (out, dropped)
}

fn join_reader(handle: Option<thread::JoinHandle<(Vec<u8>, bool)>>) -> (Vec<u8>, bool) {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(|| (Vec::new(), true))
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
