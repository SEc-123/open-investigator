use crate::agent::run_ai_investigation_loop;
use crate::analyst::synthesize_with_ai;
use crate::case::CaseContext;
use crate::collector;
use crate::config::OiConfig;
use crate::model::{HostProfile, InvestigationReport, LogSource};
use crate::policy::ReadonlyPolicy;
use crate::report::{build_report, write_report_files};
use crate::runner::CommandRunner;
use crate::store::EvidenceStore;
use anyhow::Result;
use std::collections::HashSet;

#[derive(Clone)]
pub struct InvestigationEngine {
    cfg: OiConfig,
}

impl InvestigationEngine {
    pub fn new(cfg: OiConfig) -> Self {
        Self { cfg }
    }

    /// Run a complete single-host investigation.
    ///
    /// Runtime shape:
    /// 1. Minimal deterministic discovery: host.info + logs.find.
    /// 2. AI-first investigation loop when configured and an API key is available.
    /// 3. Guardrail deterministic coverage to prevent missed core evidence categories.
    /// 4. Optional final AI synthesis over the accumulated evidence.
    pub async fn run(&self, ctx: CaseContext) -> Result<InvestigationReport> {
        let policy = ReadonlyPolicy::new(ctx.mode);
        let mut runner = CommandRunner::new(&self.cfg, policy);
        let mut store = EvidenceStore::new(&ctx)?;
        let mut scope = Vec::new();
        let mut coverage = HashSet::new();

        scope.push("host.info".to_string());
        coverage.insert("host.info".to_string());
        let host = collector::collect_host_profile(&mut store, &mut runner)?;

        scope.push("logs.find".to_string());
        coverage.insert("logs.find".to_string());
        let sources = collector::discover_logs(&mut store, &mut runner)?;

        if self.cfg.ai_first
            && self.cfg.ai_enabled
            && self.cfg.ai_planning_enabled
            && ctx.ai_enabled
        {
            let ai_tools =
                run_ai_investigation_loop(&self.cfg, &ctx, &mut store, &mut runner, &sources)
                    .await?;
            for tool in ai_tools {
                coverage.insert(tool.clone());
                scope.push(format!("ai.{tool}"));
            }
        }

        let ai_attempted = coverage
            .iter()
            .any(|tool| !matches!(tool.as_str(), "host.info" | "logs.find"));
        let should_run_guardrail = !self.cfg.ai_first
            || !self.cfg.ai_enabled
            || !self.cfg.ai_planning_enabled
            || !ctx.ai_enabled
            || !ai_attempted
            || self.cfg.ai_guardrail_baseline;

        if should_run_guardrail {
            run_deterministic_guardrail(
                &ctx,
                &mut store,
                &mut runner,
                &sources,
                &mut coverage,
                &mut scope,
            )?;
        }

        if !self.cfg.ai_first
            && self.cfg.ai_enabled
            && self.cfg.ai_planning_enabled
            && ctx.ai_enabled
        {
            let ai_tools =
                run_ai_investigation_loop(&self.cfg, &ctx, &mut store, &mut runner, &sources)
                    .await?;
            for tool in ai_tools {
                coverage.insert(tool.clone());
                scope.push(format!("ai.{tool}"));
            }
        }

        let evidence = store.load_evidence()?;
        let draft = build_report(&ctx, host.clone(), &evidence, scope.clone(), None, None);
        let ai_result = if ctx.ai_enabled && self.cfg.ai_enabled {
            synthesize_with_ai(&self.cfg, &draft, &evidence)
                .await
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let report = build_report(
            &ctx,
            host,
            &evidence,
            scope,
            ai_result.text,
            ai_result.risk_adjustment,
        );
        write_report_files(&report, store.case_dir(), ctx.output.as_deref())?;
        Ok(report)
    }
}

fn run_deterministic_guardrail(
    ctx: &CaseContext,
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
    coverage: &mut HashSet<String>,
    scope: &mut Vec<String>,
) -> Result<()> {
    match ctx.command.as_str() {
        "ip" => {
            if let Some(ioc) = ctx.ioc.as_deref() {
                run_tool("ioc.find", coverage, scope, || {
                    collector::search_ioc(store, runner, sources, ioc, &ctx.since)
                })?;
            }
            run_tool("auth.check", coverage, scope, || {
                collector::analyze_auth(
                    store,
                    runner,
                    sources,
                    ctx.ioc.as_deref(),
                    None,
                    &ctx.since,
                )
            })?;
            run_tool("web.check", coverage, scope, || {
                collector::analyze_web(store, sources, ctx)
            })?;
            run_tool("net.snap", coverage, scope, || {
                collector::snapshot_network(store, runner, ctx.ioc.as_deref())
            })?;
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
            run_tool("per.snap", coverage, scope, || {
                collector::snapshot_persistence(store, runner)
            })?;
            run_tool("svc.snap", coverage, scope, || {
                collector::snapshot_services(store, runner)
            })?;
        }
        "login" => {
            run_tool("auth.check", coverage, scope, || {
                collector::analyze_auth(
                    store,
                    runner,
                    sources,
                    ctx.ioc.as_deref(),
                    None,
                    &ctx.since,
                )
            })?;
            run_tool("acct.snap", coverage, scope, || {
                collector::snapshot_accounts(store, runner)
            })?;
            run_tool("per.snap", coverage, scope, || {
                collector::snapshot_persistence(store, runner)
            })?;
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
            run_tool("net.snap", coverage, scope, || {
                collector::snapshot_network(store, runner, ctx.ioc.as_deref())
            })?;
        }
        "web" => {
            run_tool("web.check", coverage, scope, || {
                collector::analyze_web(store, sources, ctx)
            })?;
            run_tool("java.check", coverage, scope, || {
                collector::analyze_java(store, runner)
            })?;
            maybe_run_java_deep(ctx, store, runner, coverage, scope)?;
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
            run_tool("net.snap", coverage, scope, || {
                collector::snapshot_network(store, runner, ctx.ioc.as_deref())
            })?;
            run_tool("file.recent", coverage, scope, || {
                collector::recent_files(store, ctx)
            })?;
        }
        "java" => {
            run_tool("java.check", coverage, scope, || {
                collector::analyze_java(store, runner)
            })?;
            run_tool("mem.check", coverage, scope, || {
                collector::memory_low_impact_without_java(store, runner)
            })?;
            maybe_run_java_deep(ctx, store, runner, coverage, scope)?;
            run_tool("web.check", coverage, scope, || {
                collector::analyze_web(store, sources, ctx)
            })?;
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
            run_tool("net.snap", coverage, scope, || {
                collector::snapshot_network(store, runner, ctx.ioc.as_deref())
            })?;
            run_tool("file.recent", coverage, scope, || {
                collector::recent_files(store, ctx)
            })?;
        }
        "mem" => {
            run_tool("mem.check", coverage, scope, || {
                collector::memory_low_impact(store, runner)
            })?;
            maybe_run_java_deep(ctx, store, runner, coverage, scope)?;
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
            run_tool("file.recent", coverage, scope, || {
                collector::recent_files(store, ctx)
            })?;
        }
        "per" | "persist" => {
            run_tool("per.snap", coverage, scope, || {
                collector::snapshot_persistence(store, runner)
            })?;
            run_tool("svc.snap", coverage, scope, || {
                collector::snapshot_services(store, runner)
            })?;
            run_tool("acct.snap", coverage, scope, || {
                collector::snapshot_accounts(store, runner)
            })?;
        }
        "ps" => {
            run_tool("proc.snap", coverage, scope, || {
                collector::snapshot_processes(store, runner)
            })?;
        }
        "net" => {
            run_tool("net.snap", coverage, scope, || {
                collector::snapshot_network(store, runner, ctx.ioc.as_deref())
            })?;
        }
        "svc" | "service" | "services" => {
            run_tool("svc.snap", coverage, scope, || {
                collector::snapshot_services(store, runner)
            })?;
        }
        "cont" | "container" => {
            run_tool("container.check", coverage, scope, || {
                collector::analyze_container(store, runner)
            })?;
        }
        "hist" | "history" => {
            run_tool("hist.check", coverage, scope, || {
                collector::analyze_history(store)
            })?;
        }
        "pkg" | "package" => {
            run_tool("pkg.check", coverage, scope, || {
                collector::analyze_packages(store, runner)
            })?;
        }
        "deep" => {
            run_tool("linux.deep", coverage, scope, || {
                collector::analyze_linux_deep(store, runner)
            })?;
            run_tool("windows.deep", coverage, scope, || {
                collector::analyze_windows_deep(store, runner)
            })?;
        }
        "logs" => {}
        "file" => {
            run_tool("file.recent", coverage, scope, || {
                collector::recent_files(store, ctx)
            })?;
        }
        "ask" | "scan" => {
            run_default_guardrail(ctx, store, runner, sources, coverage, scope)?;
        }
        _ => {
            run_default_guardrail(ctx, store, runner, sources, coverage, scope)?;
        }
    }
    Ok(())
}

fn run_default_guardrail(
    ctx: &CaseContext,
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    sources: &[LogSource],
    coverage: &mut HashSet<String>,
    scope: &mut Vec<String>,
) -> Result<()> {
    if let Some(ioc) = ctx.ioc.as_deref() {
        run_tool("ioc.find", coverage, scope, || {
            collector::search_ioc(store, runner, sources, ioc, &ctx.since)
        })?;
    }
    run_tool("auth.check", coverage, scope, || {
        collector::analyze_auth(store, runner, sources, ctx.ioc.as_deref(), None, &ctx.since)
    })?;
    run_tool("acct.snap", coverage, scope, || {
        collector::snapshot_accounts(store, runner)
    })?;
    run_tool("proc.snap", coverage, scope, || {
        collector::snapshot_processes(store, runner)
    })?;
    run_tool("net.snap", coverage, scope, || {
        collector::snapshot_network(store, runner, ctx.ioc.as_deref())
    })?;
    run_tool("per.snap", coverage, scope, || {
        collector::snapshot_persistence(store, runner)
    })?;
    run_tool("web.check", coverage, scope, || {
        collector::analyze_web(store, sources, ctx)
    })?;
    run_tool("java.check", coverage, scope, || {
        collector::analyze_java(store, runner)
    })?;
    run_tool("mem.check", coverage, scope, || {
        collector::memory_low_impact(store, runner)
    })?;
    maybe_run_java_deep(ctx, store, runner, coverage, scope)?;
    run_tool("svc.snap", coverage, scope, || {
        collector::snapshot_services(store, runner)
    })?;
    run_tool("container.check", coverage, scope, || {
        collector::analyze_container(store, runner)
    })?;
    run_tool("pkg.check", coverage, scope, || {
        collector::analyze_packages(store, runner)
    })?;
    run_tool("hist.check", coverage, scope, || {
        collector::analyze_history(store)
    })?;
    run_tool("linux.deep", coverage, scope, || {
        collector::analyze_linux_deep(store, runner)
    })?;
    run_tool("windows.deep", coverage, scope, || {
        collector::analyze_windows_deep(store, runner)
    })?;
    run_tool("file.recent", coverage, scope, || {
        collector::recent_files(store, ctx)
    })?;
    Ok(())
}

fn maybe_run_java_deep(
    ctx: &CaseContext,
    store: &mut EvidenceStore,
    runner: &mut CommandRunner,
    coverage: &mut HashSet<String>,
    scope: &mut Vec<String>,
) -> Result<()> {
    if ctx.java_deep {
        run_tool("java.deep", coverage, scope, || {
            collector::analyze_java_deep(store, runner, ctx, None)
        })?;
    }
    if ctx.java_artifacts_allowed() {
        run_tool("java.dump", coverage, scope, || {
            collector::java_dump_artifacts(store, runner, ctx, None)
        })?;
    }
    Ok(())
}

fn run_tool<F>(
    tool: &str,
    coverage: &mut HashSet<String>,
    scope: &mut Vec<String>,
    f: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if coverage.insert(tool.to_string()) {
        scope.push(format!("guardrail.{tool}"));
        f()?;
    }
    Ok(())
}

#[allow(dead_code)]
fn _host_profile_type_check(_: HostProfile) {}
