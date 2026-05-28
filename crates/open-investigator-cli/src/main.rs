use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use open_investigator_runtime::policy::ReadonlyPolicy;
use open_investigator_runtime::{CaseContext, InvestigationEngine, InvestigationMode, OiConfig};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "oi")]
#[command(about = "Open Investigator: read-only AI server incident investigator")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    #[command(alias = "doc")]
    Doctor,
    Ai(AiCmd),
    #[command(alias = "investigate")]
    Ask(AskCmd),
    Scan(RunArgs),
    Ip(IpCmd),
    Login(LoginCmd),
    Web(WebCmd),
    Java(RunArgs),
    #[command(alias = "per")]
    Persist(RunArgs),
    #[command(alias = "ps")]
    Process(RunArgs),
    #[command(alias = "net")]
    Network(NetCmd),
    #[command(alias = "svc")]
    Service(RunArgs),
    #[command(alias = "cont")]
    Container(RunArgs),
    #[command(alias = "hist")]
    History(RunArgs),
    Mem(RunArgs),
    #[command(alias = "pkg")]
    Package(RunArgs),
    Deep(RunArgs),
    Logs(RunArgs),
    File(FileCmd),
    #[command(alias = "rep")]
    Report(ReportCmd),
    Case(CaseCmd),
    #[command(alias = "pol")]
    Policy(PolicyCmd),
    #[command(alias = "sh")]
    Shell(ShellCmd),
}

#[derive(Args)]
struct AiCmd {
    #[command(subcommand)]
    action: AiAction,
}

#[derive(Subcommand)]
enum AiAction {
    Show,
    Status,
}

#[derive(Args, Clone)]
struct RunArgs {
    #[arg(short = 's', long, default_value = "7d")]
    since: String,
    #[arg(short = 'm', long, default_value = "safe")]
    mode: String,
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,
    #[arg(long)]
    no_ai: bool,
    /// Enable JVM internal inspection for Java memory-shell investigations.
    /// Requires investigator mode by default because it attaches to target JVMs.
    #[arg(long = "java-deep")]
    java_deep: bool,
    /// Explicitly allow heap dump creation into the case artifact directory.
    /// Requires --java-deep and -m inv.
    #[arg(long = "heap-dump")]
    heap_dump: bool,
    /// Explicitly allow JFR dump creation into the case artifact directory.
    /// Requires --java-deep and -m inv.
    #[arg(long = "jfr-dump")]
    jfr_dump: bool,
}

#[derive(Args)]
struct AskCmd {
    question: String,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct IpCmd {
    ip: String,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct LoginCmd {
    #[arg(long)]
    ip: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct WebCmd {
    #[arg(long)]
    ip: Option<String>,
    #[arg(long = "root")]
    root: Option<PathBuf>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct NetCmd {
    #[arg(long)]
    ip: Option<String>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct FileCmd {
    #[arg(long)]
    path: Option<PathBuf>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args)]
struct ReportCmd {
    case_id: Option<String>,
}

#[derive(Args)]
struct ShellCmd {
    command: String,
    #[arg(short = 'm', long, default_value = "safe")]
    mode: String,
}

#[derive(Args)]
struct CaseCmd {
    #[command(subcommand)]
    action: CaseAction,
}

#[derive(Subcommand)]
enum CaseAction {
    #[command(alias = "list")]
    Ls,
    Show {
        case_id: String,
    },
    Open {
        case_id: String,
    },
}

#[derive(Args)]
struct PolicyCmd {
    #[command(subcommand)]
    action: PolicyAction,
}

#[derive(Subcommand)]
enum PolicyAction {
    Show,
    Test { command: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = OiConfig::load_or_default();
    match cli.command {
        Commands::Init => {
            let path = OiConfig::write_default()?;
            println!("created config: {}", path.display());
            println!("set OPENAI_API_KEY to enable AI synthesis; deterministic collection works without it");
        }
        Commands::Doctor => doctor(&cfg)?,
        Commands::Ai(cmd) => handle_ai(&cfg, cmd)?,
        Commands::Ask(cmd) => {
            let ioc = extract_ipv4(&cmd.question);
            let ctx =
                make_ctx(&cfg, "ask", cmd.question, cmd.run)?.with_ioc(ioc, Some("ip".to_string()));
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Scan(args) => {
            let ctx = make_ctx(&cfg, "scan", "快速服务器调查", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Ip(cmd) => {
            let question = format!("调查可疑 IP {} 在本机最近活动与攻击迹象", cmd.ip);
            let ctx = make_ctx(&cfg, "ip", question, cmd.run)?
                .with_ioc(Some(cmd.ip), Some("ip".to_string()));
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Login(cmd) => {
            let target = cmd
                .ip
                .clone()
                .or(cmd.user.clone())
                .unwrap_or_else(|| "all".to_string());
            let question = format!("调查登录异常：{}", target);
            let ctx = make_ctx(&cfg, "login", question, cmd.run)?
                .with_ioc(cmd.ip, Some("ip".to_string()));
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Web(cmd) => {
            let question = "调查 Web/WebShell/中间件异常";
            let ctx = make_ctx(&cfg, "web", question, cmd.run)?
                .with_ioc(cmd.ip, Some("ip".to_string()))
                .with_web_root(cmd.root);
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Java(args) => {
            let ctx = make_ctx(&cfg, "java", "调查 Java 进程异常与内存马线索", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Persist(args) => {
            let ctx = make_ctx(&cfg, "per", "调查持久化与自启动项", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Process(args) => {
            let ctx = make_ctx(&cfg, "ps", "调查进程异常", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Network(cmd) => {
            let ctx = make_ctx(&cfg, "net", "调查网络连接异常", cmd.run)?
                .with_ioc(cmd.ip, Some("ip".to_string()));
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Service(args) => {
            let ctx = make_ctx(&cfg, "svc", "调查服务/daemon 异常", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Container(args) => {
            let ctx = make_ctx(&cfg, "cont", "调查容器/Docker/CRI/Kubernetes 异常", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::History(args) => {
            let ctx = make_ctx(&cfg, "hist", "调查命令历史中的可疑线索", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Mem(args) => {
            let ctx = make_ctx(&cfg, "mem", "低扰动内存异常外围调查", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Package(args) => {
            let ctx = make_ctx(&cfg, "pkg", "调查安装包/程序列表异常", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Deep(args) => {
            let ctx = make_ctx(&cfg, "deep", "平台深度只读调查", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Logs(args) => {
            let ctx = make_ctx(&cfg, "logs", "发现服务器日志源", args)?;
            run_case(&mut cfg, ctx).await?;
        }
        Commands::File(cmd) => {
            let ctx = make_ctx(&cfg, "file", "调查近期文件变化", cmd.run)?.with_path(cmd.path);
            run_case(&mut cfg, ctx).await?;
        }
        Commands::Report(cmd) => print_report(&cfg, cmd.case_id)?,
        Commands::Case(cmd) => handle_case(&cfg, cmd)?,
        Commands::Policy(cmd) => handle_policy(cmd)?,
        Commands::Shell(cmd) => handle_shell(&cfg, cmd)?,
    }
    Ok(())
}

fn make_ctx(
    cfg: &OiConfig,
    command: &str,
    question: impl Into<String>,
    args: RunArgs,
) -> Result<CaseContext> {
    let mode = parse_mode(&args.mode)?;
    let mut ctx = CaseContext::new(cfg, command, question, args.since, mode)
        .with_output(args.out)
        .with_java_deep(args.java_deep || cfg.java_deep_enabled)
        .with_java_heap_dump(args.heap_dump || cfg.java_heap_dump_enabled)
        .with_java_jfr_dump(args.jfr_dump || cfg.java_jfr_dump_enabled);
    if args.no_ai {
        ctx = ctx.without_ai();
    }
    Ok(ctx)
}

async fn run_case(cfg: &mut OiConfig, ctx: CaseContext) -> Result<()> {
    println!("[case] {}", ctx.case_id);
    println!("[mode] {}", ctx.mode);
    println!("[target] {}", ctx.display_target());
    println!("[1/5] collect minimal host profile and log sources");
    println!("[2/5] AI investigator plans and calls sealed read-only tools");
    println!("[3/5] guardrail playbook fills missing core coverage");
    println!("[4/5] write evidence and command audit");
    println!("[5/5] synthesize timeline, findings, gaps, and report");
    let engine = InvestigationEngine::new(cfg.clone());
    let report = engine.run(ctx).await?;
    println!();
    println!("结论：{}", report.conclusion);
    println!("风险等级：{}", report.risk);
    println!("置信度：{}", report.confidence);
    println!("证据数：{}", report.evidence_count);
    println!(
        "报告：{}/report.md",
        cfg.case_dir.join(&report.case_id).display()
    );
    println!(
        "证据：{}/evidence.jsonl",
        cfg.case_dir.join(&report.case_id).display()
    );
    Ok(())
}

fn handle_ai(cfg: &OiConfig, cmd: AiCmd) -> Result<()> {
    match cmd.action {
        AiAction::Show | AiAction::Status => {
            println!("Open Investigator AI configuration");
            println!("enabled: {}", cfg.ai_enabled);
            println!("planning_enabled: {}", cfg.ai_planning_enabled);
            println!("ai_first: {}", cfg.ai_first);
            println!("guardrail_baseline: {}", cfg.ai_guardrail_baseline);
            println!("base_url: {}", cfg.base_url);
            println!("model: {}", cfg.model);
            println!("planning_model: {}", cfg.planning_model());
            println!("synthesis_model: {}", cfg.synthesis_model());
            println!("api_key_env: {}", cfg.api_key_env);
            println!("api_key_present: {}", cfg.api_key_available());
            println!("max_rounds: {}", cfg.ai_max_rounds);
            println!("max_actions_per_round: {}", cfg.ai_max_actions_per_round);
            println!("context_evidence_limit: {}", cfg.ai_context_evidence_limit);
            println!("context_char_limit: {}", cfg.ai_context_char_limit);
            println!(
                "request_timeout_seconds: {}",
                cfg.ai_request_timeout_seconds
            );
            println!("java_deep_enabled: {}", cfg.java_deep_enabled);
            println!("java_deep_requires_inv: {}", cfg.java_deep_requires_inv);
            println!("java_heap_dump_enabled: {}", cfg.java_heap_dump_enabled);
            println!("java_jfr_dump_enabled: {}", cfg.java_jfr_dump_enabled);
            println!("java_deep_max_pids: {}", cfg.java_deep_max_pids);
        }
    }
    Ok(())
}

fn doctor(cfg: &OiConfig) -> Result<()> {
    println!("Open Investigator doctor");
    println!("config: {}", OiConfig::config_path().display());
    println!("case_dir: {}", cfg.case_dir.display());
    println!("model: {}", cfg.model);
    println!("planning_model: {}", cfg.planning_model());
    println!("synthesis_model: {}", cfg.synthesis_model());
    println!("base_url: {}", cfg.base_url);
    println!("api_key_env: {}", cfg.api_key_env);
    println!(
        "api_key: {}",
        if cfg.api_key_available() {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "ai: enabled={} planning={} ai_first={} guardrail={} rounds={} actions_per_round={}",
        cfg.ai_enabled,
        cfg.ai_planning_enabled,
        cfg.ai_first,
        cfg.ai_guardrail_baseline,
        cfg.ai_max_rounds,
        cfg.ai_max_actions_per_round
    );
    println!(
        "java_deep: enabled={} requires_inv={} heap_dump={} jfr_dump={} max_pids={}",
        cfg.java_deep_enabled,
        cfg.java_deep_requires_inv,
        cfg.java_heap_dump_enabled,
        cfg.java_jfr_dump_enabled,
        cfg.java_deep_max_pids
    );
    println!("os: {}", std::env::consts::OS);
    println!(
        "policy sample: {}",
        ReadonlyPolicy::new(InvestigationMode::Inv)
            .validate("ps auxww")
            .reason
    );
    fs::create_dir_all(&cfg.case_dir)
        .with_context(|| format!("create {}", cfg.case_dir.display()))?;
    Ok(())
}

fn print_report(cfg: &OiConfig, case_id: Option<String>) -> Result<()> {
    let dir = resolve_case_dir(cfg, case_id)?;
    let path = dir.join("report.md");
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    println!("{raw}");
    Ok(())
}

fn handle_case(cfg: &OiConfig, cmd: CaseCmd) -> Result<()> {
    match cmd.action {
        CaseAction::Ls => {
            for dir in list_case_dirs(&cfg.case_dir)? {
                println!(
                    "{}",
                    dir.file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("unknown")
                );
            }
        }
        CaseAction::Show { case_id } | CaseAction::Open { case_id } => {
            let dir = cfg.case_dir.join(case_id);
            let report = dir.join("report.md");
            if report.exists() {
                println!("{}", fs::read_to_string(&report)?);
            } else {
                println!("case dir: {}", dir.display());
                for entry in
                    fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))?
                {
                    let entry = entry?;
                    println!("{}", entry.path().display());
                }
            }
        }
    }
    Ok(())
}

fn handle_policy(cmd: PolicyCmd) -> Result<()> {
    match cmd.action {
        PolicyAction::Show => {
            println!("safe: sealed investigation tools only");
            println!("inv: sealed tools + readonly shell after command policy validation");
            println!("blocked: file modification, deletion, process kill, service change, account change, firewall change, download/upload, interactive shells");
        }
        PolicyAction::Test { command } => {
            let decision = ReadonlyPolicy::new(InvestigationMode::Inv).validate(&command);
            println!(
                "{}: {}",
                if decision.allowed {
                    "ALLOWED"
                } else {
                    "DENIED"
                },
                decision.reason
            );
        }
    }
    Ok(())
}

fn handle_shell(cfg: &OiConfig, cmd: ShellCmd) -> Result<()> {
    let mode = parse_mode(&cmd.mode)?;
    let ctx = CaseContext::new(
        cfg,
        "sh",
        format!("readonly shell: {}", cmd.command),
        "now",
        mode,
    );
    let store = open_investigator_runtime::EvidenceStore::new(&ctx)?;
    let policy = ReadonlyPolicy::new(mode);
    let mut runner = open_investigator_runtime::CommandRunner::new(cfg, policy);
    let out = runner.run_ro(&store, &cmd.command, "manual readonly shell")?;
    if !out.allowed {
        println!("DENIED: {}", out.reason);
        return Ok(());
    }
    if !out.stdout.is_empty() {
        println!("{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        eprintln!("{}", out.stderr);
    }
    Ok(())
}

fn parse_mode(value: &str) -> Result<InvestigationMode> {
    value
        .parse::<InvestigationMode>()
        .map_err(|err| anyhow!(err))
}

fn resolve_case_dir(cfg: &OiConfig, case_id: Option<String>) -> Result<PathBuf> {
    if let Some(case_id) = case_id {
        return Ok(cfg.case_dir.join(case_id));
    }
    latest_case_dir(&cfg.case_dir)
        .ok_or_else(|| anyhow!("no cases found in {}", cfg.case_dir.display()))
}

fn latest_case_dir(root: &Path) -> Option<PathBuf> {
    let dirs = list_case_dirs(root).ok()?;
    dirs.into_iter().last()
}

fn list_case_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    if !root.exists() {
        return Ok(dirs);
    }
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn extract_ipv4(value: &str) -> Option<String> {
    for token in value.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        if token.chars().filter(|ch| *ch == '.').count() == 3 {
            return Some(token.to_string());
        }
    }
    None
}
