# AI tool loop

Open Investigator uses actual Chat Completions tool/function calls, not a loose prompt-only summary.

## Flow

```text
1. CLI creates a case context.
2. Runtime performs minimal discovery and prepares a sealed tool list.
3. The model receives the user question and only the `oi_*` tool schema.
4. The model calls one or more tools.
5. Runtime normalizes, validates, and executes the tool call.
6. Evidence is appended to evidence.jsonl.
7. A compact observation is returned to the model as a tool result.
8. The model calls more tools or produces a final answer.
9. Guardrail collectors fill required evidence gaps.
10. report.md and report.json are generated.
```

## Tool names exposed to AI

```text
oi_ioc_find
oi_auth_check
oi_acct_snap
oi_proc_snap
oi_net_snap
oi_per_snap
oi_svc_snap
oi_web_check
oi_java_check
oi_mem_check
oi_file_recent
oi_container_check
oi_hist_check
oi_linux_deep
oi_windows_deep
oi_pkg_check
oi_ro_run
```

The internal dispatcher maps these to investigator actions such as `ioc.find`, `auth.check`, `proc.snap`, and `web.check`.

## Why guardrails remain

AI planning is useful, but production investigation cannot rely on a model never skipping a critical category. Therefore, after the AI-first loop, the runtime can run a deterministic guardrail baseline for the case type. This ensures required evidence areas such as auth, process, network, persistence, and web context are covered.

The setting is:

```toml
ai_guardrail_baseline = true
```

Disable only for testing pure model autonomy.
