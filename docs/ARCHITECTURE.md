# Open Investigator Architecture

## Product shape

Open Investigator is a single-product repository. The only binary is `oi`; the only runtime is the Open Investigator runtime.

```text
User CLI
  -> CaseContext
  -> InvestigationEngine
  -> minimal discovery: host.info + logs.find
  -> AI investigator loop over sealed function tools
  -> deterministic guardrail coverage when needed
  -> EvidenceStore
  -> report builder + optional AI synthesis
```

The core design is **AI-first but policy-bounded**:

- AI decides what to inspect next.
- Runtime executes only sealed read-only tools.
- `oi_ro_run` exists only in `inv` mode and still passes read-only policy.
- Guardrail coverage prevents a bad or incomplete AI plan from missing key host categories.

## Crates

```text
crates/open-investigator-cli
  CLI parser and user command surface.

crates/open-investigator-runtime
  Case model, config, evidence store, command policy, command runner,
  host/log/process/network/account/persistence/web/java/container collectors,
  AI investigator loop, tool registry, report generation.
```

## Runtime modules

| Module | Responsibility |
|---|---|
| `case.rs` | Case ID, case directory, command, question, mode, target options. |
| `config.rs` | Model/API/case-dir/limits/AI tool-loop settings. |
| `model.rs` | Evidence, findings, report, host profile, modes. |
| `store.rs` | Evidence JSONL and command audit log. |
| `policy.rs` | Read-only command validation. |
| `runner.rs` | Bounded command execution, timeout, truncation, audit. |
| `collector/` | OS-specific read-only collection and tagging. |
| `tools.rs` | Sealed investigation tool catalog and dispatcher. |
| `agent.rs` | Chat-completions function-tool loop: model tool calls -> runtime execution -> evidence observations -> continued model calls/final answer. |
| `playbook.rs` | InvestigationEngine and deterministic guardrail flow. |
| `analyst.rs` | Optional final evidence-grounded AI synthesis. |
| `report.rs` | JSON and Markdown report. |
| `util.rs` | Path, truncation, time-window, file helpers. |

## AI investigator loop

The AI does not receive raw shell access. It receives only OpenAI-compatible `oi_*` function tools.

```text
Round N request:
  - original user question
  - command and mode
  - IOC/path/web-root hints
  - tool schema list
  - accumulated conversation observations

Round N response:
  assistant tool_calls:
    oi_auth_check({...})
    oi_web_check({...})

Runtime:
  - normalize tool names
  - validate against sealed catalog
  - execute read-only collector
  - append evidence.jsonl
  - return compact tool observation message
```

The model can then call more tools or produce a final answer.

## Safe-mode AI-visible function tools

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
```

Investigator mode only:

```text
oi_java_deep
oi_java_dump
oi_ro_run
```

Internally these map to investigator actions such as `ioc.find`, `auth.check`, `proc.snap`, `web.check`, `java.check`, `java.deep`, and `java.dump`.

`java.deep` remains additionally gated by `--java-deep`; `java.dump` requires `--java-deep` plus `--heap-dump` or `--jfr-dump`. The raw read-only shell policy blocks JVM dump commands so artifact collection cannot bypass these collectors.

## Evidence model

Every evidence record includes:

- `id`
- `case_id`
- `host`
- `collected_at`
- optional event time
- category
- source
- title
- summary
- raw excerpt
- tags
- severity
- confidence

Reports reference evidence IDs, and raw evidence is preserved in JSONL form.

## Safety model

- Safe mode: sealed tools only.
- Investigator mode: sealed tools plus validated read-only command channel.
- Target system mutation is outside product scope.
- Output writes are restricted to case/report paths.
- Commands are limited by allowlist, deny tokens, timeout, output cap, and audit.

## Why guardrails remain

A production investigator must not miss obvious categories because a model chose a narrow plan. Therefore `ai_guardrail_baseline = true` by default. The guardrail does not replace AI; it fills missing required coverage after the AI has planned and queried.
