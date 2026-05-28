# Runtime and product boundary

Open Investigator is intentionally not a generic shell wrapper and not a fixed scanner. It uses a bounded AI investigation loop:

```text
agent turn
  -> model-visible tool surface
  -> model-selected tool calls
  -> runtime validation and execution
  -> tool observations appended back to model context
  -> repeated until final answer/report
```

## Runtime design

The runtime concepts are:

- one command-line product entrypoint;
- bounded case execution;
- model-driven tool calling;
- sealed tool registry;
- tool result observation loop;
- append-only evidence records;
- command audit log;
- final report generation;
- provider/model configuration through OpenAI-compatible Chat Completions.

## Outside product scope

The following surfaces are outside the Open Investigator product boundary and are not included in this repository:

- code editing and patch generation;
- source-code audit workflows;
- project search/indexing;
- IDE/desktop/chat UI layers;
- team/multi-agent orchestration;
- apps and connector discovery;
- web browsing/search tools;
- image tools;
- shell escalation;
- license or product gating services;
- automatic remediation/response actions.

## Investigation surface

Open Investigator exposes only server investigation tools to the model:

```text
surface: host logs, auth, process, network, accounts, persistence, web, Java, file, container, history, package evidence
```

The model works through a loop of tool calls and observations, but it cannot see or call non-investigation tools.

## Current runtime modules

```text
agent.rs      AI tool-call loop over OpenAI-compatible function tools
analyst.rs    final evidence-grounded synthesis
case.rs       case context and case directory
collector/    Linux/Windows read-only collectors
config.rs     AI/runtime configuration
model.rs      evidence, findings, reports
playbook.rs   AI-first run orchestration + deterministic guardrail coverage
policy.rs     read-only command policy
runner.rs     command execution, timeout, output cap, audit
store.rs      evidence.jsonl and commands.log
tools.rs      sealed investigator tool registry and dispatcher
report.rs     Markdown/JSON report generation
```

This is the smallest clean product boundary for a local read-only AI server investigator.
