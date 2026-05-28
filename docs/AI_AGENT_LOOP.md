# AI agent loop

Open Investigator uses a real function-tool loop. The AI investigator is not limited to a fixed scanner, and it is not allowed to run arbitrary shell. It sees a sealed set of `oi_*` tools and chooses which evidence to collect next.

## Loop

```text
case context
  -> model request with tool schemas
  -> assistant tool_calls
  -> runtime validates and executes tools
  -> evidence.jsonl append
  -> compact tool observations returned to model
  -> more tool_calls or final answer
```

This mirrors the original useful runtime behavior: model-directed tool use with iterative observations. The Open Investigator product changes the tool surface from code/project tools to host investigation tools.

## Tool call example

The model may call:

```json
{
  "tool_calls": [
    {
      "type": "function",
      "function": {
        "name": "oi_ioc_find",
        "arguments": "{\"ioc\":\"1.2.3.4\",\"type\":\"ip\",\"reason\":\"Search all discovered logs for the suspicious IP\"}"
      }
    },
    {
      "type": "function",
      "function": {
        "name": "oi_auth_check",
        "arguments": "{\"ip\":\"1.2.3.4\",\"reason\":\"Check whether the IP attempted or succeeded in login\"}"
      }
    }
  ]
}
```

The runtime maps those to internal actions:

```text
oi_ioc_find   -> ioc.find
oi_auth_check -> auth.check
```

It then executes bounded collectors, writes evidence, and returns the evidence summary as tool observations.

## Safe-mode AI-visible tools

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

Investigator mode additionally exposes:

```text
oi_java_deep
oi_java_dump
oi_ro_run
```

`oi_java_deep` and `oi_java_dump` are still gated by the case flags: `--java-deep` for internal JVM diagnostics, and `--heap-dump` or `--jfr-dump` for heavy artifacts.

`oi_ro_run` is present only in investigator mode and is still policy-filtered. It cannot be used to bypass the JVM dump gates.

## Guardrail baseline

Production investigation should not depend solely on perfect model planning. After the AI loop, guardrail coverage fills missing critical areas for the case type. For example, a suspicious IP case should cover IOC search, auth, web, net, proc, persistence, and service context.

The default is:

```toml
ai_guardrail_baseline = true
```

## Stop conditions

The loop stops when:

- the assistant returns a final answer with no tool calls;
- the provider request fails;
- `ai_max_rounds` is reached;
- all requested calls are blocked by runtime policy/budget.

All failures and denials are recorded as evidence.
