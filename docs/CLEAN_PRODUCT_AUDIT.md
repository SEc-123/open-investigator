# Clean product audit

This package is a clean Open Investigator repository.

## Included

- `crates/open-investigator-cli`: the `oi` command.
- `crates/open-investigator-runtime`: local read-only investigation runtime.
- `docs`: user, architecture, runtime derivation, and production notes.
- `examples/config.toml`: default configuration example.
- `scripts/check.sh`: local validation commands.

## Excluded

No unrelated product surface is included:

- code-editing or patch-generation engines;
- source-code audit workflows;
- project search/indexing layers;
- IDE, desktop, or browser UI;
- app connector discovery;
- web search/browsing;
- image tooling;
- shell escalation;
- team or multi-host orchestration;
- license/product gating layers;
- automatic remediation actions.

## Tool surface guarantee

The AI-visible tool surface is limited to Open Investigator investigation tools. The model cannot call code tools, patch tools, generic shell tools, web tools, or response/remediation tools because they are not present in the repository or registry.
