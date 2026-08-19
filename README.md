# GitHub Copilot Telemetry — a SOC Assessment

An empirical assessment of the OpenTelemetry data GitHub Copilot Chat emits, evaluated as a
**security log source**: what signals exist, how good they are, and what a Security Operations
Centre can actually detect with them.

Every finding here is measured from live capture or verified against the extension source. Nothing
is inferred from documentation.

## The two documents

| Document | What it covers |
|---|---|
| **[telemetry_requirements.md](telemetry_requirements.md)** | What a SOC needs to detect, attribute and respond to Copilot-related incidents — 40 numbered requirements across nine areas, derived from a nine-class threat model — and 18 gaps measured against them |
| **[signal_catalogue.md](signal_catalogue.md)** | Per-signal reference: every span, log event and metric Copilot emits, with real examples, quality assessment, and the concrete detections, hunts and investigations each supports |

## Method

Copilot Chat can export OTLP directly. The relevant settings, read from the bundled extension
rather than guessed:

```jsonc
"github.copilot.chat.otel.enabled": true,
"github.copilot.chat.otel.exporterType": "otlp-http",
"github.copilot.chat.otel.otlpEndpoint": "http://localhost:4318",
"github.copilot.chat.otel.captureContent": true,      // prompts, tool args, file contents
"github.copilot.chat.otel.maxAttributeSizeChars": 0   // no truncation
```

Traffic was received by [**glasseye**](https://github.com/Daviey/glasseye) — a custom
OpenTelemetry Collector by [@Daviey](https://github.com/Daviey) built for exactly this purpose.
**This repository is not a fork of glasseye and contains none of its code.** It contains an
assessment of the telemetry glasseye receives, plus the minimal test rig used to observe it.

Four live agent sessions were captured, across a non-git workspace, a git-backed workspace, an
MCP-enabled session, and a hooks-configured session.

## Test rig

Findings about the collector's own filtering were measured against **unmodified** upstream
`config.yaml`. The rig differs from upstream by exactly two changes:

```diff
@@ exporters:
+  file/soc:
+    path: ./agent-traffic-soc.json
@@ traces/pubsub:
-      exporters: [googlecloudpubsub]
+      exporters: [googlecloudpubsub, file/soc]
```

An observer is *added* so the post-filter stream can be measured locally; nothing is removed, and
the OTTL filter expression is byte-identical to upstream.

| File | Purpose |
|---|---|
| `rig/config.observed.yaml` | Upstream `config.yaml` + the observer above. The faithful rig |
| `rig/config.local.yaml` | Earlier variant with Pub/Sub replaced entirely. Kept for provenance |
| `rig/proposed-filter-fix.yaml` | **A proposal, not part of the test.** Corrected filter admitting `execute_hook` and `embeddings` |

## Tools

| File | Purpose |
|---|---|
| `tools/flatten.ps1` | OTLP JSON-lines → readable timeline, NDJSON, or CSV. Decodes the double-encoded content attributes and recovers text from VS Code's render-tree tool results |
| `tools/to-xlsx.ps1` | Formatted Excel workbook via COM — frozen header, autofilter, wrapped content columns |

## Headline findings

**Strong as an action recorder.** Verbatim shell commands, complete file contents written, tool
arguments and results, user prompts with injected workspace context, and the model's own
pre-execution risk verdict on terminal commands.

**Weak as an attribution and assurance system.** No end-user identity and no device identity are
emitted at all. Telemetry is off by default, user-disableable, and the collector accepts
unauthenticated spans — forged control events were ingested indistinguishably from real traffic
during testing.

**Selected specifics:**

- **The SOC filter drops more than intended.** `embeddings` spans — workspace code sent to an
  embedding model, 30 chunks in one observed call — reach no SOC feed at all. Nor would
  `execute_hook` policy decisions.
- **Agents reach the network without a shell.** Asked to read a file from a GitHub repository, the
  agent used `fetch_webpage` against `raw.githubusercontent.com` — no clone, nothing written to
  disk, invisible to EDR and DLP. A detection watching `git clone` misses it entirely.
- **The convenient command field is silently truncated at 256 characters** and is therefore
  evadable by padding. The full command survives in `gen_ai.tool.call.arguments`.
- **`mcp_server_name_hash` is unsalted SHA-256** — `sha256("github")` reproduces the observed
  value. It is not a redaction.
- **`tool_call_count` is always zero**, despite tool calls occurring in the same captures.
- **~1 MB/hour/workstation of idle metrics** with the editor merely open, before any prompt.

## Scope and limits

The span inventory is **complete** — source inspection confirms exactly five operation types
(`chat`, `invoke_agent`, `execute_tool`, `embeddings`, `execute_hook`) and all five are documented.

Log events and metrics are **~40% covered**: 4 of 10 event types and 8 of 20 instruments. The
remainder belong to two Copilot surfaces these sessions never exercised —

- **inline completions / edit acceptance**, including the metrics measuring how much AI-generated
  code entered the codebase and persisted;
- **the cloud / pull-request agent**, which runs server-side with no developer at a keyboard, and
  for which every control discussed here — approval prompts, endpoint collection, host-to-user
  resolution — is inapplicable.

Both are **unassessed, not assessed-and-cleared**.

Hook telemetry is code-verified and reproduced synthetically, but could not be observed live: the
emission path appears scoped to the Claude/CLI agent, which the Copilot Free tier does not provide.

## Environment tested

| | |
|---|---|
| VS Code | 1.123.0 (`6a44c352bd`) |
| Copilot extension | bundled `copilot` v0.51.0 |
| Collector | glasseye, OCB v0.157.0 |
| Models observed | `mai-code-1.1-flash`, `claude-haiku-4.5`, `gpt-4o-mini-2024-07-18`, `text-embedding-3-small-512`, `metis-1024-I16-Binary` |

## A note on captured data

No capture artefacts are included in this repository. With `captureContent` enabled the telemetry
contains verbatim prompts, source code, and command output — classify any capture store at the
level of the most sensitive repository the agent can reach.

## Credits

[glasseye](https://github.com/Daviey/glasseye) is the work of [@Daviey](https://github.com/Daviey).
This repository assesses the telemetry it collects and does not modify or redistribute it.
