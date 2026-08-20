# GitHub Copilot Telemetry — SOC Signal Catalogue

**Status:** Draft for review
**Date:** 2026-08-19
**Author:** @jrrbailey1
**Companion document:** `telemetry_requirements.md` (requirements and gap analysis)

A per-signal reference for every telemetry type GitHub Copilot emits: what it is, how it arrives,
how good it is as security telemetry, a real example, and the practical detections, hunts and
investigative uses each one supports.

This catalogue assesses the telemetry on its **intrinsic merit**. It deliberately ignores what the
current `filter/soc` pipeline does or does not forward — see `telemetry_requirements.md` §6 for
that. Everything here is measured from a live agent-mode session captured through the glasseye
collector.

| Item | Value |
|---|---|
| VS Code | 1.123.0 (`6a44c352bd`) |
| Copilot extension | bundled `copilot` v0.51.0 |
| Session 1 | Agent turn in a non-git workspace: 19 spans, 25 log records, 8 metric instruments |
| Session 2 | Agent turn in a **git-backed** workspace: 11 spans, confirming repository attributes and surfacing `embeddings` and `fetch_webpage` |
| Models observed | `mai-code-1.1-flash`, `claude-haiku-4.5`, `gpt-4o-mini-2024-07-18`, `text-embedding-3-small-512`, `metis-1024-I16-Binary` |
| Settings | `otel.enabled=true`, `captureContent=true`, `maxAttributeSizeChars=0` |
| Idle volume | **~1 MB/hour/workstation** of metrics with VS Code merely open (20 MB over 20.1 h) |

> Signals marked **[content]** only carry prompt and file content when
> `github.copilot.chat.otel.captureContent` is enabled. Without it you retain the metadata and
> lose the payload.

---

## Overview

| Telemetry | Signal | Emits | SOC value | Quality |
|---|---|---|---|---|
| `execute_tool` / run_in_terminal | span | on completion | **Critical** | Good |
| `execute_tool` / fetch_webpage | span | on completion | **Critical** | Good |
| `copilot_chat.tool.call` | log | per tool call | **Critical** | Excellent |
| `execute_tool` / create_file, read_file | span | on completion | **High** | Mixed — result is unusable raw |
| `embeddings` | span | per index/search | **High** (blind spot) | Metadata only |
| `chat` / panel/editAgent | span | per agent turn | **High** (investigation) | Good content, poor economics |
| `invoke_agent` | span | end of turn only | **High** | Good, 99% bloat |
| `chat` / copilotLanguageModelWrapper | span | per assessment | **High**, degraded | Orphan trace |
| `gen_ai.client.inference.operation.details` | log | per LLM call | **Medium** | No trace context |
| `copilot_chat.agent.turn` | log | per turn | **Medium** | Excellent |
| 8 metric instruments | metric | **every ~10 s** | **Medium** | Excellent |
| `copilot_chat.session.start` | log | per session | Low–Medium | Excellent |
| `manage_todo_list` / progressMessages / title | span | — | **None** | — |

### How the SOC use cases are categorised

Each signal below lists its uses under four headings. They are not interchangeable — the split
reflects what you can realistically do with that signal:

| Heading | Meaning |
|---|---|
| **Detection** | A rule can be written that fires on its own, without an analyst present. Needs a signal that is unambiguous in isolation. |
| **Hunt** | **Threat hunting** — an analyst proactively searching for adversary activity that no rule has alerted on, working from a hypothesis and a baseline of normal. Used here where a finding depends on comparison against typical behaviour, so it cannot be expressed as a standalone rule. |
| **Investigation** | Reconstructing what happened once an incident is already open. Prioritises completeness and fidelity over volume or latency. |
| **Enrichment** | Joining this signal to another source — EDR, proxy, DNS, repository inventory, GitHub audit — to make detection or investigation possible. |

A signal strong for investigation is often weak for detection, and vice versa: `panel/editAgent`
holds the richest evidence in the feed but is far too large and too context-dependent to alert on,
while `copilot_chat.tool.call` is near-useless for reconstruction yet ideal for a rule.

---

# Tier 1 — direct detection value

## `execute_tool` / run_in_terminal (span)

**What it is.** A shell command proposed by the agent and executed on the developer's machine.

**How it comes through.** Trace span, child of `invoke_agent`, emitted **on completion** — a
long-running command is invisible until it finishes. Carries the command both inside the JSON
arguments blob and lifted into a flat attribute.

**Quality: good.** The flat `github.copilot.tool.parameters.command` attribute means detections
can match on the command without parsing nested JSON. Result is plain text.

```
name  = execute_tool run_in_terminal          duration = 7983ms   parent = invoke_agent
gen_ai.tool.call.arguments = {"command":"cd /d \"c:\\…\\copilot-e2e-sandbox\" && \"C:/…/python.exe\" hello.py",
                              "explanation":"Run the new Python script…"}
gen_ai.tool.call.result    = Note: The tool simplified the command to `cd /d "…" ; "…/python.exe" hello.py`
                             (terminal ID=c00df606-8330…)
github.copilot.tool.parameters.command = cd /d "c:\…\copilot-e2e-sandbox" && "C:/…/python.exe" hello.py
copilot_chat.chat_session_id           = 6fecb406-420e-497b-8faf-8fd59598721d
```

### SOC use cases

**Detection**
- Destructive commands: `rm -rf`, `Remove-Item -Recurse -Force`, `format`, `drop database`, mass file deletion.
- Exfiltration primitives: `curl`/`Invoke-WebRequest` POSTing to non-corporate hosts, `scp`, `nc`,
  cloud CLI uploads (`aws s3 cp`, `az storage blob upload`), pastebin-style endpoints.
- Living-off-the-land download-and-execute: `curl … | sh`, `iwr … | iex`, `certutil -urlcache`,
  `bitsadmin`, base64-decode-and-run chains.
- Credential access: commands touching `~/.ssh`, `~/.aws/credentials`, `.env`, keychains,
  `git config --get credential.*`, `cmdkey /list`.
- Unreviewed dependency introduction: `npm install`, `pip install`, `go get`, `gem install` —
  particularly with a non-default registry or a git URL.
- Source-control manipulation: `git remote add`, `git push` to an unrecognised remote,
  `git config` changes to hooks, history rewrites.
- Privilege and persistence: `net user /add`, `schtasks`, `sc create`, `New-Service`, registry Run keys.

**Hunt**
- Commands executed by the agent that never appear in shell history or the user's terminal
  transcript — agent execution can bypass the provenance you normally rely on.
- Repeated identical commands across many users in a short window — a poisoned instruction file or
  shared prompt driving fleet-wide behaviour.
- Commands whose `explanation` field disagrees with what the command actually does.

**Investigation**
- Rebuild the exact command sequence for an incident timeline, in order, with durations.
- The `result` field records where the tool *rewrote* the model's command — establishing what was
  actually executed versus what was requested.

**Enrichment**
- Join to EDR process-creation / Windows 4688 events by command line and timestamp to confirm
  execution and enumerate child processes. This span supplies the **intent**; EDR supplies the
  **effect**.

---

## `copilot_chat.tool.call` (log)

**What it is.** One structured record per tool invocation, with outcome and duration.

**How it comes through.** Log record with full trace context (`traceId` + `spanId` both set).
Roughly 200 bytes. No arguments, no content.

**Quality: excellent.** Typed fields, no nested encoding, negligible volume. The best
detection primitive in the entire feed — ingestible at full volume with no content-handling
concerns.

```json
{ "body": "copilot_chat.tool.call: manage_todo_list",
  "traceId": "3b4a34bb7503a1504ccc47ee94bbac2b", "spanId": "909b5c306e047cfc",
  "attributes": { "event.name": "copilot_chat.tool.call",
                  "gen_ai.tool.name": "manage_todo_list",
                  "success": true,
                  "duration_ms": 6 } }
```

### SOC use cases

**Detection**
- Tool-call rate anomaly: a burst far above the user's baseline indicates a runaway agent,
  a scripted abuse pattern, or a prompt-injection loop.
- `success=false` spikes: an agent repeatedly failing tool calls is often probing permissions or
  hitting controls — worth surfacing even though each failure is individually benign.
- First-use alerting: a user or repository invoking a high-risk tool (`run_in_terminal`) for the
  first time.
- Off-hours agent activity where the user has no corresponding interactive logon.

**Hunt**
- Build per-user and per-repo tool-usage profiles; investigate profile shifts.
- Long `duration_ms` on tools that are normally fast — an unexpectedly slow `read_file` may mean
  an unusually large file was pulled into context.

**Investigation**
- Cheap skeleton of an entire session: what was done, in what order, and whether it worked —
  before you pay the cost of pulling the full content spans.

**Enrichment**
- Because it carries `traceId`/`spanId`, it is the correct pivot from a cheap alert into the
  expensive, content-bearing span.

---

## `execute_tool` / fetch_webpage (span)

**What it is.** Arbitrary outbound HTTP fetch performed by the agent, with the retrieved content
returned into model context.

**How it comes through.** Trace span, child of `invoke_agent`, on completion. The full URL list is
in `gen_ai.tool.call.arguments`.

**Quality: good content, but no flat attribute.** URLs are captured verbatim in clean JSON —
however `fetch_webpage` is in neither the shell-tool nor file-tool set, so it gets **no**
`github.copilot.tool.parameters.*` convenience field. Detections must parse
`gen_ai.tool.call.arguments`. Given this is the primary agent egress channel, that is an awkward
asymmetry: the highest-risk network tool is harder to alert on than a file read.

```
name = execute_tool fetch_webpage    duration = 10057ms   parent = invoke_agent
gen_ai.tool.call.arguments = {"urls":["https://raw.githubusercontent.com/jrrbailey1/kobayashi-maru/main/README.md"],
                              "query":"README content summary"}
gen_ai.tool.call.id        = toolu_01HAada26CqJbcTzwsC9bdrm
```

### Why this matters more than `run_in_terminal` for exfiltration

Observed directly in testing: asked to read a file from a GitHub repository, the agent did **not**
clone and did **not** use a GitHub API tool. It fetched `raw.githubusercontent.com` through this
generic tool. Repository content entered model context with **nothing written to disk** — no
directory for EDR to see, no file for DLP to scan. This span is the only record that it happened.

A detection watching `run_in_terminal` for `git clone` misses this case entirely.

### SOC use cases

**Detection**
- Fetches to hosts outside an approved allow-list — the primary agent egress channel.
- Fetches to raw content endpoints (`raw.githubusercontent.com`, gists, pastebins) — code and
  data retrieval that bypasses endpoint file monitoring.
- Fetches to URLs constructed from data the agent just read: a strong prompt-injection and
  exfiltration signature (data encoded into a URL path or query string).
- Fetches to internal hosts the developer's workstation would not normally reach — SSRF-shaped
  behaviour driven through the agent.

**Hunt**
- Domains appearing across many users' agent sessions but absent from normal browsing telemetry.
- Correlate fetched URLs against threat intelligence and newly-registered-domain feeds.

**Investigation**
- Establishes precisely what external content entered the model's context, and therefore what may
  have influenced subsequent agent behaviour — the carrier in an injection chain.

**Enrichment**
- Join to proxy and DNS logs by URL and timestamp to confirm the request left the host and to see
  the response size.

---

## `execute_tool` / create_file and read_file (spans)

**What it is.** The data-in and data-out record: files the agent read into model context, and
files it wrote to disk.

**How it comes through.** Trace spans, children of `invoke_agent`, on completion. Path is lifted
into a flat attribute; content is inside the arguments JSON. **[content]**

**Quality: mixed — and this is the worst defect in the feed.** Arguments are clean. But
`gen_ai.tool.call.result` returns **VS Code's internal render tree** (`{"node":{"type":1,"ctor":2,
"ctorName":"_Me",…}}`) with minified class names that are undocumented and change between builds.
File content is recoverable only by walking the tree for scattered `text` nodes. Any parser built
against it will break silently on a VS Code upgrade.

```
gen_ai.tool.call.arguments = {"filePath":"c:\…\hello.py","content":"from pathlib import Path\n\n…"}
github.copilot.tool.parameters.file_path = c:\…\copilot-e2e-sandbox\hello.py
github.copilot.tool.parameters.edit_type = create
gen_ai.tool.call.result   = {"node":{"type":1,"ctor":2,"ctorName":"fk","children":[{"type":2,…
```

### SOC use cases

**Detection — `read_file`**
- Reads of secret-bearing paths: `.env`, `*.pem`, `id_rsa`, `credentials`, `secrets/`,
  `appsettings*.json`, `web.config`, `terraform.tfstate`, `.npmrc`, `.pypirc`.
- Reads of regulated or classified content: paths matching customer-data, HR or finance
  directories, or files carrying a sensitivity label.
- Collection pattern: many reads across unrelated directories within a short window — recon or
  staging rather than normal task-focused work.

**Detection — `create_file`**
- Writes to CI/CD and infrastructure: `.github/workflows/`, `Jenkinsfile`, `Dockerfile`,
  Terraform, Helm charts, Kubernetes manifests.
- Writes to dependency manifests: `package.json`, `requirements.txt`, `go.mod`, `pom.xml` —
  supply-chain introduction.
- Writes to persistence-relevant locations: `.git/hooks/`, shell profiles, scheduled-task
  definitions, service definitions.
- Secrets written *into* source: run secret-scanning over the `content` field, the same rules you
  apply at commit time — but earlier in the chain.
- Writes to security controls: linter configs, `.gitignore` additions hiding artefacts, disabled
  test files, modified security policy files.

**Hunt**
- Compare agent file writes against subsequent commits: files the agent created that were never
  reviewed but reached a branch.
- Files read by the agent that the user has no business role for — lateral data access via the agent.

**Investigation**
- Complete before/after reconstruction of what the agent changed on disk, without relying on git
  (the change may predate any commit, or never be committed).
- Answers the data-exposure question directly: these are the files that entered model context.

**Enrichment**
- Join file paths to your data-classification inventory to risk-weight the event.
- Join to DLP and to repository visibility (private/internal/public) for exposure scoping.

---

# Tier 2 — investigation and context

> ### Read this before the next two sections
>
> `invoke_agent` and `chat / panel/editAgent` carry **the same field names** and are easily
> confused. They are not variants of one record — they answer different questions, and one field
> in particular means something completely different in each:
>
> | | `invoke_agent` | `chat / panel/editAgent` |
> |---|---|---|
> | Count | 1 per turn (trace root) | 6 per turn (children) |
> | **`gen_ai.input.messages`** | **the user's typed prompt**, ~150 chars | **what was actually sent to the model** — avg 27,573 chars, max 56,435 |
> | `copilot_chat.user_request` | clean prose, no wrappers | JSON array with `<context>` / `<editorContext>` |
> | `usage.input_tokens` | turn total (112,335) | per-iteration (17,668) |
> | Repository attributes | **only here** | absent |
> | Arrives | end of turn only (431 s) | progressively, first at ~4 s |
> | Real content after bloat | **657 chars** | ~32 KB |
>
> **In one line:** `invoke_agent` tells you what was *asked*; `panel/editAgent` tells you what was
> *sent* and why the agent acted. Use the first for triage and repository context, the second for
> exposure scoping and injection investigation.

## `chat` / panel/editAgent (span)

**What it is.** One LLM call per iteration of the agent loop — the agent's reasoning between the
user's request and its actions.

**The distinguishing property.** `gen_ai.input.messages` here is **not** the user's prompt. It is
the complete payload transmitted to the model: injected editor context, workspace state, and the
file contents that tool results fed back into the conversation. Averaged **27,573 characters**
across 12 spans, peaking at **56,435**. This is the only record that answers *what source code left
the building* — `invoke_agent` cannot, because it holds only what the user typed.

**How it comes through.** Trace span, child of `invoke_agent`. Emitted per iteration, so these
**stream out during the turn** — the first landed seven minutes before `invoke_agent` closed. Your
only in-flight visibility into the LLM side. **[content]**

**Quality: good content, poor economics.** Measured across 12 spans: **77%** is two static,
repeated attributes — `gen_ai.tool.definitions` (avg 81,814 chars) and `gen_ai.system_instructions`
(avg 25,036). Strip those two and a span drops from ~138 KB to **~32 KB**, of which 27 KB is the
prompt you want. That single change makes retaining all six reasoning spans per turn affordable.

```
name = chat mai-code-1.1-flash    duration = 3978ms   parent = invoke_agent
copilot_chat.user_request  = [{"type":"input_text","text":"<context>\nThe current date is…\n<editorContext>…
gen_ai.input.messages      = [{"role":"user","parts":[{"type":"text","content":"<environment_info>…  (+3340)
gen_ai.output.messages     = [{"role":"assistant","parts":[{"type":"text","content":"I'll read the README…
gen_ai.system_instructions = […]  (+26,059 chars)
gen_ai.tool.definitions    = […]  (+60,778 chars)
copilot_chat.request.options = {"reasoning":{"effort":"medium","summary":"detailed"},"store":false,…}
gen_ai.usage.input_tokens  = 17668
```

### SOC use cases

**Detection**
- Secret and PII scanning over `gen_ai.input.messages` — this is where credentials embedded in
  source code actually leave the building. Expensive; run it here rather than everywhere.
- Injected context volume: an unusually large `input_tokens` relative to the user's baseline means
  an unusually large slice of the codebase went to the model.
- Policy-violating prompt content: requests to disable controls, generate exploit code, or process
  regulated data.

**Hunt — prompt injection (this is the primary record)**
- Look for instruction-shaped language arriving inside *tool results* or file content rather than
  in the user's own prompt: "ignore previous instructions", "you must now", embedded system-prompt
  markers, hidden or zero-width text.
- Compare the user's stated request in `invoke_agent` against the reasoning in these spans — a
  divergence between what was asked and what the agent decided to do is the injection signature.
- Repeated identical injected context across users points to a poisoned repository file
  (`copilot-instructions.md`, `AGENTS.md`, a README) rather than an individual incident.

**Investigation**
- The only record that explains **why** the agent ran a given command. When `run_in_terminal`
  shows something alarming, this span holds the reasoning that led to it.
- Scopes data exposure precisely: exactly which files, which lines, and how much context was
  transmitted, per turn.

**Enrichment**
- Extract referenced file paths from injected context to build the true exposure set — which is
  usually much larger than the files the user consciously opened.

---

## `invoke_agent` (span)

**What it is.** The session envelope — one per user request. What was asked, what was delivered.

**The distinguishing property.** Two things exist only here. First, `copilot_chat.user_request` is
the user's words **clean** — no `<context>` wrappers, no injected workspace state, none of the
noise that makes the same field unusable on `panel/editAgent`. That makes it the single best field
in the feed for acceptable-use policy matching. Second, the **repository attributes**
(`github.copilot.git.repository`, `.branch`, `.commit_sha`, `github.org`) appear on this span and
**no other** — so every child-span alert must join back here via `traceId` to learn which
repository it concerned.

**How it comes through.** Root span of the trace, emitted **only at end of turn** — 431 seconds in
the observed session, by which time every action has already executed. Unusable for real-time
detection; ideal as the case-summary record. **[content]**

**Quality: good, but 99% bloat.** 60,830 of its 61,487 characters are `tool.definitions`,
delivering **657 characters** of actual content — the cheapest span in the feed once that one
attribute is stripped.

```
copilot_chat.user_request = Read README.md and create hello.py that prints the first heading then run it
copilot_chat.turn_count   = 6
gen_ai.input.messages     = [{"role":"user","parts":[{"type":"text","content":"Read README.md and create…
gen_ai.output.messages    = [{"role":"assistant","parts":[{"type":"text","content":"## Result\n\nCreated…
gen_ai.usage.input_tokens = 112335   cache_read = 86528   output = 1785
github.copilot.agent.type = builtin
```

### SOC use cases

**Detection**
- Prompt-content policy matching on `copilot_chat.user_request` — a single clean field holding the
  user's actual words, without the injected context noise of the turn spans. The best field in the
  feed for acceptable-use rules.
- Total `input_tokens` per turn above threshold — a proxy for large-scale context exposure that
  works even without content capture.
- `github.copilot.agent.type` other than `builtin` — a custom or third-party agent is in use.

**Hunt**
- Requests asking the agent to access, aggregate or summarise data outside the user's normal remit.
- Users whose prompts consistently attempt to work around tooling controls.

**Investigation**
- The case-file header. Start triage here: one record gives the request, the outcome, the turn
  count and the total exposure, then pivot into the child spans via `traceId`.
- `gen_ai.output.messages` records what the agent *claims* it did — compare against the
  `execute_tool` spans showing what it actually did.

**Reporting**
- Per-user and per-repo Copilot usage summaries for governance, using token counts rather than
  content.

---

## `chat` / copilotLanguageModelWrapper (span)

**What it is.** Copilot's own internal LLM calls, made without user involvement. Two jobs observed:
**terminal-command risk assessment** and result summarisation.

**How it comes through.** Trace span — but a **root span in its own trace**, not a child of
`invoke_agent`. **[content]**

**Quality: valuable, structurally undermined.** Because these are orphan traces, the risk verdict
**cannot be joined by trace context to the command it assessed**. Correlation must be done on
timestamp proximity plus session ID, which is fragile when turns overlap. A free pre-classified
risk field made much harder to use than it should be.

```
copilot_chat.user_request = You assess what one terminal command does for a code-editing AI agent,
                            and how risky it is. Reply with STRICT JSON only…
gen_ai.output.messages    = [{"role":"assistant","parts":[{"type":"text",
                            "content":"{\"risk\":\"green\",\"explanation\":\"Changes directory and executes hello.py.\"}"}]}]
```

### SOC use cases

**Detection**
- Parse the verdict JSON and alert on `"risk":"red"` or `"yellow"` — a prioritised queue of risky
  commands, pre-classified at no cost to you.
- **Highest-value rule available from this signal:** a non-green verdict where the corresponding
  command still executed. That is a human approving something the model flagged, and it is the
  closest proxy available for the approval telemetry Copilot does not emit (see
  `telemetry_requirements.md` G4).

**Hunt**
- Per-user ratio of flagged-to-executed commands over time. A user who consistently approves
  flagged commands is a behavioural signal worth reviewing, regardless of outcome.
- Verdict explanations that disagree with the command text — model misclassification, or a command
  crafted to read benign.

**Investigation**
- Provides a plain-language description of what each command was intended to do, useful when
  reconstructing an incident for non-technical stakeholders.

**Caveats**
- It is an advisory model judgement, not an enforced control — nothing blocks a red verdict.
- Treat the correlation to the assessed command as best-effort until the orphan-trace issue is
  resolved. Match on `session.id` plus a narrow time window, and verify the command text appears
  in the assessment prompt.

---

# Tier 3 — governance and baselining

## `gen_ai.client.inference.operation.details` (log)

**What it is.** One record per LLM call: model, token usage, finish reason, server response ID.

**How it comes through.** Log record — **the only log type with no `traceId` or `spanId`**,
verified across all 12 records. Correlation to its span is possible only via `gen_ai.response.id`.

**Quality: compromised by the missing trace context**, otherwise clean and compact.

```json
{ "body": "GenAI inference: gpt-4o-mini-2024-07-18",
  "traceId": null, "spanId": null,
  "attributes": { "event.name": "gen_ai.client.inference.operation.details",
                  "gen_ai.operation.name": "chat",
                  "gen_ai.request.model": "gpt-4o-mini-2024-07-18",
                  "gen_ai.response.id": "ef39f8b7-5e9d-484c-8917-f02685bfc67f",
                  "gen_ai.response.finish_reasons": {"arrayValue":{"values":[{"stringValue":"stop"}]}},
                  "gen_ai.request.max_tokens": 4096,
                  "gen_ai.usage.input_tokens": 268, "gen_ai.usage.output_tokens": 7 } }
```

### SOC use cases

**Detection**
- Model allow-listing: alert on any `gen_ai.request.model` outside the approved set. Two distinct
  models appeared in a single session (`mai-code-1.1-flash`, `gpt-4o-mini-2024-07-18`) without the
  user choosing either, so baseline before you alert.
- Provider drift: `gen_ai.provider.name` other than `github` indicates a custom endpoint or BYOK
  configuration — a direct policy-bypass signal.
- **`finish_reasons` containing `content_filter`** — the provider refused or truncated the
  response. A strong, low-noise indicator of prompt content that violated policy, available even
  without content capture enabled.
- `max_tokens` far above baseline — configuration change enabling much larger context transfer.

**Hunt**
- Token-usage outliers per user per day as an exfiltration proxy that requires no content access.
- Sudden appearance of a new model across many users — an untracked rollout or a changed default.

**Enrichment**
- `gen_ai.response.id` is server-issued and is the most likely join key to GitHub's own
  server-side records. Retain it even if you drop everything else from this event.

---

## `copilot_chat.agent.turn` (log)

**What it is.** One record per iteration of the agent loop, describing the shape of that turn.

**How it comes through.** Log record with full trace context. A few hundred bytes.

**Quality: excellent.** Typed, compact, complete.

```json
{ "body": "copilot_chat.agent.turn: 0",
  "traceId": "3b4a34bb…", "spanId": "909b5c30…",
  "attributes": { "event.name": "copilot_chat.agent.turn",
                  "turn.index": 0, "tool_call_count": 0,
                  "gen_ai.usage.input_tokens": 17668,
                  "gen_ai.usage.output_tokens": 85 } }
```

### SOC use cases

**Detection**
- Runaway agent: `turn.index` climbing far beyond baseline indicates a loop, a stuck agent, or an
  injection driving repeated action. Cheap to alert on, no content required.
- Blast-radius alerting: high `tool_call_count` in a single turn — one request causing many
  actions deserves review regardless of what those actions were.
- Context growth within a session: `input_tokens` rising sharply turn over turn means the agent is
  accumulating an increasingly large slice of the codebase.

**Hunt**
- Establish normal turn-count and tool-density distributions per team, then investigate the tail.
- Turns with high token usage but zero tool calls — large context transmitted for no action, worth
  understanding.

**Reporting**
- Cost and capacity forecasting for the Copilot estate, from the same records.

---

## Metrics — 8 instruments

`copilot_chat.session.count`, `copilot_chat.agent.turn.count`,
`copilot_chat.agent.invocation.duration`, `copilot_chat.tool.call.count`,
`copilot_chat.tool.call.duration`, `copilot_chat.time_to_first_token`,
`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`.

**How they come through.** Periodic export **every ~10 seconds**, measured across 283 export
cycles — and they continue while VS Code sits idle, independent of any Copilot activity.
Dimensioned by model, provider, tool name and success.

**Quality: excellent.** Standard OTel instruments, low volume, no content.

### SOC use cases

**Detection — the most important use of this signal**
- **Gap detection / heartbeat.** Because metrics export unconditionally every 10 seconds while the
  editor is open, their *absence* is a reliable evasion signal. Alert when a host with an assigned
  Copilot seat stops reporting metrics while the user remains logged on. This is the control that
  closes the "user disabled telemetry" gap (`telemetry_requirements.md` G11, and the practical
  answer to G3), and no other signal provides it.
- Fleet-level anomaly: a simultaneous drop in reporting across many hosts indicates a collector
  outage rather than user evasion — distinguishing the two is exactly what a heartbeat is for.

**Hunt**
- Token-throughput baselining per user per period via `gen_ai.client.token.usage` — an
  exfiltration-volume signal that requires no access to content, and therefore no privacy
  trade-off.
- `tool.call.count` dimensioned by `success` — failure-rate trends per user or tool.
- Off-hours usage profiles from `session.count`.

**Operations**
- Capacity and cost forecasting; detecting performance degradation via `time_to_first_token`
  before users report it.

---

## `embeddings` (span) — the workspace-indexing blind spot

**What it is.** Workspace content chunked and sent to an embedding model for semantic search and
indexing. A fourth `gen_ai.operation.name` value alongside `invoke_agent`, `chat` and
`execute_tool`.

**How it comes through.** Trace span, sometimes a child of `invoke_agent` and sometimes a root span
in its own trace. Emitted whenever indexing or semantic search runs — not tied to an explicit user
action.

**Quality: metadata only, and that cuts both ways.** It records *how many* chunks were sent, never
*what* was in them, so it carries no content risk of its own but cannot tell you what was exposed.

```
--- embeddings text-embedding-3-small-512    635ms   parent = child
      gen_ai.operation.name         = embeddings
      gen_ai.provider.name          = openai
      gen_ai.request.model          = text-embedding-3-small-512
      gen_ai.embeddings.input_count = 1

--- embeddings text-embedding-3-small-512   2148ms   parent = child
      gen_ai.embeddings.input_count = 30          <-- 30 chunks of workspace content in one call

--- embeddings metis-1024-I16-Binary          696ms   parent = ROOT
      gen_ai.provider.name          = openai
```

**This is a data-exposure path with no other record.** Workspace code leaves the machine for
embedding without any tool call, any prompt, or any user action that appears elsewhere in the
telemetry. Note also `gen_ai.provider.name = openai` rather than `github`.

> **All `embeddings` spans are dropped by the current `filter/soc` condition** — they match none of
> the four whitelisted values. Code leaving the workspace for indexing is therefore entirely
> invisible to the SOC. This is distinct from the `panel/editAgent` gap and needs fixing
> separately.

### SOC use cases

**Detection**
- `gen_ai.embeddings.input_count` above baseline: a large indexing burst means a large volume of
  workspace content was transmitted. The best available proxy for bulk code exposure, and it needs
  no content access at all.
- Indexing activity against a repository classified as restricted, joined via the `invoke_agent`
  parent's `github.copilot.git.repository`.
- Embedding provider or model outside the approved list — `openai` appears here where `github`
  appears elsewhere, so baseline before alerting.
- Indexing activity outside working hours or with no corresponding user session.

**Hunt**
- Cumulative embedded-chunk counts per user per repository over time — a slow-burn exposure metric
  that no other signal provides.
- A developer opening a sensitive repository for the first time, then a large indexing burst.

**Investigation**
- Establishes that workspace indexing occurred and at what scale, which is often the answer to
  "how did the model know about that file?" when no `read_file` span exists.

**Limitation to state plainly**
- Content is not captured, so this bounds exposure by volume only. Answering *which* files were
  embedded requires correlating with workspace contents at that timestamp.

---

## `copilot_chat.session.start` (log)

**What it is.** Session boundary marker, emitted once when a chat session begins.

**How it comes through.** Log record with full trace context.

**Quality: excellent.** Small, typed, complete.

```json
{ "body": "copilot_chat.session.start",
  "traceId": "3b4a34bb7503a1504ccc47ee94bbac2b", "spanId": "909b5c306e047cfc",
  "attributes": { "event.name": "copilot_chat.session.start",
                  "session.id": "6fecb406-420e-497b-8faf-8fd59598721d",
                  "gen_ai.request.model": "mai-code-1.1-flash",
                  "gen_ai.agent.name": "GitHub Copilot Chat" } }
```

### SOC use cases

**Detection**
- Off-hours or anomalous-time session starts, particularly where they do not align with an
  interactive logon or a known on-call window.
- Session starts from a host or account with no assigned Copilot seat — a licensing anomaly that
  can also indicate account misuse.
- Session-rate anomalies: many sessions started in rapid succession suggests scripted use.

**Investigation**
- The session anchor. `session.id` appears on spans and other log types, so this record establishes
  the start of the timeline and the initial model in use.

**Reporting**
- Adoption and seat-utilisation metrics, without touching any content.

---

# Noise — suppress, do not delete

| Span | Why it exists | Practical use |
|---|---|---|
| `chat` / progressMessages | Generates UI "thinking…" strings | Suppression rule. No security value |
| `chat` / title | Generates the conversation title | Suppress for detection, but the generated title is a useful human-readable label for case management, and the record does contain the user's request |
| `execute_tool` / manage_todo_list | Internal agent task bookkeeping | Suppression rule. Currently the only pure-noise record that passes `filter/soc` |

Suppress at the collector rather than at the SIEM — the volume is small, but filtering early keeps
detection content clean and reduces analyst noise.

---

# Conditional attributes — present only in specific circumstances

Source inspection of extension v0.51.0 revealed attributes that are implemented but appear only
when particular conditions hold. Each was initially absent from a capture and initially misread as
a missing capability — the distinction between "not emitted" and "not emitted *here*" matters.

Each subsection states **which span carries the attributes**, because that determines what your
detections can see without a join.

### Repository context — CONFIRMED PRESENT (runtime-verified, session 2)

> **Carried on:** `invoke_agent` spans **only** — one per turn, on the trace root.
> **Condition:** the workspace must be a git repository with a configured remote.

No `execute_tool`, `chat`, `embeddings` or `execute_hook` span carries these. A `run_in_terminal`
alert therefore arrives with **no repository context**; you must join back to the parent span via
`traceId` to learn which repository the action touched. Build that join into your enrichment
pipeline rather than discovering it mid-incident.

Absent from the first capture only because that workspace had no `.git`. Re-running in a
git-backed workspace produced them exactly as the code predicted:

```
github.copilot.git.repository = https://github.com/jrrbailey1/copilot-e2e-sandbox.git
github.copilot.git.branch     = master
github.copilot.git.commit_sha = 1f21a83cc8de914e1ebed72291cfc2f73f708e28
github.copilot.github.org     = jrrbailey1
```

| Attribute | Source |
|---|---|
| `github.copilot.git.repository` | remote fetch URL of the active repository |
| `github.copilot.git.branch` | current head branch |
| `github.copilot.git.commit_sha` | head commit hash |
| `github.copilot.github.org` | parsed from the GitHub remote URL |

Populated from the VS Code Git extension's `activeRepository`. The remote does not need to be
reachable — the value comes from the configured fetch URL, not a successful fetch.

**SOC use cases:** risk-weight every event by repository sensitivity; scope an incident to a
specific repo, branch and commit; detect agent activity against production or regulated
repositories; join `github.copilot.git.repository` to your repository inventory to resolve
visibility (private/internal/public), which Copilot does *not* emit. Branch and commit together
identify precisely which code state was exposed to the model.

**Caveat:** attribution degrades silently to nothing outside a git workspace, with no marker
distinguishing "not a repository" from "attribute missing". Treat absence as unknown, not as safe.

### MCP server attribution — CONFIRMED PRESENT (runtime-verified, session 3)

> **Carried on:** `execute_tool` spans — the same span type as any built-in tool call, one per
> MCP tool invocation.
> **Condition:** an MCP server must be configured and the agent must invoke one of its tools.

Because these are ordinary `execute_tool` spans, they **already pass `filter/soc`** and reach the
SOC feed unchanged — unlike `embeddings` and `execute_hook`. T6 detections are buildable against
the current pipeline today.

Enabling the built-in GitHub MCP server (`github.copilot.chat.githubMcpServer.enabled`) and asking
the agent to search repositories produced this span:

```
gen_ai.operation.name = execute_tool          <- ordinary tool span, not a distinct type
gen_ai.tool.name      = mcp_github_mcp_se_search_repositories
gen_ai.tool.type      = extension             <- the discriminator: builtin tools report "function"
gen_ai.tool.call.arguments = {"query":"glasseye in:name,description,readme","page":1,"perPage":10}
gen_ai.tool.call.result    = {"total_count":38,"items":[{"id":39622984,"full_name":"coppeliaMLA/glasseye",…
github.copilot.tool.parameters.mcp_server_name      = github
github.copilot.tool.parameters.mcp_server_name_hash = c0b0109d9439de57fe3cf03abeccbc52f4c98170c732d3b69af5e6395ace574e
github.copilot.tool.parameters.mcp_tool_name        = mcp_se_search_repositories
```

Arguments and results are captured in full, exactly as for built-in tools.

> **`gen_ai.tool.type` is the discriminator.** Verified across all three sessions without
> exception: every built-in tool (`run_in_terminal`, `read_file`, `create_file`, `fetch_webpage`,
> `manage_todo_list`, `configure_python_environment`) reports `type=function`, and the MCP tool
> reports `type=extension`. Detecting third-party tool use is therefore a **single-field match** —
> no prefix parsing or name heuristics required.

**MCP tool spans already reach the SOC feed.** They are `execute_tool` operations, so they pass
`filter/soc` unchanged. Unlike the `embeddings` and `panel/editAgent` blind spots, T6 detections
are buildable against the current pipeline today.

**The `_hash` variant provides no privacy.** It is an unsalted, single-iteration SHA-256 of the
server name — verified: `sha256("github")` reproduces the observed value exactly. Any MCP server
with a guessable name (`github`, `slack`, `jira`, `postgres`, an internal hostname) is recoverable
by dictionary attack in milliseconds. Retain it as a stable correlation key if useful, but do
**not** treat it as a redacted form of the server name.

Note the schema also declares `github.copilot.mcp.server.name` and
`github.copilot.mcp.server.name_hash` as attributes distinct from the `tool.parameters.*` forms;
only the latter appeared in this capture.

### SOC use cases

**Detection**
- `gen_ai.tool.type = "extension"` where `mcp_server_name` is not on an approved list — the core
  T6 rule, and the one to build first.
- Any MCP tool invocation against a server that appeared for the first time on that host.
- MCP tool arguments or results containing sensitive data patterns — a third-party integration is
  now a data path, and the result payload shows exactly what it returned.
- MCP activity reaching resources beyond the current workspace: the server acts with the user's
  own token, so its reach is the user's entire GitHub access, not just the open repository.

**Hunt**
- Inventory MCP servers in use across the estate by grouping on `mcp_server_name` — a
  shadow-integration census that no other source provides.
- Compare `mcp_tool_name` frequency per user against team norms.

**Investigation**
- Attribute a data-access action to the specific third-party integration that performed it, with
  the full request and response payload.

### `execute_hook` (span) — code-verified, not reachable on this account

> **Carried on:** its own dedicated `execute_hook` span — the fifth `gen_ai.operation.name` value,
> not attributes bolted onto another span.
> **Condition:** hooks must be configured *and* the session must run on the Claude / Copilot CLI
> agent path. Not emitted by the default agent.

**What it is.** A configured hook command executing against a gated agent action, recording whether
that action was allowed or blocked. **The only enforced control event Copilot emits** — every other
control signal in this catalogue is advisory.

**The distinguishing property.** `github.copilot.hook.decision` is a real enforcement outcome, not a
model opinion. From the extension source: `success → pass`, **`exit_code === 2 → block`**, otherwise
`non_blocking_error`. A `PreToolUse` hook exiting 2 **stops the tool call from running**. Contrast
`copilotLanguageModelWrapper`, which produces a risk verdict that nothing acts on.

**How it comes through.** Trace span, one per hook invocation, emitted on hook completion. Small —
dominated by `hook_input`, which carries the full gated payload. Configured via the `/hooks` slash
command ("Configure Claude Code hooks for tool execution and events"), which writes Claude Code's
schema to `.claude/settings.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "*",
    "hooks": [ { "type": "command", "command": "…" } ] } ] } }
```

**Quality: unverified in production form.** Attribute names and the decision mapping are read from
source; the shape below was reproduced synthetically and confirmed to traverse the pipeline. No
live emission was observed — see the testing outcome below.

```
gen_ai.operation.name          = execute_hook
copilot_chat.hook_type         = PreToolUse       (one of 27 events, incl. PermissionRequest/Denied)
copilot_chat.hook_command      = cmd /c glasseye-policy-gate
copilot_chat.hook_input        = {"tool_name":"run_in_terminal","tool_input":{"command":"Remove-Item -Recurse…
copilot_chat.hook_output       = DENY: destructive filesystem operation outside workspace root
copilot_chat.hook_result_kind  = blocked
copilot_chat.hook_exit_code    = 2
github.copilot.hook.decision   = block
github.copilot.hook.duration   = 0.087
github.copilot.hook.tool_names = ["run_in_terminal"]
github.copilot.hook.invocation_id = 82de9e91-f785-438f-a5c0-d55620f641ed
```

**Testing outcome (2026-08-19): no live hook telemetry could be produced.** With `SessionStart`,
`PreToolUse` and `PostToolUse` all registered in the workspace, a session making three tool calls
emitted **zero** hook attributes; the agent was `github.copilot.agent.type = builtin`. The emission
code sits in `ClaudeMessageDispatch` beside the bundled Claude Code CLI, so coverage appears scoped
to the Claude / Copilot CLI agent — and the test account is **Copilot Free**, which offers no agent
picker to reach it.

### SOC use cases

*Contingent on hooks proving available and covering the default agent — see caveats.*

**Detection**
- `github.copilot.hook.decision = block` — a policy control actually stopped an agent action. The
  highest-value control event available from Copilot, and the only enforced one.
- Hooks registered on `PermissionRequest` / `PermissionDenied` would capture **human approval
  decisions** — the H1/H2 telemetry absent everywhere else (see `telemetry_requirements.md` G4).
- `decision = non_blocking_error` — the control itself failed. A hook erroring open is a silent
  loss of enforcement, and looks identical to no policy being configured.
- Absence of expected `execute_hook` spans on a host with hooks deployed: control tampering, or a
  session on an agent path hooks do not cover.

**Hunt**
- Per-user ratio of `block` to `pass` over time. A user accumulating blocks is either fighting the
  policy or probing its edges; either merits a look.
- Repeated blocks on the same `tool_names` across many users — usually a mis-scoped policy rather
  than an incident, and worth catching before analysts learn to ignore the alert.
- `hook.duration` outliers: a slow hook delays every gated action and is the first thing an
  engineer will be tempted to disable.

**Investigation**
- `copilot_chat.hook_input` carries the complete gated payload, so a blocked action is fully
  reconstructable — you see exactly what was stopped, not merely that something was.
- `hook_output` records the policy's own reasoning, giving the rationale alongside the decision.

**Enrichment**
- Join `hook.invocation_id` and `chat_session_id` to the corresponding `execute_tool` span to pair
  each decision with the action it gated.

> **Two caveats before designing around this.** Hook coverage may not extend to the *default*
> agent, which would make it of limited practical value in an estate where most sessions run there.
> And `execute_hook` matches none of the four values in `filter/soc`, so hook decisions would be
> **dropped before reaching the SOC** — the same blind spot as `embeddings`.

### Other declared attributes not observed

> **Carried on:** unconfirmed. These appear in the extension's attribute constant table but never
> in a capture, so the carrying span is inferred from naming rather than observed.

| Attribute | Likely carrier (inferred) |
|---|---|
| `gen_ai.agent.id`, `.version`, `.description` | `invoke_agent`, alongside `gen_ai.agent.name` |
| `gen_ai.output.type` | `chat` spans |
| `copilot_chat.location`, `copilot_chat.intent` | `invoke_agent` or `chat` — chat entry point and classified intent |
| `github.copilot.tool.parameters.skill_name` | `execute_tool`, for skill-invoking tools |

Treat these as documented-but-unverified; confirm against your own capture before building on them.

> **Method note.** Two internal sets in the extension gate the flat parameter attributes:
> shell tools (`bash`, `powershell`, `local_shell`, `run_in_terminal`, …) populate
> `tool.parameters.command`, and edit tools (`view`, `create`, `edit`, `str_replace`, …) populate
> `tool.parameters.file_path` / `edit_type`. Tools outside those sets carry only the JSON
> arguments blob.

---

# Coverage of this catalogue — what is and is not documented

Source inspection gives a definitive denominator for each signal type. Measured against it:

| Signal | Emitted by Copilot | Documented here | Coverage |
|---|---|---|---|
| Span operation types | 5 | 5 | **complete** |
| Log event types | 10 | 4 | **40%** |
| Metric instruments | 20 | 8 | **40%** |

The undocumented events and metrics are not hidden or undiscoverable — they belong to **three
Copilot surfaces our test sessions never exercised**. Everything in this catalogue characterises
the *chat and agent* surface.

### Surface 1 — inline completions and edit acceptance *(not tested)*

```
events   copilot_chat.inline.done · copilot_chat.edit.hunk.action
         copilot_chat.edit.survival · copilot_chat.edit.feedback
metrics  copilot_chat.edit.acceptance.count · copilot_chat.edit.survival.four_gram
         copilot_chat.edit.survival.no_revert · copilot_chat.lines_of_code.count
         copilot_chat.chat_edit.outcome.count · copilot_chat.agent.edit_response.count
```

Ghost-text completions and whether suggested edits were accepted, reverted or survived. This is a
different product surface from chat, and it is the one most developers use most of the time.

**Why a SOC should care:** `lines_of_code.count` and the `edit.survival.*` metrics measure **how
much AI-generated code entered the codebase and persisted**. That is the code-provenance question
AppSec asks — what proportion of our code was machine-authored and never reverted — and it is
available as cheap metadata with no content capture.

### Surface 2 — cloud / pull-request agent *(not tested)*

```
events   copilot_chat.cloud.session.invoke
metrics  copilot_chat.cloud.session.count · copilot_chat.cloud.pr_ready.count
         copilot_chat.pull_request.count
```

The autonomous Copilot coding agent that runs server-side and raises pull requests.

**Why a SOC should care:** this is agent activity with **no developer at a keyboard**. Every
control discussed in this catalogue — approval prompts, risk verdicts, endpoint telemetry — assumes
a human in the loop and an IDE on a managed device. Neither holds here. Arguably the highest-risk
surface, and the least covered by an endpoint collector.

### Surface 3 — user feedback *(not tested)*

```
events   copilot_chat.user.feedback
metrics  copilot_chat.user.feedback.count · copilot_chat.user.action.count
```

Thumbs up/down and related UI actions. Low security value; listed for completeness.

---

## The span inventory specifically *is* complete — verified from source

Observation alone cannot tell you whether a catalogue is exhaustive. Code inspection can. The
exporter filters every span against a fixed allow-set before export:

```js
ci = { CHAT:"chat", INVOKE_AGENT:"invoke_agent", EXECUTE_TOOL:"execute_tool",
       EMBEDDINGS:"embeddings", CONTENT_EVENT:"content_event", EXECUTE_HOOK:"execute_hook" }

Z0i = new Set([ci.CHAT, ci.INVOKE_AGENT, ci.EXECUTE_TOOL, ci.EMBEDDINGS, ci.EXECUTE_HOOK])
export(spans) { spans.filter(s => s.attributes[OPERATION_NAME] === undefined
                                  || Z0i.has(String(s.attributes[OPERATION_NAME]))) }
```

**There are exactly five span operation types**, and this catalogue documents all five — four
observed directly, `execute_hook` code-verified and reproduced synthetically. Nothing else can
appear. Two details worth noting: `content_event` is defined but absent from the export set, so it
never reaches a collector; and spans with **no** operation name pass the filter unconditionally,
which is how a forged span with omitted attributes slips straight through.

---

# Attribute availability — which fields you can actually build detections on

The flat `github.copilot.tool.parameters.*` attributes are far more convenient than parsing the
JSON blob, but they are populated for **specific tool names only**, from two hard-coded sets:

**Shell tools** → populate `tool.parameters.command`:
```
bash · powershell · local_shell · runInTerminal · run_in_terminal · Bash
```

**File tools** → populate `tool.parameters.file_path` and `tool.parameters.edit_type`:
```
view · create · edit · str_replace · str_replace_editor · insert · readFile · createFile
replaceString · applyPatch · read_file · create_file · apply_patch · insert_edit_into_file
replace_string_in_file · multi_replace_string_in_file · edit_notebook_file
Read · Edit · MultiEdit · Write · NotebookEdit
```

`edit_type` is derived from the tool name, normalising to `create` / `insert` / `str_replace` /
`update` — a useful pre-classification of what a file operation actually did.

**Every other tool gets no flat attribute at all.** That includes `fetch_webpage`,
`github_repo`, `github_text_search`, `install_extension`, `install_python_packages`,
`run_vscode_command`, `create_and_run_task` and `runSubagent` — several of which are the higher-risk
capabilities. Detections against those must parse `gen_ai.tool.call.arguments` as JSON.

### The 256-character trap

```js
if (uEt.has(toolName)) {
  let s = pick(input, ["command","cmd","commandLine"]);
  s && (gated[TOOL_PARAM_COMMAND] = s.length > 256 ? s.slice(0, 256) : s);
}
```

`github.copilot.tool.parameters.command` is **silently truncated at 256 characters**. It is a raw
`slice`, not the `Co()` helper used for content attributes — so there is **no
`...[truncated, original N chars]` marker** and no relationship to the
`maxAttributeSizeChars` setting. A 300-character obfuscated one-liner appears in your SIEM as a
clean 256-character command with no indication anything was cut.

> **Detection rule:** match on the flat `tool.parameters.command` for cheap, indexed alerting, but
> always extract the authoritative command from `gen_ai.tool.call.arguments`, which is not subject
> to this cap. Any rule anchored on the *end* of a command string — trailing pipe, redirect, or
> terminator — is unreliable on the flat field.

---

# Cross-cutting quality issues

These affect every consumer and should be factored into any parsing or detection work.

1. **Everything interesting is double-encoded.** Content is a JSON document inside a string
   attribute — `gen_ai.input.messages`, `output.messages`, `system_instructions`,
   `tool.definitions`, `tool.call.arguments`, and sometimes `copilot_chat.user_request`. Every
   consumer parses twice.
2. **Internal serialisation leaks into `tool.call.result`.** Minified VS Code class names
   (`_Me`, `wn`, `y6e`, `fk`) that are undocumented and unstable across releases. Parsers will
   break silently on upgrade. This is the one item worth raising with GitHub as a telemetry defect.
3. **No severity on any log record.** `severityText` and `severityNumber` are empty on all 25
   records, so SIEM-native severity triage is unavailable — you must derive severity yourself.
4. **`eventName` field unset.** The event name lives only in the `event.name` attribute; the body
   carries a human-readable duplicate. Key parsers on the attribute.
5. **Trace correlation broken in two places.** Inference logs carry no trace context; risk-verdict
   spans are orphan roots. Both require fallback joins on `gen_ai.response.id` or
   `session.id` + time.
6. **Spans emit on completion.** A 344-second tool call is invisible for 344 seconds. Build
   real-time detections on the log events, not the spans.

**The underlying strength:** the schema follows OpenTelemetry GenAI semantic conventions
(`gen_ai.*`), so standard SIEM parsers and GenAI observability tooling understand most of it
without custom mapping. The defects above are implementation quality, not model design.

---

# Suggested detection build order

Ordered by value delivered per unit of effort, and deliberately front-loading rules that need no
content capture.

| # | Rule | Source signal | Needs content? |
|---|---|---|---|
| 1 | Telemetry heartbeat / gap detection | metrics | No |
| 2 | Dangerous command patterns | `run_in_terminal` span | No* |
| 3 | Non-green risk verdict where command executed | `copilotLanguageModelWrapper` span | Yes |
| 4 | Sensitive-path file reads | `read_file` span | No* |
| 5 | Writes to CI/CD, IaC, dependency manifests | `create_file` span | No* |
| 6 | Model allow-list and provider drift | inference log | No |
| 7 | `content_filter` finish reason | inference log | No |
| 8 | Tool-call rate and failure-rate anomalies | `tool.call` log | No |
| 9 | Runaway agent (turn count, tool density) | `agent.turn` log | No |
| 10 | Secret/PII scanning of prompts | `panel/editAgent` span | Yes |

\* **Partially verified.** Code inspection confirms `gen_ai.tool.definitions`,
`gen_ai.system_instructions`, `gen_ai.input.messages` and `gen_ai.output.messages` are gated
behind `captureContent` — they are set inside `if (… config.captureContent) { … }` blocks. The
gating of `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` and the flat
`github.copilot.tool.parameters.*` attributes was **not** established, so rules 2, 4 and 5 may or
may not survive with content capture disabled. Confirm by running a capture with
`captureContent=false` before relying on it — this materially affects whether a
privacy-preserving deployment retains any detection capability.

> **Handling note.** Any store built from these signals contains verbatim prompts, source code and
> command output. Classify it at the level of the most sensitive repository the agent can reach —
> see `telemetry_requirements.md` G9 and O2.
