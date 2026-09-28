# Jev permission proxy — implementation plan

**Status:** implementation-ready, with the explicit OpenCode declaration checks in Slice 0 as an implementation gate
**Research date:** 2026-09-24
**Project root:** `/home/curious/opencode-jev-permissions`
**Target runtime:** Node.js `>=22.19.0`, ESM, strict TypeScript (required by the installed OpenCode dependency graph)

## 1. Goal and non-goals

### Goal

Build a publishable OpenCode V2 **server** plugin that processes every permission request it observes while active in each OpenCode location where the plugin is loaded, and performs best-effort reconciliation for pending requests in sessions learned through public events or prompt hooks. It evaluates each valid observed request through TypeSafe AI's hosted Jev System One model and either:

- replies `once` only for a highly confident allow,
- replies `reject` for a highly confident deny or a mandatory local hard-deny, or
- sends no reply and leaves the request pending for manual review for uncertainty, ambiguity, malformed input, missing/invalid credentials, timeout, cancellation, or any Jev/API failure.

The implementation must be privacy-minimizing, deterministic under test, safe under duplicate/concurrent events, recoverable from missed events for sessions known while the plugin remains active, and clean up without creating late replies. It must not imply universal startup catch-up when OpenCode exposes no public session/permission enumeration API.

### Non-goals

- No CLI or TUI plugin and no `./tui` export.
- No replacement or mutation of OpenCode's permission rules.
- No attempt to observe operations that OpenCode resolves to `allow` or configured `deny` before a pending request exists. This plugin covers **requests OpenCode actually raises and the plugin observes while active**.
- No guarantee of discovering a request that was already pending in an old, unknown session before subscription and emitted no observed public event afterward; the current public Promise API has no session-enumeration method.
- No `always` reply and no durable broad approval.
- No upload of full transcripts, assistant reasoning, tool output, file contents, arbitrary metadata, or whole session history.
- No live Jev calls in automated tests.
- No real API key in source, examples, fixtures, snapshots, logs, or committed configuration.
- No unrelated OpenCode or project configuration changes.
- No shell execution, command evaluation, dynamic plugin loading, or general telemetry.

## 2. Official-contract findings and verification gates

Only official OpenCode V2 and TypeSafe documentation was used for architecture research.

### Verified now

1. **V2 Promise plugin entrypoint:** `import { Plugin } from "@opencode/plugin"` and a default export created with `Plugin.define({ id, setup })`. `setup` may return a cleanup function. This is a server plugin, not a CLI plugin.
2. **Plugin instance location:** `ctx.location` describes the location where that plugin instance loaded. It is explicitly not a guarantee about every session or event the instance can observe.
3. **Events:** `ctx.event.subscribe({ signal })` returns an async iterable of `OpenCodeEvent`; the stream must be aborted during cleanup. The official client guide says event subscriptions are live-only, have no replay/reconnect, and a late subscriber sees a current `server.connected` marker rather than missed business events. The server event endpoint is cross-location, so this plugin must explicitly filter to its `ctx.location.directory`.
4. **Permission methods documented by V2:**
   - `ctx.permission.list({ sessionID })`
   - `ctx.permission.get({ sessionID, requestID })`
   - `ctx.permission.reply({ sessionID, requestID, reply: "once" })`
5. **Valid permission replies:** the official API schema exposes exactly `once | always | reject`. The permissions guide says `reject` rejects the target and every other pending permission request in that session. The adapter's internal reply type must therefore contain only `once | reject`.
6. **Permission request fields:** the official OpenAPI schema publicly verifies `id`, `sessionID`, `action`, `resources`, and optional `save`, `metadata`, `source`, and `message`. The plugin must not spread optional fields into Jev or logs.
7. **V2 action names:** built-ins include `read`, `edit`, `glob`, `grep`, `shell`, `subagent`, `skill`, `question`, `webfetch`, `websearch`, `external_directory`, `execute`, and plugin/MCP-defined action strings. The adapter must not maintain an allowlist that silently skips an action.
8. **Runtime floor:** pinned `@opencode/plugin` 2.0.16 resolves through `@opencode/util` / `@effect/platform-node` to `undici` 8.11.2, whose engine is Node `>=22.19.0`. Vite 7.3.6 accepts `^20.19.0 || >=22.12.0`, but that does not lower the `undici` floor. The package must therefore declare and verify Node `>=22.19.0`; TypeSafe SDK's lower own minimum does not change the package target.
9. **TypeSafe JavaScript SDK:** `npm install @typesafe-ai/sdk`; `import { choice, TypeSafeClient } from "@typesafe-ai/sdk"`; the package publishes ESM, CommonJS, and declarations. The documented client method is `client.systemOne({ state, model?, questions }, options?)`.
10. **TypeSafe state:** Jev accepts a string, JSON object, or array of text values. The official guidance recommends a named structured object containing only decision-relevant state.
11. **Choice answers:** a Choice returns `choice`, `probabilities`, and `confidence` in `[0,1]`; confidence is derived from probability concentration. Multiple questions are evaluated in parallel against one state.
12. **SDK credentials/logging:** the SDK reads `TYPESAFE_API_KEY` when `apiKey` is omitted. SDK `debug` logging can include bodies; known credential headers are redacted but bodies are not. Explicitly set SDK `logLevel: "off"`.
13. **SDK transport:** a total deadline must be imposed by the plugin because the SDK timeout is per attempt and retries do not have a total retry budget. `RequestOptions.signal` and bounded `RetryPolicy` are documented.
14. **Hosted endpoint/model:** the official endpoint is `https://api.typesafe.ai/v1/systemone`; `jev-latest` is the documented stable Jev alias and SDK default. Pin `baseURL` to the official host so `TYPESAFE_BASE_URL` cannot redirect the API key.
15. **Jev limitations:** Jev is a structured decision model, not an LLM agent. It does not generate text and cannot be used to replace OpenCode's model or permission system.
16. **Session enumeration gap:** the installed public Promise `ctx.session` domain has no `list` method. `ctx.permission.list` requires a known `sessionID`, and the public plugin context exposes no location-wide session or pending-permission enumeration method. Reconciliation must therefore be limited to sessions observed through verified public events or the public prompt hook.

### Must be checked against the exact installed packages in Slice 0

The public V2 documentation does **not** fully specify the server-stream `permission.asked` payload property path or a public type-only import path for that event. The CLI documentation has a `permission.asked` example, but this is a different API and must not be used to infer the Promise server event shape. Slice 0 must resolve the following before adapter code is accepted:

1. Pin exact compatible `@opencode/plugin` and `@typesafe-ai/sdk` versions in `package.json`/lockfile.
2. Inspect only public declarations exported by the installed `@opencode/plugin` package to identify the exact `OpenCodeEvent` `permission.asked` variant and its payload location.
3. Add a negative compile contract for the installed `ctx.session` surface: it has no `list`, and no source slice may substitute `ctx.session.list`, direct HTTP calls, private Core imports, or an OpenCode SDK client workaround.
4. Confirm the generated context return wrappers and error representation for permission `list/get/reply`; do not infer them solely from the raw HTTP schema. The raw HTTP body calls the field `decision`, while the plugin context documentation calls it `reply`.
5. Confirm the public type export for `ctx.session.hook("prompt", ...)` or infer it from `typeof ctx.session.hook`; do not import an internal declaration path.
6. Confirm the accepted cleanup return type. Cleanup must synchronously stop new work even if it cannot await workers.
7. Add compile-only contract fixtures for every confirmed call. If no public named event type exists, narrow `OpenCodeEvent` with a local runtime guard and do not depend on package internals.

These are implementation verification tasks, not reasons to guess API shapes. A slice using an unverified event or list shape is not done.

## 3. Architecture

### 3.1 Component boundaries

```text
OpenCode server event stream
        |
        v
Event adapter / location scope / dedupe
        |
        v
Permission port: list(known session) -> get -> pre-reply get -> reply
        |
        v
Relevant-intent provider (bounded cache, local fallback extraction)
        |
        v
Normalizer + redactor  -----> sanitized audit metadata only
        |
        v
Deterministic guardrail engine + risk signals
        |
        v
Jev evaluator (@typesafe-ai/sdk, fixed official base URL)
        |
        v
Pure decision core (local hard policy + Jev confidence/probability gates)
        |
        +--> once
        +--> reject
        +--> no reply / manual pending
```

The pure decision core has no imports from OpenCode or TypeSafe SDK. The OpenCode adapter and Jev client implement small injected ports, allowing all policy tests to run without a server, credentials, timers, or network. A bounded in-memory `KnownSessionRegistry` is the only reconciliation input: it records session IDs learned from verified public events or the prompt hook after authoritative location verification. It is reset on cleanup/reload and is never treated as a complete server-side session index.

### 3.2 Request data flow

Before normal request processing, the adapter starts its public event consumer and prompt-hook registration, then enables interval/reconciliation work. It learns a session only from a verified public event or prompt hook that exposes `sessionID`, confirms the session through public `ctx.session.get`, and records it only when the normalized location matches this instance. There is no initial all-session scan.

For each accepted `permission.asked` notification:

1. Extract only `sessionID` and `requestID` using the installed event type confirmed in Slice 0.
2. Compute an in-process key from the canonical location directory, session ID, and request ID.
3. If the key is already tracked, do nothing; return the existing promise/state.
4. Verify ownership: read the session and require `session.location.directory` to normalize equal to this instance's `ctx.location.directory`. Never assume the event belongs to `ctx.location`.
5. Fetch the authoritative pending request with `ctx.permission.get`; a missing request is `already_resolved_external` and receives no reply.
6. Validate the request envelope without logging raw values. Missing/invalid IDs, action, or resources become malformed/manual.
7. Obtain relevant user intent locally:
   - prefer a bounded, redacted in-memory value captured by the V2 prompt hook;
   - otherwise read `ctx.session.context` only as a local fallback, locate the nearest preceding user message associated with `source.messageID` when possible, extract only its text, redact it immediately, cap it, and discard the transcript. Never send assistant messages, tool output, reasoning, or multiple historical prompts.
8. Build a local raw fact model. Classify action/tool, shell resources, paths, URLs, search text, and generic resources using the verified V2 resource conventions plus conservative lexical classification.
9. Run path and shell guardrails against the raw local values. Produce only stable signal codes and booleans; do not put matched secret values into signals.
10. Build the outbound Jev state from an allowlisted projection: redacted action/tool, redacted shell command(s) only for shell, normalized affected resources, deterministic signals, relevant redacted intent, and the versioned local policy. Omit session IDs, message IDs, raw paths/home directories, arbitrary metadata, request messages, transcripts, and file contents.
11. For every valid observed request, including a local hard-deny, invoke Jev once through the bounded evaluator. The local hard-deny remains a non-bypassable input and final code constraint. This reconciles “every valid observed request is evaluated” with “guardrails run before Jev.”
12. Validate the complete Jev response at runtime. Pass typed answers to the pure decision core.
13. The core emits one of `ALLOW_ONCE`, `REJECT`, or `MANUAL_PENDING` using the rules in section 7.
14. Before any automatic reply, call `get` again. If absent, record external resolution and do not reply.
15. Serialize the terminal transition per request and send at most one `once` or `reject`. Handle 404/not-found as already resolved; other failures use the bounded reply recovery below and otherwise leave pending.
16. Emit sanitized audit metadata and release raw/redacted working data as soon as the request terminal state is reached.

### 3.3 Why the evaluation hook is not the primary mechanism

V2 also documents `ctx.permission.hook("evaluate")`. This plan intentionally does not use it as the decision transport: the requested behavior is a proxy for already-raised pending requests with `once`/`reject` reply semantics and manual fallback. An evaluation hook can mutate pre-request effects and would allow an automatic allow without an OpenCode permission reply, weakening the explicit `once` invariant. Reconsidering that transport is a separate design change.

## 4. Threat model and non-bypassable safety invariants

### Trust boundaries

- OpenCode and all loaded plugins are trusted to provide an authenticated event/request, but their content is untrusted data.
- The model can intentionally craft unusual shell syntax, paths, metadata, or prompt text.
- User intent and tool arguments may contain prompt injection, credentials, personal data, or encoded payloads.
- Jev is remote, probabilistic, fallible, and influenced by every outbound field. It is never a security authority.
- TypeSafe receives hosted request data. Official docs say customer requests are not used for training, but zero data retention is described as available for enterprise customers; README must not imply ZDR for every account.
- The local process environment contains `TYPESAFE_API_KEY`; the plugin must narrow its reach and never serialize environment data.

### Mandatory invariants

1. **Hard local policy wins:** any mandatory guardrail hit returns `REJECT` regardless of Jev output or configured thresholds.
2. **No Jev override:** Jev may refine intent/risk, but code—not model output—enforces secret, destructive, privilege/security-boundary, and obvious-exfiltration rules.
3. **No fail-open:** no key, 401, timeout, rate limit exhaustion, API/transport error, malformed request/response, invalid answer, missing intent for an allow, or uncertain parse means no automatic allow.
4. **Manual means pending:** uncertainty sends no OpenCode reply. It must not be translated to `once`; it must not be translated to `reject` unless a local hard-deny independently requires it.
5. **At most one grant:** the adapter's reply union is only `once | reject`; no code path accepts, constructs, stores, or emits `always`.
6. **Current-request check:** an automatic reply is attempted only after a fresh `get`, and a 404/absence wins over a late Jev result.
7. **Minimum outbound data:** raw command/path/intent exists only in local memory long enough to classify/redact. Jev receives an allowlisted projection, never an arbitrary object spread.
8. **No transcript upload:** at most one redacted, bounded relevant user-intent fragment may be sent. No assistant/system/tool messages, file contents, or historical transcript.
9. **No secret exfiltration through configuration:** TypeSafe base URL is fixed to `https://api.typesafe.ai`; no configurable base URL/proxy is accepted. SDK logging is forced off; plugin logs use a separate sanitized logger.
10. **No sensitive logs:** no raw resource, command, path, URL query, intent, prompt, source ID, arbitrary metadata, error body/message, header, or API key may be logged/audited/persisted.
11. **Unknown syntax is not safe:** suspicious or insufficiently parsed shell/path constructs disable auto-allow. A clear hard-deny still rejects.
12. **No durable raw data:** the initial release does not use `ctx.storage` for commands, intent, paths, transcripts, answers, or audit payloads. In-memory records expire and are cleared on cleanup.
13. **Location isolation:** a plugin instance may reply only to sessions whose authoritative location equals its loaded `ctx.location.directory`.
14. **OpenCode policy ownership:** the plugin does not call `ctx.permission.rules`, change `permissions`, or claim coverage of operations resolved before a request exists.

### Mandatory deterministic guardrail categories

The first release must include conservative, versioned rules for:

- **Secret access:** environment dumps; `.env*` other than explicitly public examples; SSH/private keys; cloud credentials; package-registry credentials; browser/keychain/credential stores; system shadow files; commands/flags that reveal passwords, tokens, cookies, or authorization material.
- **Destructive operations/files:** force/recursive deletion, root/home/current-workspace deletion, disk formatting/overwrite, destructive Git reset/clean/force-push, mass permission/ownership changes, database truncate/drop, process/service shutdown, and edits to system, credential, VCS-hook, OpenCode policy/plugin, or security-boundary files.
- **Privilege/security-boundary changes:** `sudo`/`doas`/`su`/elevated runners, setuid/setgid, firewall/security tooling, auth/security service configuration, system path mutation, and attempts to weaken or replace this plugin/OpenCode policy.
- **Obvious exfiltration:** a secret/credential source combined with a network sink or upload client in one command/resource set; piping/command substitution from protected files into `curl`, `wget`, `nc`, remote shell/copy tools, paste services, or cloud upload commands; direct upload of protected local data.
- **Uncertain parsing:** encoded/nested shell constructs, unsupported control operators, malformed paths, unavailable canonicalization, or ambiguous resource classification produce `unparseable`/`unknown_scope` signals and block auto-allow.

False positives are acceptable because they conservatively leave requests pending or reject. False negatives are minimized through deny-only widening, lexical plus token-based shell inspection, path canonicalization of the nearest existing ancestor, and tests for bypass variants. The README must not claim the scanner is a complete shell security boundary; OpenCode's own permission configuration remains a separate layer.

## 5. Core interfaces and Jev contract

These are interface contracts, not implementation code.

### Normalized local types

- `PermissionKey`: canonical location identity + `sessionID` + `requestID`.
- `PermissionFacts`: validated action, locally classified raw resources, optional verified tool identity, source correlation, location, and bounded local intent candidate.
- `RedactedContext`: outbound-safe action/tool, optional redacted commands, normalized resource descriptors, deterministic risk signals, relevant intent, and local policy version.
- `GuardrailAssessment`: stable signal codes, parse status, and `hardDeny` boolean; never matched values.
- `JevEvaluation`: validated auxiliary answers, final Choice answer, probabilities, confidence, model version, and token usage. Usage/model are metadata; raw response is not logged.
- `CoreDecision`: `ALLOW_ONCE`, `REJECT`, or `MANUAL_PENDING`, with a closed reason code and confidence bucket.

### Injected ports

- **Permission port:** session lookup, pending list/reconcile, get, and reply with the verified V2 context contract.
- **Event source:** async event subscription plus abort.
- **Intent provider:** cache lookup/update and bounded local fallback extraction.
- **Jev evaluator:** `evaluate(context, { signal, deadline })`, with production implementation backed only by `@typesafe-ai/sdk` and a fake in tests.
- **Audit sink:** structured sanitized events through an injected logger.

### Jev request

Use one `systemOne` call with a structured state and three parallel Choice questions:

1. `intent_alignment`: `supported | contradicted | unclear`.
2. `risk_class`: `routine | elevated | high | unclear`.
3. `policy_decision`: `allow_once | deny | manual_review`.

The state contains only:

- `request.action` and optional verified tool name;
- redacted shell command(s), only for shell;
- normalized/redacted affected resources with kind and scope category;
- deterministic signal codes and bounded summary counts;
- optional redacted, bounded `user_intent`;
- `local_policy.version`, hard-deny codes, `unknown: "manual_review"`, and `maximum_grant: "once"`.

The final Choice criteria explicitly define `allow_once` as compatible with non-negotiable local policy and relevant intent, `deny` as a clear policy/intent safety conflict, and `manual_review` for ambiguity. Code still enforces hard guardrails and thresholds.

### Jev client behavior

- Instantiate lazily so a missing key does not prevent plugin setup.
- Let the SDK read `TYPESAFE_API_KEY`; never read it into application config, logs, errors, or state.
- Explicitly set official `baseURL`, configured Jev-only `defaultModel`, and SDK `logLevel: "off"`.
- Default to one retry, short bounded backoff, and an 8-second total deadline; pass an abort signal for cleanup/deadline.
- Do not retry malformed answers, 401, or deterministic local failures.
- Runtime-validate answer labels, `type === "choice"`, finite confidence/probabilities in `[0,1]`, all expected labels, and probability sum within a small documented tolerance.
- Convert errors to a closed sanitized taxonomy; never interpolate `error.message`, response body, headers, or request state.
- Pin the SDK version resolved from the current official JavaScript SDK docs during Slice 0. The research baseline is the official v0.6.0 documentation, but the lockfile is authoritative at implementation time.

## 6. Configuration schema and defaults

`ctx.options` is untrusted and must be parsed with an explicit runtime validator. Unknown keys, invalid ranges, non-finite numbers, non-Jev model names, or invalid enum values make setup enter a safe no-op mode and log only `config_invalid`; requests then remain pending. Mandatory guardrails cannot be disabled.

| Option | Default | Validation / meaning |
|---|---:|---|
| `model` | `"jev-latest"` | Non-empty `jev-*`; official hosted Jev only. No arbitrary endpoint/model provider. |
| `timeoutMs` | `8000` | Total wall-clock deadline across attempts; 100–30000. |
| `maxRetries` | `1` | 0–2; bounded below SDK defaults. |
| `maxConcurrency` | `4` | 1–16 Jev evaluations across the instance. |
| `maxQueueSize` | `256` | 1–2048; overflow is manual pending with no network call. |
| `reconcileIntervalMs` | `30000` | 5000–300000; best-effort catch-up for missed events only in sessions known while active. |
| `thresholds.allowConfidence` | `0.98` | 0–1; routine auto-allow. |
| `thresholds.allowProbability` | `0.95` | 0–1; selected `allow_once` probability. |
| `thresholds.elevatedAllowConfidence` | `0.99` | 0–1 and not lower than routine threshold. |
| `thresholds.denyConfidence` | `0.95` | 0–1. |
| `thresholds.denyProbability` | `0.90` | 0–1. |
| `thresholds.auxiliaryConfidence` | `0.90` | Required for intent/risk auxiliary answers used in composition. |
| `limits.commandChars` | `4096` | 256–16384; redacted outbound cap. |
| `limits.intentChars` | `2000` | 128–8192; redacted outbound cap. |
| `limits.resources` | `16` | 1–64; extra values are summarized, not silently dropped. |
| `limits.resourceChars` | `512` | 64–4096 per normalized resource. |
| `pluginLogLevel` | `"info"` | `info | warn | off`; controls sanitized plugin metadata only, never the TypeSafe SDK logger. |

### Example OpenCode configuration (documentation only; no key)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "opencode-jev-permissions",
      "options": {
        "model": "jev-latest",
        "timeoutMs": 8000,
        "maxRetries": 1,
        "maxConcurrency": 4,
        "maxQueueSize": 256,
        "reconcileIntervalMs": 30000,
        "thresholds": {
          "allowConfidence": 0.98,
          "allowProbability": 0.95,
          "elevatedAllowConfidence": 0.99,
          "denyConfidence": 0.95,
          "denyProbability": 0.9,
          "auxiliaryConfidence": 0.9
        },
        "limits": {
          "commandChars": 4096,
          "intentChars": 2000,
          "resources": 16,
          "resourceChars": 512
        },
        "pluginLogLevel": "info"
      }
    }
  ]
}
```

The key is configured only in the OpenCode process environment, for example through a secret manager or shell environment:

```sh
export TYPESAFE_API_KEY='<provided-at-runtime>'
```

Do not put a key in `opencode.jsonc`, plugin options, an `apiKey` field, fixtures, or README examples. Do not use OpenCode's `{env:...}` substitution for this plugin because the plugin intentionally reads the process environment through the TypeSafe SDK.

The plugin does not add a `permissions` array. OpenCode resolves allow/ask/deny before publishing a pending request. Users who want more operations to reach the proxy must configure their own narrow `ask` rules; that policy choice is outside this plugin.

## 7. Event/reply state machine and threshold policy

### Per-request states

```text
SESSION_OBSERVED (public event or prompt hook; location verified)
 -> REQUEST_DISCOVERED_BY_EVENT | REQUEST_DISCOVERED_BY_KNOWN_SESSION_RECONCILIATION
 -> OUT_OF_SCOPE | EXTERNALLY_RESOLVED | MALFORMED_MANUAL
 -> NORMALIZED
 -> GUARD_ASSESSED
 -> JEV_PENDING
 -> CORE_DECISION
 -> PRE_REPLY_GET
 -> ALLOW_ONCE | REJECT | MANUAL_PENDING | EXTERNALLY_RESOLVED | REPLY_UNKNOWN
```

A request discovered by periodic `ctx.permission.list({ sessionID })` enters the same keyed path as an event-discovered request; its source is metadata only. A request in an old session absent from `KnownSessionRegistry` has no public discovery path and is not claimed as covered. Terminal records remain only as bounded in-memory tombstones long enough to suppress duplicates, then expire. `MANUAL_PENDING` intentionally does not call OpenCode; the request remains owned by OpenCode for manual review.

### Pure decision table

Evaluate in this order:

1. If request/response validation fails, use `MANUAL_PENDING`, except a previously detected local hard-deny remains `REJECT`.
2. If any mandatory local guardrail fired, return `REJECT` immediately and irrevocably.
3. If the Jev final label is not one of the three exact labels, return `MANUAL_PENDING`.
4. If the selected final label is `manual_review`, return `MANUAL_PENDING` at any confidence.
5. If the label is `deny`, return `REJECT` only when final confidence, selected probability, valid probability distribution, and model identity are valid and meet the deny thresholds. Otherwise return `MANUAL_PENDING`.
6. If the label is `allow_once`, require all of the following; otherwise return `MANUAL_PENDING`:
   - no hard/uncertain parser signal;
   - relevant intent exists and `intent_alignment` is `supported` at the auxiliary confidence/probability floor;
   - `risk_class` is `routine` at the routine allow thresholds, or `elevated` at the stricter elevated allow thresholds;
   - `risk_class` is never `high` or `unclear` for automatic allow in v1;
   - final `allow_once` meets the allow confidence and selected-probability thresholds;
   - all probability distributions and expected answers validate.
7. Map only `ALLOW_ONCE -> "once"` and `REJECT -> "reject"`. No decision maps to `always`.

Defaults are intentionally asymmetric: a false deny harms availability, while a false allow can affect security, so allowing requires a higher confidence/probability and coherent auxiliary answers.

### Idempotency, races, and reconciliation

- Create the coordinator and known-session registry first, register the public prompt hook, start the public event consumer, and only then enable normal periodic/reconciliation work. Event callbacks only validate/enqueue and never await Jev, avoiding slow-consumer overflow.
- Add a session to `KnownSessionRegistry` only when a verified public event or prompt hook exposes `sessionID` and public `ctx.session.get` confirms the normalized location equals `ctx.location.directory`. The registry is bounded, has a TTL, is cleared on cleanup, and stores IDs/metadata only.
- At the configured interval, after reconnect, and after a new session is learned, call only `ctx.permission.list({ sessionID })` for each known in-scope session, then feed each returned pending request through the same keyed coordinator. Use `get` before processing and again before any reply.
- A missed `permission.asked` event can be recovered only if its session was already learned from another public event or prompt hook while this plugin instance remained active. A reconnect reconciles the sessions still known in memory.
- There is no public `ctx.session.list`, location-wide Promise permission list, direct HTTP fallback, private Core API, or OpenCode SDK-client workaround. The plugin therefore cannot discover an already-pending request in an old session that emitted no observed public event after subscription unless that session later becomes known through a public prompt/event. README and acceptance language must state this limitation.
- A keyed map/process future suppresses duplicate event/reconciliation discoveries. Global semaphore enforces `maxConcurrency`; a bounded queue prevents unbounded memory. Queue overflow is manual pending.
- A per-request terminal lock permits at most one reply transition. Reply operations may be serialized per session to make audit order deterministic, while Jev calls remain concurrent.
- Before both automatic replies, perform a fresh `get`. A missing request is external completion and wins over the Jev result.
- If `reply` fails with a known not-found/404, mark externally resolved. For an ambiguous reply transport failure, perform one fresh `get`; if still pending, retry the **same** `once`/`reject` at most once. If still unresolved, leave it pending and stop. Never recompute a different decision solely because of a reply transport error.
- A successful `reject` may clear all pending requests in that session under the documented OpenCode contract. Workers for those requests re-check and record external resolution; they do not issue further replies. Tests must model this behavior explicitly.
- Within one active generation, Jev evaluation is at-least-once for a pending request and OpenCode side effects are at-most-one successful reply. A crash/reload resets `KnownSessionRegistry`; re-evaluation is possible only after a request or its session is observed again through a public API. A crash after reply leaves no pending request.
- Do not use durable storage for this reconciliation. For a known session, `get`/its returned pending list is authoritative; there is no authoritative all-session list to persist or query.

### Error and cancellation behavior

| Condition | Automatic reply | Result |
|---|---|---|
| Mandatory local hard-deny | `reject`, even if key/Jev is unavailable | Local safety decision |
| Missing or whitespace-only `TYPESAFE_API_KEY` | None, unless hard-deny | Manual pending; plugin remains loaded |
| 401/invalid key | None, unless hard-deny | Manual pending |
| Total timeout / 429 exhausted / 5xx / network failure | None, unless hard-deny | Manual pending |
| Malformed OpenCode request | None | Manual pending |
| Malformed Jev answer | None, unless hard-deny | Manual pending |
| Low/ambiguous confidence | None | Manual pending |
| Queue overflow | None | Manual pending |
| Request already absent | None | Already resolved |
| Event stream ends/errors | None | Reconnect and best-effort reconcile known in-memory sessions |
| Plugin cleanup before decision | None | Abort Jev; request remains pending if OpenCode retains it |
| Plugin cleanup during reply | At most current call | No new work; next setup starts with no known sessions |

OpenCode configuration reload may cancel pending permissions itself. The plugin cleanup remains non-replying. A fresh instance does not inherit the old known-session registry and can reconcile only sessions it observes through public APIs after setup; it cannot claim universal catch-up for old sessions.

## 8. Redaction, intent, and audit details

### Outbound redaction

- Preserve shell verbs/structure and relevant non-sensitive argument names, but replace credential values, authorization material, cookies, private-key material, signed query values, and high-entropy secret literals.
- Strip URL userinfo, fragments, and sensitive query keys/values. Preserve scheme, normalized public host, and non-sensitive action path/query fields needed for judgment. Mark loopback/private/internal hosts categorically rather than uploading internal hostnames.
- Convert absolute home/workspace prefixes to tokens such as `<project>`, `<home>`, `<external>`, and `<system>`; do not upload usernames or machine-specific absolute roots.
- For paths, retain normalized relation (`project`, `external`, `home`, `system`, `secret`, `protected`) and a redacted/short display token. Keep raw canonical path only inside guardrail evaluation.
- Redact likely secrets in user intent, then run a second sensitive-literal detector. If a field still appears sensitive or cannot be safely projected, omit it and set `redaction_complete: false`; this blocks auto-allow.
- Cap commands, intent, resource count, and each resource with head/tail truncation markers so an action at either end is not lost silently. Oversize/ambiguous context is a manual signal.
- Never serialize arbitrary `metadata`, `message`, `source`, environment objects, tool output, or full message structures.

### Relevant intent

- Prompt-hook cache key is session ID; value contains only redacted text, a monotonically increasing local revision, timestamp, and truncation/redaction flags.
- New admitted prompts replace the current intent. Do not concatenate a transcript.
- When the prompt cache is empty, including a request discovered by known-session reconciliation, use the nearest preceding user message to the source tool message, otherwise the latest user message in the returned context. This full context is local and ephemeral; only the selected fragment continues.
- If no user message can be selected, set intent unavailable. Jev can still be called and can deny, but auto-allow is impossible.
- Clear/expire cache entries on session idle if the installed event shape exposes a reliable idle marker; otherwise use bounded TTL and clear all on cleanup.

### Sanitized audit schema

Allowlisted fields only:

- schema version, plugin version, request ID, a non-secret session correlation (raw session ID is permitted only if OpenCode diagnostics require it; otherwise use a per-process hash);
- action/tool category, resource count/kind counts, local/external/home/system flags;
- stable guardrail/risk/manual reason codes and parse/redaction flags;
- Jev model version, selected label, confidence/probability rounded or bucketed, token usage, latency bucket;
- outcome (`once`, `reject`, `manual`, `external`, `skipped`) and sanitized error category/status.

Never log raw or redacted commands/paths/intent, matched values, request metadata, Jev state/questions/answers in full, raw errors, or headers. Tests must capture every log sink and assert sentinel secrets/paths/prompts are absent.

## 9. Planned file tree

Only the following project files should be created during implementation, in addition to this plan:

```text
/home/curious/opencode-jev-permissions/
├── .opencode/plans/jev-permission-proxy.md
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
├── package.json
├── package-lock.json
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── config.ts
│   ├── decision/
│   │   └── core.ts
│   ├── domain.ts
│   ├── guardrails/
│   │   ├── index.ts
│   │   ├── path-policy.ts
│   │   ├── shell-policy.ts
│   │   └── signals.ts
│   ├── index.ts
│   ├── jev/
│   │   ├── client.ts
│   │   └── questions.ts
│   ├── observability/
│   │   ├── audit.ts
│   │   └── errors.ts
│   ├── opencode/
│   │   ├── context-builder.ts
│   │   ├── contract.ts
│   │   ├── coordinator.ts
│   │   ├── intent-cache.ts
│   │   ├── permissions.ts
│   │   └── plugin.ts
│   └── redaction/
│       ├── index.ts
│       ├── paths.ts
│       └── text.ts
└── test/
    ├── config.test.ts
    ├── contracts/
    │   └── opencode-v2.compile.ts
    ├── decision-core.test.ts
    ├── fixtures/
    │   └── fake-opencode.ts
    ├── guardrails.test.ts
    ├── integration.test.ts
    ├── jev-client.test.ts
    ├── redaction.test.ts
    ├── setup.ts
    └── unit.test.ts
```

Do not add a CLI entrypoint, RPC, TUI source, live integration suite, shell execution helper, or unrelated configuration.

## 10. Ordered implementation slices

Implement exactly one slice at a time. Review and run that slice's verification before starting the next.

### Slice 0 — Package scaffold and exact V2/SDK contract lock

**Goal**

- Create the dedicated ESM/strict-TS Node `>=22.19.0` package skeleton.
- Resolve all Slice 0 declaration questions and make invalid assumptions fail to compile.
- Establish deterministic no-network tests and closed domain/config types.

**Non-goals**

- No event processing, Jev calls, guardrail behavior, or README publication text.

**Constraints**

- Pin exact installed compatible versions and commit the lockfile.
- Set `package.json` `engines.node` to `>=22.19.0`; use the same floor in CI, development docs, verification, and packed-consumer checks. The installed `undici` 8.11.2 engine is the controlling reason.
- Use only public package declarations/imports.
- Test setup replaces network access with a throwing fake and unsets `TYPESAFE_API_KEY`.
- Configure strict TypeScript including `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.

**Exact files**

- `package.json`
- `package-lock.json`
- `tsconfig.json`
- `vitest.config.ts`
- `.gitignore`
- `src/domain.ts`
- `src/config.ts`
- `test/setup.ts`
- `test/config.test.ts`
- `test/contracts/opencode-v2.compile.ts`

**Interfaces/data flow**

- Define the normalized local types, closed manual/error/audit reason unions, `PermissionKey`, and internal reply union (`once | reject`).
- Implement a pure `parsePluginOptions(unknown)` contract returning validated options/defaults or a sanitized configuration error.
- Compile-only fixtures call the documented Promise plugin shape and the exact installed permission/event/prompt contracts confirmed above, plus a negative assertion that `ctx.session` has no `list` method.

**Tests**

- Defaults and every validation boundary; unknown keys and non-Jev model rejected.
- Compile fixture for `Plugin.define`, `setup`, cleanup, permission calls, event subscription, and prompt hook; a negative contract rejects any `ctx.session.list` or direct client/private-Core workaround.
- Assert the test harness has no API key and that accidental global fetch fails immediately.
- A type-level assertion makes `always` unassignable to the internal reply type.

**Definition of done**

- `npm ci`, typecheck, and tests pass with no network.
- The exact package versions, Node `>=22.19.0` engine, and verified public type/import choices are recorded in README compatibility notes later and in package metadata now.
- No unresolved permission event/list/reply shape or nonexistent `ctx.session.list` call remains in the compile fixture.

**Dependencies:** none.

### Slice 1 — Redaction and minimal context projection

**Goal**

- Build pure, independently testable secret/path/URL/intent redaction and an allowlisted Jev context projection.
- Build the bounded prompt-intent cache and local fallback selector without outbound transcript leakage.

**Non-goals**

- No Jev client, decision thresholds, shell execution, or filesystem content reads.

**Constraints**

- Raw values remain local; projection accepts only an explicit field allowlist.
- Apply a post-redaction sensitive-literal scan and fail closed for auto-allow eligibility.
- Use no regex supplied by user configuration and no unbounded recursive serialization.

**Exact files**

- `src/domain.ts` (only shared type refinements)
- `src/redaction/index.ts`
- `src/redaction/paths.ts`
- `src/redaction/text.ts`
- `src/opencode/context-builder.ts`
- `src/opencode/intent-cache.ts`
- `src/observability/audit.ts`
- `src/observability/errors.ts`
- `test/redaction.test.ts`
- `test/unit.test.ts`

**Interfaces/data flow**

- Intent hook/cache updates a redacted bounded value.
- `contextBuilder.build(facts, intent, policy)` returns outbound-safe `RedactedContext` plus `redaction_complete`; it never returns raw data to the Jev port.
- Audit accepts a closed metadata union, not arbitrary objects.

**Tests**

- Sentinel API keys, bearer/basic tokens, cookies, password flags, private-key blocks, signed URLs, home paths, internal hosts, env dumps, and high-entropy literals are absent from projections.
- Preserve harmless command verbs/paths needed for judgment.
- Unknown metadata/message/source structures are omitted.
- Intent cache replaces rather than concatenates; truncation and missing-intent behavior are deterministic.
- Audit sink rejects/does not serialize raw fields.

**Definition of done**

- Unit tests demonstrate no unnecessary full transcript or arbitrary metadata can cross the builder boundary.
- Outbound objects are JSON-serializable and structurally typed.

**Dependencies:** Slice 0.

### Slice 2 — Deterministic guardrails and risk signals

**Goal**

- Implement the mandatory non-bypassable local policy for secret access, destructive operations/files, privilege/security-boundary changes, obvious exfiltration, and uncertain parsing.

**Non-goals**

- No Jev evaluation or OpenCode replies; the module returns an assessment only.

**Constraints**

- Pure decision logic with filesystem canonicalization injected as a narrow `PathResolver` port.
- Deny-only widening; no shell execution and no user-disable option.
- Stable signal codes contain no matched values.
- Unknown/ambiguous syntax is manual-ineligible, while clear hard matches reject.

**Exact files**

- `src/guardrails/index.ts`
- `src/guardrails/path-policy.ts`
- `src/guardrails/shell-policy.ts`
- `src/guardrails/signals.ts`
- `src/domain.ts` (guardrail assessment refinements only)
- `test/guardrails.test.ts`

**Interfaces/data flow**

- `evaluateGuardrails(facts, policy, pathResolver)` returns signals, parse status, and immutable `hardDeny`.
- Shell inspection tokenizes without execution and correlates multiple resource entries for exfiltration.
- Path inspection uses location/project boundaries and nearest-existing-ancestor canonicalization; unresolved canonicalization blocks auto-allow.

**Tests**

- Every mandatory category has positive and near-miss cases.
- Obvious exfiltration requires source/sink correlation across compound resources.
- Safe read-only operations are not hard-denied.
- Obfuscation/control operators/malformed path resources yield uncertainty, not allow eligibility.
- Symlink/escape and external/system path cases are deterministic with a fake resolver.
- A fake later “Jev allow” cannot change `hardDeny` in the composed policy test.

**Definition of done**

- Guardrail tests are table-driven and contain no live shell/filesystem dependency.
- The policy is versioned and cannot be disabled through options.

**Dependencies:** Slices 0–1.

### Slice 3 — Jev questions, client boundary, and runtime validation

**Goal**

- Build the single-call structured Jev evaluator with three atomic Choice questions, fixed hosted endpoint, bounded cancellation/retries, forced-off SDK logging, and strict response validation.

**Non-goals**

- No final allow/deny/manual mapping; no OpenCode dependency.

**Constraints**

- Lazy client creation and SDK environment credential lookup.
- Fixed `https://api.typesafe.ai`; configured `jev-*` model only.
- Total deadline independent of per-attempt SDK timeout.
- Tests inject a fake fetch/evaluator and make zero live calls.

**Exact files**

- `src/jev/questions.ts`
- `src/jev/client.ts`
- `src/observability/errors.ts`
- `test/jev-client.test.ts`
- `test/redaction.test.ts` (Jev-state privacy assertions only)

**Interfaces/data flow**

- Question builder accepts only `RedactedContext` plus guardrail assessment/policy version.
- Client sends one `systemOne` request and returns only validated `JevEvaluation` metadata.
- SDK exceptions map to closed sanitized categories; raw exceptions do not escape to audit.

**Tests**

- Exact state/question JSON contains no IDs, raw paths, metadata, transcript, or secret sentinels.
- Canned fake-fetch success, 401, 429, 500, timeout, abort, malformed JSON/schema, invalid labels, NaN/out-of-range confidence, missing probabilities, and bad sums.
- SDK is configured with fixed base URL, Jev model, bounded retry, and `logLevel: "off"`.
- A custom logger that throws is never called.
- Total deadline and cleanup signal cancel fake pending work.

**Definition of done**

- No invalid or ambiguous Jev answer reaches the decision core.
- Tests pass with the key absent and global live network disabled.

**Dependencies:** Slices 0–2.

### Slice 4 — Pure decision core and reply mapping

**Goal**

- Implement conservative composition of local hard policy, Jev answers, confidence/probability thresholds, risk/intent coherence, and the closed `once | reject | manual` outcome.

**Non-goals**

- No OpenCode context, network, timers, or logging side effects.

**Constraints**

- Pure synchronous function with no I/O.
- Local hard-deny is first and non-overridable.
- High/unclear risk and absent intent cannot auto-allow in v1.
- Internal automatic reply mapping cannot represent `always`.

**Exact files**

- `src/decision/core.ts`
- `src/domain.ts` (decision reason refinements only)
- `test/decision-core.test.ts`

**Interfaces/data flow**

- `decide(guardrails, jev, thresholds)` returns a `CoreDecision` and sanitized audit metadata.
- `mapAutomaticReply(decision)` returns `once`, `reject`, or no reply.

**Tests**

- Exact threshold boundaries and just-below cases.
- Routine allow, stricter elevated allow, high-risk manual, deny, and hard-deny cases.
- Low confidence, `manual_review`, disagreement, missing intent, malformed distributions, and unknown model all manual.
- Jev allow cannot override a local hard-deny.
- Exhaustive tests prove `always` is impossible and low/medium outcomes emit no reply.

**Definition of done**

- The complete behavior table in section 7 is covered independently of SDK/OpenCode.
- Core has no imports from adapters and is trivial to fuzz with bounded inputs.

**Dependencies:** Slices 0–3.

### Slice 5 — OpenCode permission adapter, lifecycle, and reconciliation

**Goal**

- Implement the Promise V2 server plugin, event adapter, location scope, bounded known-session registry, permission port, bounded coordinator, prompt hook, stream reconnect, known-session interval/reconnect reconciliation, and cleanup.

**Non-goals**

- No CLI/TUI, permission-rule mutation, raw-data persistence, or actual Jev transport in tests.

**Constraints**

- Use only the declarations locked in Slice 0; never call nonexistent `ctx.session.list` and never add direct HTTP, private Core, or OpenCode SDK-client access.
- Learn sessions only from verified public events/prompt hooks and location-check them before reconciliation or replies.
- Event callback enqueues quickly and never waits for Jev.
- All raw request work remains inside one keyed async operation.
- Cleanup synchronously prevents new transitions and aborts event/Jev work.

**Exact files**

- `src/opencode/contract.ts`
- `src/opencode/permissions.ts`
- `src/opencode/coordinator.ts`
- `src/opencode/plugin.ts`
- `src/index.ts`
- `src/observability/audit.ts`
- `test/unit.test.ts`
- `test/contracts/opencode-v2.compile.ts`

**Interfaces/data flow**

- `contract.ts` narrows verified events/requests and owns the only OpenCode type assertions.
- `permissions.ts` wraps session `get`, per-known-session permission `list`, request `get`/`reply`, unwrapping, and sanitized error behavior.
- `coordinator.ts` owns the bounded in-memory known-session registry, dedupe, queue, semaphore, per-request locks, known-session reconciliation, and terminal tombstones.
- `plugin.ts` wires validated options and ports, starts the public event consumer and prompt hook before normal reconciliation, and returns cleanup that clears the registry.
- `src/index.ts` only default-exports `Plugin.define` with the stable package ID.

**Tests**

- Correct event variant/property extraction from the confirmed installed type.
- Out-of-location events are not processed.
- Duplicate event/reconciliation discoveries call Jev once and reply once.
- Event stream reconnect invokes `permission.list` only for already-known in-scope sessions and produces no duplicate replies.
- A prompt-hook-observed session is location-verified and becomes eligible for interval reconciliation.
- An old unknown session with no observed public event is not enumerated and does not trigger any private/direct-client fallback.
- Missing/resolved request and 404 paths never reply.
- Reply failure follows the bounded same-decision recovery rule.
- Cleanup clears timers, aborts stream/Jev calls, disposes the prompt registration, clears raw/intent data, and prevents post-cleanup transitions.
- Plugin default export/id/options compile against the exact package.

**Definition of done**

- Fake event + permission contexts demonstrate the complete state machine without network.
- No direct HTTP, OpenCode SDK client, private Core import, internal declaration path, or `ctx.session.list` workaround exists; only verified public plugin-context methods are used.

**Dependencies:** Slices 0–4.

### Slice 6 — Integration-style hardening and full deterministic suite

**Goal**

- Exercise the plugin as a fake OpenCode location/event stream with a fake Jev port, including concurrency, races, subscription/reconnect, known-session reconciliation, failure, and privacy invariants.

**Non-goals**

- No live OpenCode/Jev integration test and no credential requirement.

**Constraints**

- Fake event source honors abort/backpressure and can terminate/reconnect.
- Fake permission store models request removal and documented session-wide `reject` behavior.
- Every test uses fake timers where timing matters and has no wall-clock/network dependency.

**Exact files**

- `test/fixtures/fake-opencode.ts`
- `test/integration.test.ts`
- `test/unit.test.ts`
- `test/jev-client.test.ts`
- `src/opencode/coordinator.ts` (only defects found by tests)
- `src/opencode/permissions.ts` (only defects found by tests)
- `src/observability/audit.ts` (only defects found by tests)

**Interfaces/data flow**

- Emit a valid asked event, duplicates, out-of-scope events, manual resolution, reconnect, and cleanup through the fake context.
- Inject deterministic Jev answers/delays/errors and inspect captured outbound states plus all sanitized audit events.

**Tests**

- High allow produces exactly `once`; high deny and hard-deny produce `reject`; every uncertainty/failure leaves pending.
- Missing/invalid key path with no Jev client still leaves ordinary requests pending.
- A hard-deny rejects even with missing/failing Jev.
- Concurrent requests respect max concurrency/queue size and dedupe by location/session/request.
- User resolves during Jev delay; no late reply occurs.
- `reject` clears session peers; workers reconcile as externally resolved and do not reply again.
- A deliberately missed `permission.asked` event in a session already known from a prompt hook is recovered by `ctx.permission.list({ sessionID })` without a duplicate Jev call or reply.
- An old unknown session with no post-subscription public observation is not discovered, and the fake asserts that no session-list, direct HTTP, private Core, or SDK-client method is invoked.
- Plugin unloaded during Jev/queue/reply boundaries creates no new late reply.
- Sentinel secret, command, path, prompt, API key, arbitrary metadata, and raw SDK error text are absent from Jev state and every log sink.
- Run the suite repeatedly and under shuffled test order to detect shared state.

**Definition of done**

- All confirmed requirements have a deterministic test, including cleanup and best-effort known-session reconciliation plus the explicit unknown-old-session limitation.
- `npm test` remains green with networking disabled and no API key.

**Dependencies:** Slices 0–5.

### Slice 7 — Documentation, packaging, and release verification

**Goal**

- Produce a publishable, installable package with accurate setup/config/privacy/limitations documentation and no credential or unrelated config changes.

**Non-goals**

- No live API smoke test, CLI/TUI docs, npm publication, or license legal advice.

**Constraints**

- README claims must match tests and official docs.
- State hosted processing and account-specific retention terms accurately.
- Include the exact supported OpenCode/Node/SDK compatibility range.
- `prepack` runs the complete offline verification.

**Exact files**

- `README.md`
- `LICENSE`
- `CHANGELOG.md`
- `package.json`
- `package-lock.json`
- `tsconfig.json`
- `vitest.config.ts`
- `.gitignore`

**Interfaces/data flow**

- Installation: npm package name/version, Node `>=22.19.0` requirement and dependency reason, matching `engines.node`, OpenCode V2 config object, and runtime `TYPESAFE_API_KEY` secret-manager setup.
- Documentation includes the full options/defaults table, request-state behavior, `once`/`reject` mapping, manual fallback, event volatility, location scope, privacy projection, mandatory guardrails, TypeSafe hosted processing, the session-wide reject limitation, and the inability to enumerate pre-subscription pending requests in old unknown sessions.
- Explicitly state that OpenCode-resolved allow/deny operations do not emit a pending request and the plugin does not change rules.

**Tests**

- Parse the README JSONC snippet as JSONC, validate option keys/defaults against the parser in a docs/config test if practical without adding a second config implementation, and assert README/package `engines.node` both state `>=22.19.0`.
- Pack inspection confirms only intended files and built ESM/types are present.
- Install the packed tarball into a temporary consumer and import the default export without starting OpenCode or making a network call.

**Definition of done**

- `npm run verify` and `npm pack --dry-run` pass.
- A fresh consumer can resolve the package and default export using the documented Node/ESM setup.
- No live credential or network is needed for verification.

**Dependencies:** Slices 0–6.

## 11. Verification commands

Run from `/home/curious/opencode-jev-permissions`:

```sh
node -e 'const [a,b,c]=process.versions.node.split(".").map(Number); if (a<22 || (a===22 && (b<19 || (b===19 && c<0)))) process.exit(1)'
npm pkg get engines.node
npm ci
npm run typecheck
env -u TYPESAFE_API_KEY npm test
npm run build
env -u TYPESAFE_API_KEY npm run verify
npm pack --dry-run
```

`engines.node` must be `>=22.19.0`, and the verification runtime check must pass. `npm test` must use the test setup that disables live network access. `npm run verify` must chain the engine check, typecheck, deterministic tests, and build. A temporary packed-consumer import is part of Slice 7 but must not contact OpenCode or TypeSafe.

No command in the required verification suite may make a live Jev call or require a real key.

## 12. Acceptance criteria

The implementation is accepted only when all are true:

1. The package is an ESM strict-TypeScript OpenCode V2 Promise server plugin with default `Plugin.define` export, no CLI/TUI surface, and matching `engines.node`/README/verification requirements of `>=22.19.0` because the installed `undici` 8.11.2 dependency requires that floor.
2. Every permission request observed while the plugin is active for the instance's authoritative location—through `permission.asked` or best-effort reconciliation of a session learned from public events/prompt hooks—enters the coordinator; no action/agent/model allowlist skips an observed request.
3. Cross-location events/sessions are ignored safely using public `ctx.session.get` location data, even though the server event stream is cross-location and live-only.
4. Every valid observed request, including local hard-deny requests, reaches the Jev evaluator exactly once per accepted in-process discovery; malformed requests and missing credentials are the documented exceptions.
5. Jev receives one minimal structured state with no full transcript, file contents, IDs, arbitrary metadata/messages, raw absolute paths, or unredacted secrets.
6. Secret access, destructive files/commands, privilege/security-boundary changes, obvious exfiltration, and uncertain parsing have deterministic non-bypassable tests.
7. No Jev result can override a mandatory local hard-deny.
8. Only a validated, coherent high-confidence routine/elevated allow maps to `once`; high/unclear risk cannot auto-allow in v1.
9. Only a validated high-confidence deny maps to `reject`; uncertain, ambiguous, malformed, missing-key, invalid-key, timeout, rate-limit, API, and transport paths send no reply and leave the request pending.
10. The adapter cannot construct or emit `always` under any code path.
11. `once` is requested only after a fresh pending `get`; already-resolved requests receive no reply.
12. Duplicate event/reconciliation discoveries, setup/event overlap, concurrent requests, bounded queueing, stream reconnect, periodic known-session reconciliation, reply races, and documented session-wide `reject` behavior are tested.
13. The implementation uses no `ctx.session.list`, direct HTTP, private Core import, or OpenCode SDK-client workaround. A missed request is recovered only for a session known while active; an already-pending request in an old unknown session with no observed public event is explicitly outside guaranteed coverage and remains untouched rather than being claimed or fail-opened.
14. Cleanup aborts event/Jev work, clears timers/data/hooks, prevents new replies, and is safe when invoked more than once.
15. Logs/audits contain only allowlisted metadata and pass sentinel-based absence tests for commands, paths, prompts, secrets, API keys, raw errors, and full responses.
16. The TypeSafe SDK is pinned, uses the fixed official hosted base URL and Jev model, reads `TYPESAFE_API_KEY` from the environment, and has SDK logging forced off.
17. Missing key does not prevent plugin setup; all ordinary requests remain manually pending.
18. Tests are deterministic, shuffled/repeat safe, make zero live calls, and pass with the API key unset.
19. README contains accurate install/config/default/threshold/privacy/limitation documentation, the V2 JSONC plugin example, and no real key.
20. `npm ci`, typecheck, tests, build, verify, pack dry-run, and offline packed-consumer import all pass under Node `>=22.19.0`.
21. This planning task update creates no application/test code; its only authored file is this plan, and any pre-existing or concurrently created user files are left untouched.

## 13. Risks and open questions

### Risks

- **Server event shape drift:** the public docs expose `OpenCodeEvent` but not the full `permission.asked` variant. Slice 0's installed-declaration lock and compile fixture are mandatory.
- **Permission resource ambiguity:** `Permission.Request.resources` is an unlabelled string array. Conservative classification plus unknown-resource manual eligibility is required; do not infer undocumented prefixes without installed evidence.
- **`reject` is session-wide:** the only public rejection reply can clear unrelated pending approvals. The plugin evaluates concurrently, documents the behavior, and uses authoritative per-session `list/get` for known sessions; there is no public per-request deny reply alternative.
- **Event volatility/slow consumers:** the stream has no replay and can fail when slow. Fast enqueueing, reconnect, and periodic reconciliation are mandatory for known sessions, but neither reconnect nor the public Promise API provides complete missed-event recovery for old unknown sessions.
- **Shell grammar bypass:** a lexical/token scanner cannot be a complete shell parser. Unparseable/suspicious forms are manual-ineligible, and README must not overstate coverage.
- **Prompt injection/Jev calibration:** redacted intent and resources can still contain adversarial instructions. Only local deterministic hard policy may block or allow unconditionally; threshold tuning requires real evaluation data that this credential-free task does not perform.
- **Privacy across hosted API:** minimal redaction lowers exposure but cannot guarantee removal of every secret pattern. Users must review TypeSafe account terms/DPA/ZDR and the exact outbound projection policy.
- **Model alias movement:** `jev-latest` can change behavior. The response model is audited; README recommends pinning a versioned Jev ID after threshold calibration while retaining `jev-latest` as the conservative default.
- **Missing intent/cache fallback/subagents:** the local fallback for an event-discovered or known-session-reconciled request may be ambiguous. Absence blocks auto-allow but not a high-confidence deny/hard-deny.
- **No public enumeration API:** the Promise `ctx.session` domain has no `list`, and permission listing requires a known session ID. Direct HTTP, private Core, and SDK-client workarounds are explicitly prohibited rather than treated as optional implementation details.
- **Instance duplication:** if OpenCode loads duplicate copies for one directory, authoritative location checks and request tombstones reduce but cannot create a cross-runtime distributed lock. README should advise one package configuration per location.

### Decisions recorded for v1

- Promise server plugin, not Effect or CLI/TUI.
- Event/reply transport, not the permission evaluation hook.
- `jev-latest` default, Jev-only configurable model, fixed official API base URL.
- No durable raw-data storage.
- Three atomic Jev Choice questions in one call.
- High/unclear Jev risk is never auto-allowed.
- Local hard-deny is the sole failure-path exception to manual fallback.
- Per-session `reject` cascade is accepted as the documented cost of the only public reject reply.
- Public-API-only reconciliation tracks known in-memory sessions; it does not promise universal startup catch-up for old unknown sessions.
- Node `>=22.19.0` is the package floor imposed by the installed OpenCode/`undici` graph, even though individual dependencies advertise lower or wider ranges.

### User input still useful, but not blocking planning

- Choose MIT versus Apache-2.0 for `LICENSE`.
- Confirm the desired npm package name/scope if `opencode-jev-permissions` is unavailable or already owned; no registry lookup or publication is part of this task.
- Decide later whether to pin a versioned Jev model after offline fixture/threshold calibration; defaults are already safe.
- Decide later whether users need an opt-in way to widen coverage by converting selected OpenCode `allow` results to `ask`. That would require a separate permission-policy/evaluation-hook design and is not in v1.

## 14. Official documentation used

### OpenCode V2

- Overview: https://opencode.ai/v2/docs/
- Server plugins, Promise context, events, permissions, and publishing: https://opencode.ai/v2/docs/build/plugins/
- Permissions, actions, defaults, `once`/`always`/`reject`, and session-wide reject behavior: https://opencode.ai/v2/docs/permissions/
- Configuration/plugin options and locations: https://opencode.ai/v2/docs/config/
- API reference and `Permission.Request`/`Permission.Reply`: https://opencode.ai/v2/docs/api/
- Official OpenAPI document linked by the V2 API reference: https://opencode.ai/v2/openapi.json
- Client event-stream volatility and location behavior: https://opencode.ai/v2/docs/build/client/
- V2 plugin migration/lifecycle/cleanup guidance: https://opencode.ai/v2/docs/build/plugins/migrate-v1/

### TypeSafe AI

- JavaScript/TypeScript SDK and documented client import: https://docs.typesafe.ai/sdk/javascript
- `TypeSafeClient.systemOne`: https://docs.typesafe.ai/sdk/javascript/api/classes/TypeSafeClient
- Client config, environment key, fixed base URL/model/logging options: https://docs.typesafe.ai/sdk/javascript/api/interfaces/TypeSafeClientConfig
- Per-call cancellation/timeout/retry options: https://docs.typesafe.ai/sdk/javascript/api/interfaces/RequestOptions
- Retry policy and body-logging warning context: https://docs.typesafe.ai/sdk/javascript/api/interfaces/RetryPolicy
- Structured state guidance: https://docs.typesafe.ai/concepts/state
- Choice request/response and parallel-question guidance: https://docs.typesafe.ai/primitives/choice
- Confidence semantics: https://docs.typesafe.ai/confidence
- Confidence-gated routing: https://docs.typesafe.ai/patterns/confidence-routing
- Current Jev model, limits, data handling, and version pinning: https://docs.typesafe.ai/models
- Jev's role versus coding-agent models: https://docs.typesafe.ai/introduction/coding-agents
- Official legal/data-handling entry point: https://docs.typesafe.ai/legal
