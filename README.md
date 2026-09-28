# opencode-jev-permissions

OpenCode V2 Promise **server** permission proxy evaluated by TypeSafe AI's
hosted Jev System One model.

For every permission request the plugin observes while active in its loaded
location, it first applies mandatory local guardrails. A local hard-deny is
rejected immediately without a hosted call. Every other valid request gets
one bounded Jev evaluation over a minimal redacted projection and then either
receives `once`, receives `reject`, or remains pending for manual review in
OpenCode.

Package-only. No activation, registration, live network calls, or credential
handling outside the documented runtime environment variable. Offline
verification only; no live API smoke test and no npm publication are part of
this package.

- Package: `opencode-jev-permissions`
- Version: `0.1.0`
- Runtime: ESM, strict TypeScript, Node `>=22.19.0`
- Entrypoints: `./dist/index.js` (ESM) with `./dist/index.d.ts` types
- Plugin ID: `opencode-jev-permissions` (default `Plugin.define` export)
- No CLI/TUI surface and no `./tui` export

## Compatibility

| Component | Supported version | Notes |
|---|---|---|
| Node.js | `>=22.19.0` | Required floor. Pinned `@opencode/plugin@2.0.16` resolves through `@opencode/util` / `@effect/platform-node` to `undici@8.11.2`, whose engine is Node `>=22.19.0`. TypeSafe SDK and Vite advertise lower/wider ranges; they do not lower this package floor. `engines.node` and verification enforce the same floor. |
| OpenCode | V2 Promise server plugin API | Uses only verified public declarations: `Plugin.define`, `ctx.location`, `ctx.event.subscribe`, `ctx.permission.list/get/reply`, `ctx.session.get/context/hook("prompt")`. No `ctx.session.list`, direct HTTP, private Core import, or OpenCode SDK-client workaround. |
| `@opencode/plugin` | `2.0.16` exact | Locked in `package.json` / `package-lock.json`. |
| `@typesafe-ai/sdk` | `0.6.0` exact | Locked in `package.json` / `package-lock.json`. Publishes ESM/CommonJS/declarations; this package uses the ESM import. |
| TypeScript | `5.9.3` (dev-only) | Strict, including `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. |
| Vitest | `4.0.18` (dev-only) | Deterministic offline tests; production dependencies remain minimal. |

Production dependencies are only `@opencode/plugin` and `@typesafe-ai/sdk`.
TypeScript and Vitest are dev-only.

## Installation

```sh
node -e 'const [a,b,c]=process.versions.node.split(".").map(Number); if (a<22 || (a===22 && (b<19 || (b===19 && c<0)))) process.exit(1)'
npm install opencode-jev-permissions@0.1.0
```

The package ships built ESM JavaScript plus TypeScript declarations under
`dist/` (`files` allowlist: `dist`, `README.md`, `LICENSE`, `CHANGELOG.md`).
Build output is never committed.

A fresh ESM consumer resolves the default export without starting OpenCode
and without network or credentials:

```js
import plugin from "opencode-jev-permissions";
console.log(typeof plugin);
```

## OpenCode configuration (unapplied snippet only)

The snippet below is documentation only. It is not applied by this package
and does not activate or register anything outside the package. Do not add a
real API key to configuration, options, fixtures, or examples.

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
          "allowConfidence": 0.8,
          "allowProbability": 0.85,
          "elevatedAllowConfidence": 0.9,
          "denyConfidence": 0.85,
          "denyProbability": 0.8,
          "auxiliaryConfidence": 0.8
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

The plugin does not add a `permissions` array and does not read or mutate
OpenCode permission rules. OpenCode resolves `allow` / `ask` / `deny`
before publishing a pending request. Users who want more operations to reach
the proxy must configure their own narrow `ask` rules; that policy choice is
outside this plugin. This README provides no instructions that auto-approve
permissions.

### Options and defaults

`ctx.options` is untrusted and parsed with an explicit runtime validator.
Unknown keys, invalid ranges, non-finite numbers, non-`jev-*` model names,
or invalid enum values put setup into a safe no-op mode that logs only
`config_invalid`; requests then remain pending. Mandatory guardrails cannot
be disabled.

| Option | Default | Validation / meaning |
|---|---:|---|
| `model` | `"jev-latest"` | Non-empty `jev-*`; official hosted Jev only. No arbitrary endpoint/model provider. |
| `timeoutMs` | `8000` | Total wall-clock deadline across attempts; 100–30000. |
| `maxRetries` | `1` | 0–2; bounded below SDK defaults. |
| `maxConcurrency` | `4` | 1–16 Jev evaluations across the instance. |
| `maxQueueSize` | `256` | 1–2048; overflow is manual pending with no network call. |
| `reconcileIntervalMs` | `30000` | 5000–300000; best-effort catch-up for missed events only in sessions known while active. |
| `thresholds.allowConfidence` | `0.80` | 0–1; routine auto-allow. |
| `thresholds.allowProbability` | `0.85` | 0–1; selected `allow_once` probability. |
| `thresholds.elevatedAllowConfidence` | `0.90` | 0–1 and not lower than routine threshold. |
| `thresholds.denyConfidence` | `0.85` | 0–1. |
| `thresholds.denyProbability` | `0.80` | 0–1. |
| `thresholds.auxiliaryConfidence` | `0.80` | Required for intent/risk auxiliary answers used in composition. |
| `limits.commandChars` | `4096` | 256–16384; redacted outbound cap. |
| `limits.intentChars` | `2000` | 128–8192; redacted outbound cap. |
| `limits.resources` | `16` | 1–64; extra values are summarized, not silently dropped. |
| `limits.resourceChars` | `512` | 64–4096 per normalized resource. |
| `pluginLogLevel` | `"info"` | `info \| warn \| off`; writes JSON audit lines containing sanitized plugin metadata to the process console. It never changes the TypeSafe SDK logger (always `"off"`). |

## Secret setup (process environment only)

The SDK reads the exact variable `TYPESAFE_API_KEY` from the OpenCode
process environment when `apiKey` is omitted. Configure it only there, for
example through a secret manager or shell environment:

```sh
export TYPESAFE_API_KEY='<provided-at-runtime>'
```

Rules:

- The plugin never reads `TYPESAFE_API_KEY` into application config, logs,
  errors, or outbound state, and never prints, logs, persists, or sends it.
- The plugin does not load `.env` files.
- OpenCode `{env:...}` substitution is not used for this plugin; the plugin
  intentionally relies on the process environment through the TypeSafe SDK.
- A misspelled or differently named variable will be ignored.
- Do not put a key in `opencode.jsonc`, plugin options, an `apiKey` field,
  fixtures, snapshots, or README examples.
- Missing or whitespace-only key does not prevent plugin setup; ordinary
  requests remain manually pending (see fail-to-manual behavior below).
- Do not include a real key in any committed file.

## Request semantics

### `once` / `reject` / manual

- `once` means a highly confident, fully validated allow for exactly one
  use. The internal automatic-reply union is only `once | reject`; no code
  path accepts, constructs, stores, or emits `always`.
- `reject` means a highly confident deny or a mandatory local hard-deny.
- Manual means pending: uncertainty sends no OpenCode reply. The request
  remains owned by OpenCode for manual review. Manual is never translated
  to `once`, and never to `reject` unless a local hard-deny independently
  requires it.

Evaluation order for each valid observed request:

1. Validation failure is manual, except a previously detected local
   hard-deny remains `reject`.
2. Any mandatory local guardrail hit returns `reject` immediately and
   irrevocably without calling Jev.
3. Unknown final Jev label is manual.
4. `manual_review` is manual at any confidence.
5. `deny` is `reject` only when final confidence, selected probability,
   valid distribution, and model identity meet the deny thresholds;
   otherwise manual.
6. `allow_once` requires all of: no hard/uncertain parser signal, relevant
   intent exists with `supported` alignment at the auxiliary floor, risk is
   `routine` at routine thresholds or `elevated` at the stricter elevated
   threshold (never `high`/`unclear` in v1), final confidence/probability
   thresholds met, and all distributions valid; otherwise manual.
7. Only `ALLOW_ONCE -> once` and `REJECT -> reject` are mapped. Defaults are
   intentionally asymmetric: allowing requires higher confidence and
   coherent auxiliary answers because a false allow can affect security.

Before any automatic reply the adapter performs a fresh `get`. A missing
request (including 404/not-found) is external resolution and wins over a
late Jev result; no reply is sent. Reply transport uses bounded same-decision
recovery: one fresh `get`, then at most one retry of the identical decision.
A different decision is never recomputed because of a reply error.

### Fail-to-manual behavior

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

No key, timeout, rate-limit, API, transport, malformed, or uncertain path
implies automatic allow. There is no fail-open.

### Location scope

A plugin instance may reply only to sessions whose authoritative
`session.location.directory` normalizes equal to its loaded
`ctx.location.directory`. The server event endpoint is cross-location, so
the plugin never assumes an event belongs to its location; it verifies
ownership through public `ctx.session.get` before reconciliation or replies
and ignores out-of-scope sessions safely.

### Events, reconciliation, and known limitations

- The plugin observes `permission.asked` events while active. The installed
  public shape carries the request at `data` with `data.sessionID` and
  `data.id`. Event subscriptions are live-only with no replay or reconnect;
  a late subscriber sees a current `server.connected` marker rather than
  missed business events, and the stream can fail when slow. Event callbacks
  validate and enqueue quickly and never await Jev.
- A bounded in-memory `KnownSessionRegistry` records only session IDs
  learned from verified public events or the public prompt hook after
  authoritative location verification. It is bounded, has a TTL, is cleared
  on cleanup/reload, stores IDs/metadata only, and is never treated as a
  complete server-side index.
- At the configured interval, after reconnect, and after a new session is
  learned, the plugin calls only `ctx.permission.list({ sessionID })` for
  each known in-scope session, then feeds each returned pending request
  through the same keyed coordinator with `get` before processing and again
  before any reply. Duplicate event/reconciliation discoveries call Jev once
  and reply at most once per request.
- There is no public `ctx.session.list`, location-wide permission list,
  direct HTTP fallback, private Core API, or OpenCode SDK-client workaround.
  A missed `permission.asked` event can be recovered only if its session was
  already learned from another public event or prompt hook while the plugin
  instance remained active. An already-pending request in an old unknown
  session that emitted no observed public event after subscription is
  explicitly outside guaranteed coverage and remains untouched rather than
  claimed or fail-opened.
- Operations OpenCode resolves to `allow` or configured `deny` before a
  pending request exists emit no pending request and are not covered.
- Session-wide `reject` limitation: per the official permissions guide, the
  only public rejection reply rejects the target and every other pending
  permission request in that session. The plugin evaluates concurrently,
  documents this behavior, and uses authoritative per-session `list`/`get`
  for known sessions; there is no public per-request deny alternative.
  Workers for cleared peers re-check and record external resolution without
  further replies.
- Cleanup aborts event/Jev work, clears timers, raw/intent data, and prompt
  hook registration, prevents new replies, and is safe when invoked more
  than once. A fresh instance starts with no known sessions.

## Privacy and TypeSafe hosted processing

Jev receives one minimal structured state with three parallel atomic Choice
questions. No full transcript, assistant reasoning, tool output, file
contents, arbitrary metadata, whole session history, session/message IDs,
raw absolute paths, home directories, or unredacted secrets are sent.

Sent (allowlisted projection only):

- `request.action` and optional verified tool name;
- redacted shell command(s), only for shell actions;
- normalized/redacted affected resources with kind (`path | url | command |
  query | generic | unknown`) and scope (`project | external | home |
  system | secret | protected | unknown`) plus a short display token;
- deterministic signal codes and bounded summary counts;
- optional redacted bounded `user_intent` (at most one fragment);
- `local_policy` with version (`guardrails-v1`), hard-deny codes,
  `unknown: "manual_review"`, and `maximum_grant: "once"`;
- `redaction_complete` and truncation flags (blocking auto-allow when false).

Omitted: session IDs, message IDs, raw paths/home roots, arbitrary
`metadata`/`message`/`source` structures, environment objects, transcripts,
and file contents.

Redaction preserves shell verbs/structure and relevant non-sensitive names
while replacing credential values, authorization material, cookies,
private-key material, signed query values, and high-entropy secret literals;
strips URL userinfo, fragments, and sensitive query keys/values; converts
absolute home/workspace prefixes to tokens such as `<project>`, `<home>`,
`<external>`, `<system>`; and caps commands, intent, resource count, and
each resource with head/tail truncation markers. A post-redaction
sensitive-literal scan omits unsafe fields and marks
`redaction_complete: false`, which blocks auto-allow. Oversize or ambiguous
context is a manual signal.

Relevant intent is at most one fragment: the prompt-hook cache (session ID
key; redacted text, revision, timestamp, truncation/redaction flags; new
prompts replace rather than concatenate) or, when empty, the nearest
preceding user message to the source tool message (otherwise the latest user
message) from a local ephemeral `session.context` read. Absent intent blocks
auto-allow but not a high-confidence deny or hard-deny.

Mandatory guardrails are deterministic, versioned (`guardrails-v1`), and
cannot be disabled. They cover secret access (environment dumps, non-example
`.env*`, SSH/private keys, cloud/registry credentials, browser/keychain
stores, shadow files, password/token/cookie/authorization reveal), destructive
operations/files (force/recursive deletion, root/home/workspace deletion,
disk overwrite, destructive Git reset/clean/force-push, mass permission
changes, truncate/drop, shutdown, edits to system/credential/VCS-hook/
OpenCode policy/plugin/security-boundary files), privilege and
security-boundary changes (`sudo`/`doas`/`su`/elevated runners,
setuid/setgid, firewall/security tooling, auth service config, system path
mutation, attempts to weaken this plugin or OpenCode policy), obvious
exfiltration (secret/credential source plus network sink or upload client in
one command/resource set), and uncertain parsing
(encoded/nested/unsupported shell constructs, malformed paths, unavailable
canonicalization, ambiguous classification). False positives conservatively
leave requests pending or reject. The scanner is lexical plus token-based
with nearest-existing-ancestor canonicalization and is not a complete shell
security boundary; OpenCode permission configuration remains a separate
layer.

TypeSafe hosted processing: evaluation is performed by the hosted Jev model
at the fixed official base URL `https://api.typesafe.ai` (no configurable
base URL or proxy; the SDK reads `TYPESAFE_API_KEY` itself) with SDK
`logLevel: "off"` and a separate sanitized plugin logger. Per TypeSafe
documentation, customer requests are not used for training, while zero data
retention is described as available for enterprise customers; this README
does not imply universal zero retention for every account. Review TypeSafe
account terms, DPA, and the exact outbound projection above before use.
Jev is a structured decision model, not an LLM agent; it cannot replace
OpenCode's model or permission system, and Jev output never overrides local
hard policy.

Audit records and logs contain only allowlisted metadata: schema/plugin
versions, action/tool categories, resource kind/scope counts, stable signal
and reason codes, parse/redaction flags, Jev model version, selected label,
rounded or bucketed confidence/probability, token usage, latency buckets,
outcome (`once | reject | manual | external | skipped`), and sanitized error
category/status. Raw or redacted commands/paths/intent, matched values,
request metadata, full Jev state/questions/answers, raw errors, headers, and
keys are never logged, audited, or persisted.

## Jev evaluator

- Fixed `baseURL: "https://api.typesafe.ai"`, Jev-only `defaultModel`
  (default `"jev-latest"`), `logLevel: "off"` with a no-op logger.
- Lazily instantiated so a missing key does not prevent setup.
- Total 8-second wall-clock deadline independent of the per-attempt SDK
  timeout, bounded retries (`maxRetries`, default `1`), bounded backoff,
  and abort for cleanup/deadline. No retry for malformed answers, 401, or
  deterministic local failures.
- One `systemOne` call with three parallel Choice questions:
  `intent_alignment` (`supported | contradicted | unclear`), `risk_class`
  (`routine | elevated | high | unclear`), `policy_decision` (`allow_once |
  deny | manual_review`). Final criteria define `allow_once` as compatible
  with non-negotiable local policy and relevant intent, `deny` as a clear
  safety conflict, and `manual_review` for ambiguity.
- Strict runtime validation before the decision core: `type === "choice"`,
  exact labels, finite confidence/probabilities in `[0,1]`, complete
  distributions, probability sum within `0.01`, and valid model/usage
  shape. Errors map to a closed sanitized taxonomy without interpolating
  messages, bodies, headers, or request state.
- `jev-latest` is the documented stable alias and SDK default. The response
  model is audited; pin a versioned `jev-*` ID after threshold calibration
  if needed while retaining `jev-latest` as the conservative default.

## Verification (offline)

From the project root (Node `>=22.19.0`):

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

`npm run verify` chains the engine check, `typecheck` (no-emit),
deterministic tests, and `build` (emits ESM plus declarations to ignored
`dist/`). `prepack` runs the same complete offline verification. No script
requires network, credentials, or OpenCode startup; tests replace network
with a throwing fake and unset `TYPESAFE_API_KEY`.

Pack inspection confirms only intended files and built ESM/types are
included. A temporary packed-consumer check installs the tarball outside the
repo and imports the default export without starting OpenCode or making
network calls, asserting basic export shape only.

## License

Apache-2.0; see `LICENSE` and the `license` field in `package.json`.

No license was previously declared, so `0.1.0` defaults to Apache-2.0. The
selection is replaceable: replace both files together before publishing if
a different license is desired. See `CHANGELOG.md`. This note is not legal
advice.
