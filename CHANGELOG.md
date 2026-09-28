# Changelog

All notable changes to `opencode-jev-permissions` are documented here.
This project follows semantic versioning; `0.1.0` is the initial publishable release.

## [Unreleased]

- Calibrated the default Jev thresholds so clearly supported routine requests
  can resolve automatically while elevated, unclear, and low-confidence cases
  remain pending; deterministic destructive/secret/privilege/boundary and
  obvious-exfiltration guardrails remain hard rejects.

### Fixed

- Production path guardrails now resolve symlinks, normalize traversal, and
  resolve the nearest existing ancestor for new destinations before deciding
  project/external/system/home/protected/secret scope.
- Mandatory local hard-denies now reject immediately without sending an
  unnecessary Jev request.
- `pluginLogLevel` now emits the already-sanitized audit records as JSON at
  `info` or `warn`; `off` remains silent.

## [0.1.0] - 2026-09-24

Initial publishable offline-verified release. Package-only; no activation,
registration, live network calls, or credential handling outside the
documented runtime environment variable.

### Behavior

- OpenCode V2 Promise server plugin (`Plugin.define`, id
  `opencode-jev-permissions`) with no CLI/TUI surface.
- Observes permission requests raised while the plugin instance is active:
  `permission.asked` events carry the request at `data` (`data.sessionID`,
  `data.id`), verified against the installed `@opencode/plugin` declarations.
- Location-scoped: replies only for sessions whose authoritative
  `session.location.directory` normalizes equal to the instance
  `ctx.location.directory`. The server event stream is cross-location, so
  ownership is verified via public `ctx.session.get` before any further work.
- Authoritative flow per request: ownership check, `permission.get`,
  validation, local intent, guardrails, allowlisted redacted projection, one
  bounded Jev evaluation, pure decision, fresh pre-reply `get`, at most one
  automatic reply.
- Automatic replies are only `once` (highly confident allow) and `reject`
  (highly confident deny or mandatory local hard-deny). There is no `always`
  path. Uncertainty, ambiguity, malformed input, missing/invalid credentials,
  timeout, cancellation, rate limits, transport/API failures, queue overflow,
  or low confidence send no reply and leave the request pending for manual
  review in OpenCode.
- Mandatory local guardrails (`guardrails-v1`, cannot be disabled) cover
  secret access, destructive operations/files, privilege and
  security-boundary changes, obvious exfiltration (secret source correlated
  with a network sink), and uncertain parsing. Any hard-deny forces `reject`
  regardless of Jev output; unknown or suspicious syntax blocks auto-allow.
  The scanner is lexical/conservative and is not claimed as a complete shell
  security boundary; OpenCode permission configuration remains a separate layer.
- Relevant intent is at most one redacted bounded fragment: prompt-hook cache
  first, otherwise the nearest preceding user message from the local
  `session.context` fallback. Assistant messages, tool output, reasoning,
  file contents, transcripts, and arbitrary metadata are never sent. Absent
  intent blocks auto-allow but not a high-confidence deny or hard-deny.
- Outbound Jev state is an allowlisted projection only (redacted action/tool,
  shell-only redacted commands, normalized kind/scope resources, signal
  codes, counts, optional redacted intent, versioned local policy with
  `unknown: manual_review` and `maximum_grant: once`). Session/message IDs,
  raw absolute paths, home directories, metadata, messages, transcripts, and
  environment data are omitted.
- One `systemOne` call with three parallel atomic Choice questions
  (`intent_alignment`, `risk_class`, `policy_decision`) against the fixed
  hosted base URL `https://api.typesafe.ai`, default model `jev-latest`
  (only `jev-*` names accepted), 8-second total deadline, at most 1 retry
  with bounded backoff, caller/cleanup abort, and SDK `logLevel: "off"`.
  Responses are runtime-validated (labels, choice type, finite
  confidence/probabilities in `[0,1]`, complete distributions, probability
  sum within `0.01`, model/usage shape) before reaching the decision core.
- Conservative decision composition with asymmetric thresholds (routine
  allow `0.98` confidence / `0.95` probability; elevated allow `0.99`
  confidence; deny `0.95` / `0.90`; auxiliary `0.90`; elevated threshold
  never below routine). `high`/`unclear` risk never auto-allows in v1.
- Best-effort reconciliation only for sessions learned through verified
  public events or the public prompt hook while the instance remains active
  (bounded in-memory registry, TTL, cleared on cleanup). Periodic
  `permission.list({ sessionID })` covers known sessions after start,
  reconnect, new sessions, and at `reconcileIntervalMs`. There is no public
  session enumeration, direct HTTP, private Core, or SDK-client workaround;
  an already-pending request in an old unknown session with no observed
  public event after subscription is explicitly out of guaranteed coverage.
- Documented OpenCode limit: `reject` clears the target and every other
  pending request in that session. Workers re-check and record external
  resolution without further replies.
- Operations OpenCode resolves to `allow` or configured `deny` before a
  pending request exists emit no request and are not covered; the plugin
  does not read or mutate permission rules.
- Invalid plugin options enter a safe no-op mode (`config_invalid`,
  requests remain pending). Missing key does not prevent setup; ordinary
  requests remain pending. Cleanup synchronously stops new work, aborts
  event/Jev work, clears timers/data/hooks, and is safe to invoke twice.
- Logs and audit records contain only allowlisted metadata (categories,
  counts, signal codes, confidence buckets, token usage, sanitized error
  categories). Raw values, secrets, paths, prompts, bodies, headers, and
  keys are never logged, audited, or persisted.

### Configuration

- Full options/defaults documented in README (model, timeouts, retries,
  concurrency, queue, reconcile interval, thresholds, limits, log level).
  Unknown keys, invalid ranges, non-finite numbers, non-`jev-*` models, and
  invalid enums are rejected to safe no-op.
- Runtime secret is process-environment only: exact `TYPESAFE_API_KEY` in
  the OpenCode process environment or secret manager. The plugin does not
  load `.env` and does not use OpenCode `{env:...}` substitution.

### Packaging and verification

- ESM package, Node `>=22.19.0` (floor imposed by `undici@8.11.2` in the
  installed OpenCode dependency graph), exact `2.0.16` / `0.6.0` dependency
  pins, `dist` ESM JavaScript plus declarations, `files` allowlist.
- `npm run verify` chains the Node engine check, `typecheck` (no-emit),
  deterministic offline tests, and `build`. `prepack` runs the same offline
  verification. No script requires network, credentials, or OpenCode startup.
- Verified offline with `npm run typecheck`, `env -u TYPESAFE_API_KEY
  npm test`, `env -u TYPESAFE_API_KEY npm run verify`, `npm pack --dry-run`,
  and a temporary packed-consumer default-export import without starting
  OpenCode or contacting TypeSafe.

### License

- No license was previously declared, so this release defaults to
  Apache-2.0 (`LICENSE`, `package.json` `license` field). The selection is
  replaceable: if a different license is desired, replace both files
  together before publishing. This note is not legal advice.
