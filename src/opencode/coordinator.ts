/**
 * Bounded permission coordinator (Slice 5).
 *
 * Owns the known-session registry, keyed dedupe, bounded queue/semaphore,
 * per-request terminal lock with at-most-one reply, per-session reply
 * serialization, known-session reconciliation, event-stream reconnect with
 * bounded backoff, and terminal tombstones. Event callbacks validate and
 * enqueue quickly and never await Jev. Raw request work stays inside one
 * keyed async operation; only redacted context crosses to Jev.
 */

import {
  canonicalRequestKey,
  extractPermissionAsked,
  extractPromptSession,
  extractPromptText,
  isValidID,
  normalizeLocationDirectory,
  validatePermissionRequest,
  type NormalizedPermissionRequest,
} from "./contract.js";
import {
  fetchSessionContext,
  getAuthoritativeRequest,
  getSessionDirectory,
  listPendingRequests,
  preReplyCheck,
  replyWithRecovery,
  type PermissionPorts,
  type ReplyDecision,
} from "./permissions.js";
import { RelevantIntentCache, selectRelevantIntent } from "./intent-cache.js";
import { buildRedactedContext } from "./context-builder.js";
import { evaluateGuardrails } from "../guardrails/index.js";
import {
  classifyPathScope as classifyResolvedPathScope,
  type PathResolver,
} from "../guardrails/path-policy.js";
import { GUARDRAIL_POLICY_VERSION } from "../guardrails/signals.js";
import { decide, mapAutomaticReply } from "../decision/core.js";
import type { JevEvaluateResult } from "../jev/client.js";
import type {
  ActionCategory,
  AuditMetadata,
  AuditOutcome,
  AuditReason,
  ConfidenceBucket,
  ErrorReason,
  GuardrailAssessment,
  GuardrailSignalCode,
  LocalResource,
  PermissionFacts,
  RedactedContext,
  RedactedPolicy,
  ResourceKind,
  ResourceScope,
} from "../domain.js";
import type { PluginConfigThresholds } from "../config.js";
import type { AuditSink } from "../observability/audit.js";
import { FILESYSTEM_PATH_RESOLVER } from "./path-resolver.js";

export type { PermissionPorts };
export type { ReplyDecision };

export type JevEvaluatePort = (
  context: RedactedContext,
  assessment: GuardrailAssessment,
  options: Readonly<{ signal?: AbortSignal }>,
) => Promise<JevEvaluateResult>;

export type EventSubscribePort = (signal: AbortSignal) => AsyncIterable<unknown>;

export interface CoordinatorLimits {
  readonly commandChars: number;
  readonly intentChars: number;
  readonly resources: number;
  readonly resourceChars: number;
}

export interface CoordinatorOptions {
  readonly locationDirectory: string;
  readonly maxConcurrency: number;
  readonly maxQueueSize: number;
  readonly reconcileIntervalMs: number;
  readonly thresholds: PluginConfigThresholds;
  readonly limits: CoordinatorLimits;
  readonly ports: PermissionPorts;
  readonly intentCache: RelevantIntentCache;
  readonly jevEvaluate: JevEvaluatePort;
  readonly audit: AuditSink;
  readonly pathResolver?: PathResolver;
  readonly subscribeEvents?: EventSubscribePort;
}

interface KnownSessionEntry {
  readonly directory: string;
  readonly addedAt: number;
}

interface TombstoneEntry {
  readonly outcome: string;
  readonly expiresAt: number;
}

const KNOWN_SESSION_BOUND = 512;
const KNOWN_SESSION_TTL_MS = 30 * 60 * 1000;
const TOMBSTONE_BOUND = 1024;
const TOMBSTONE_TTL_MS = 5 * 60 * 1000;
const BACKOFF_INITIAL_MS = 100;
const BACKOFF_MAX_MS = 5000;

const KNOWN_ACTION_CATEGORIES: readonly ActionCategory[] = Object.freeze([
  "read",
  "edit",
  "glob",
  "grep",
  "shell",
  "subagent",
  "skill",
  "question",
  "webfetch",
  "websearch",
  "external_directory",
  "execute",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as object | null;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function toBucket(value: number): ConfidenceBucket {
  if (value >= 0.9) return "high";
  if (value >= 0.5) return "medium";
  return "low";
}

/** Map a valid action string to a closed category without skipping. */
export function classifyActionCategory(action: string): ActionCategory {
  const lower = action.toLowerCase();
  for (const known of KNOWN_ACTION_CATEGORIES) {
    if (lower === known) return known;
  }
  if (lower.includes("mcp")) return "mcp";
  if (lower.includes("plugin")) return "plugin";
  return "other";
}

/** Conservative lexical classification; never returns generic/unknown for valid input. */
export function classifyResource(
  value: string,
  actionCategory: ActionCategory,
  locationDirectory: string,
  pathResolver: PathResolver = FILESYSTEM_PATH_RESOLVER,
): LocalResource {
  if (actionCategory === "shell") {
    return Object.freeze({ value, kind: "command" as const, scope: "unknown" as const });
  }
  if (value.includes("://")) {
    return Object.freeze({ value, kind: "url" as const, scope: "external" as const });
  }
  if (
    (actionCategory === "read" ||
      actionCategory === "edit" ||
      actionCategory === "glob" ||
      actionCategory === "grep") &&
    value.length > 0 &&
    !value.includes("://")
  ) {
    const scope = evaluatePathScope(value, actionCategory, locationDirectory, pathResolver);
    return Object.freeze({ value, kind: "path" as const, scope });
  }
  const looksPath =
    value.startsWith("/") ||
    value.startsWith("./") ||
    value.startsWith("../") ||
    value.includes("/") ||
    value.startsWith("~") ||
    /^[A-Za-z]:\//.test(value);
  if (looksPath) {
    const scope = evaluatePathScope(value, actionCategory, locationDirectory, pathResolver);
    return Object.freeze({ value, kind: "path" as const, scope });
  }
  return Object.freeze({ value, kind: "query" as const, scope: "external" as const });
}

function evaluatePathScope(
  value: string,
  actionCategory: ActionCategory,
  locationDirectory: string,
  pathResolver: PathResolver,
): ResourceScope {
  try {
    return classifyResolvedPathScope(value, {
      boundaries: { projectRoot: locationDirectory },
      resolver: pathResolver,
      actionCategory,
    });
  } catch {
    return "unknown";
  }
}

function dedupeSignals(codes: readonly GuardrailSignalCode[]): readonly GuardrailSignalCode[] {
  const seen = new Set<GuardrailSignalCode>();
  for (const code of codes) {
    if (!seen.has(code)) seen.add(code);
  }
  // Deterministic order matching the canonical list.
  const order: readonly GuardrailSignalCode[] = [
    "secret_access",
    "destructive_operation",
    "privilege_change",
    "security_boundary_change",
    "obvious_exfiltration",
    "unparseable_syntax",
    "unknown_scope",
    "unresolved_path",
    "ambiguous_resource",
    "oversize",
    "redaction_incomplete",
    "missing_intent",
    "intent_ambiguous",
    "risk_unclear",
    "high_risk",
    "low_confidence",
    "invalid_answer",
    "queue_overflow",
    "api_unavailable",
  ];
  const result: GuardrailSignalCode[] = [];
  for (const code of order) {
    if (seen.has(code)) result.push(code);
  }
  return Object.freeze(result);
}

function isTruncated(redacted: RedactedContext): boolean {
  const truncation = redacted.truncation;
  if (truncation === undefined) return false;
  return (
    truncation.commands === true ||
    truncation.intent === true ||
    truncation.resources === true ||
    truncation.resource === true
  );
}

function buildRequestMetadata(
  actionCategory: ActionCategory,
  resources: readonly LocalResource[],
  signals: readonly GuardrailSignalCode[],
  flags: Readonly<{
    redactionComplete: boolean;
    intentAvailable: boolean;
    truncated: boolean;
    parseStatus: "parsed" | "unparseable" | "unknown_scope";
  }>,
): AuditMetadata {
  const kindCounts: Record<ResourceKind, number> = {
    path: 0,
    url: 0,
    command: 0,
    query: 0,
    generic: 0,
    unknown: 0,
  };
  const scopeCounts: Record<ResourceScope, number> = {
    project: 0,
    external: 0,
    home: 0,
    system: 0,
    secret: 0,
    protected: 0,
    unknown: 0,
  };
  for (const resource of resources) {
    kindCounts[resource.kind] = Math.min(1_000_000, kindCounts[resource.kind] + 1);
    scopeCounts[resource.scope] = Math.min(1_000_000, scopeCounts[resource.scope] + 1);
  }
  return Object.freeze({
    type: "request" as const,
    action: actionCategory,
    resourceCount: Math.min(1_000_000, resources.length),
    kindCounts: Object.freeze({ ...kindCounts }),
    scopeCounts: Object.freeze({ ...scopeCounts }),
    signals: Object.freeze([...signals]),
    flags: Object.freeze({ ...flags }),
  });
}

function emitAudit(
  audit: AuditSink,
  reason: AuditReason,
  outcome: AuditOutcome,
  metadata?: AuditMetadata,
  error?: ErrorReason,
): void {
  try {
    audit.emit({
      schemaVersion: 1,
      reason,
      outcome,
      ...(error === undefined ? {} : { error }),
      ...(metadata === undefined ? {} : { metadata }),
    });
  } catch {
    // Audit must never break the pipeline.
  }
}

/** Normalize a session.context payload into intent-cache input. */
function normalizeContextMessages(context: unknown): Readonly<{ messages: unknown }> {
  try {
    if (Array.isArray(context)) {
      const mapped: unknown[] = [];
      for (const entry of context.slice(0, 256)) {
        if (!isRecord(entry)) continue;
        const typeValue = entry.type;
        const roleValue = entry.role;
        const role =
          typeof roleValue === "string"
            ? roleValue
            : typeof typeValue === "string"
              ? typeValue
              : undefined;
        const text = entry.text;
        const content = entry.content;
        const id = entry.id;
        const messageID = entry.messageID;
        mapped.push({
          ...(role === undefined ? {} : { role }),
          ...(typeof text === "string" ? { text } : {}),
          ...(content === undefined ? {} : { content }),
          ...(typeof id === "string" ? { id } : {}),
          ...(typeof messageID === "string" ? { messageID } : {}),
        });
      }
      return { messages: mapped };
    }
    if (isRecord(context) && Array.isArray(context.messages)) {
      return normalizeContextMessages(context.messages);
    }
    if (isRecord(context) && Array.isArray(context.data)) {
      return normalizeContextMessages(context.data);
    }
    return { messages: [] };
  } catch {
    return { messages: [] };
  }
}

/**
 * Bounded coordinator for one plugin instance location.
 *
 * All OpenCode narrowing goes through contract/permissions helpers. Tests
 * inject fake ports and a fake Jev evaluator; production wires real context
 * methods and JevClient through plugin.ts.
 */
export class PermissionCoordinator {
  private readonly locationDirectory: string;
  private readonly maxConcurrency: number;
  private readonly maxQueueSize: number;
  private readonly reconcileIntervalMs: number;
  private readonly thresholds: PluginConfigThresholds;
  private readonly limits: CoordinatorLimits;
  private readonly ports: PermissionPorts;
  private readonly intentCache: RelevantIntentCache;
  private readonly jevEvaluate: JevEvaluatePort;
  private readonly audit: AuditSink;
  private readonly pathResolver: PathResolver;
  private readonly subscribeEvents?: EventSubscribePort;

  private readonly knownSessions = new Map<string, KnownSessionEntry>();
  private readonly inFlight = new Map<string, Promise<void>>();
  private readonly tombstones = new Map<string, TombstoneEntry>();
  private readonly sessionChains = new Map<string, Promise<void>>();

  private activeJev = 0;
  private readonly jevWaiters: Array<() => void> = [];

  private disposed = false;
  private readonly abortController = new AbortController();
  private intervalId: ReturnType<typeof setInterval> | undefined;
  private backoffTimer: ReturnType<typeof setTimeout> | undefined;
  private backoffAttempts = 0;
  private eventLoopRunning = false;

  public constructor(options: CoordinatorOptions) {
    this.locationDirectory = normalizeLocationDirectory(options.locationDirectory);
    this.maxConcurrency = options.maxConcurrency;
    this.maxQueueSize = options.maxQueueSize;
    this.reconcileIntervalMs = options.reconcileIntervalMs;
    this.thresholds = options.thresholds;
    this.limits = options.limits;
    this.ports = options.ports;
    this.intentCache = options.intentCache;
    this.jevEvaluate = options.jevEvaluate;
    this.audit = options.audit;
    this.pathResolver = options.pathResolver ?? FILESYSTEM_PATH_RESOLVER;
    if (options.subscribeEvents !== undefined) {
      this.subscribeEvents = options.subscribeEvents;
    }
  }

  public get isDisposed(): boolean {
    return this.disposed;
  }

  public getKnownSessionIDs(): readonly string[] {
    this.pruneKnownSessions(Date.now());
    return Object.freeze([...this.knownSessions.keys()]);
  }

  public getStats(): Readonly<{ knownSessions: number; inFlight: number; tombstones: number }> {
    return Object.freeze({
      knownSessions: this.knownSessions.size,
      inFlight: this.inFlight.size,
      tombstones: this.tombstones.size,
    });
  }

  private pruneKnownSessions(now: number): void {
    for (const [sessionID, entry] of this.knownSessions) {
      if (now - entry.addedAt >= KNOWN_SESSION_TTL_MS) this.knownSessions.delete(sessionID);
    }
  }

  private rememberSession(sessionID: string, directory: string): void {
    if (this.disposed) return;
    if (!isValidID(sessionID)) return;
    this.pruneKnownSessions(Date.now());
    this.knownSessions.delete(sessionID);
    this.knownSessions.set(sessionID, { directory, addedAt: Date.now() });
    while (this.knownSessions.size > KNOWN_SESSION_BOUND) {
      const oldest = this.knownSessions.keys().next().value;
      if (typeof oldest !== "string") break;
      this.knownSessions.delete(oldest);
    }
  }

  private isTombstoned(key: string): boolean {
    const entry = this.tombstones.get(key);
    if (entry === undefined) return false;
    if (Date.now() >= entry.expiresAt) {
      this.tombstones.delete(key);
      return false;
    }
    return true;
  }

  private rememberTombstone(key: string, outcome: string): void {
    if (this.disposed) return;
    this.tombstones.delete(key);
    this.tombstones.set(key, { outcome, expiresAt: Date.now() + TOMBSTONE_TTL_MS });
    while (this.tombstones.size > TOMBSTONE_BOUND) {
      const oldest = this.tombstones.keys().next().value;
      if (typeof oldest !== "string") break;
      this.tombstones.delete(oldest);
    }
  }

  /**
   * Validate and enqueue a permission event quickly without awaiting Jev.
   * Synchronous entry; async work continues in a keyed operation.
   */
  public notifyEvent(event: unknown): void {
    if (this.disposed) return;
    if (this.abortController.signal.aborted) return;
    let identity: { sessionID: string; requestID: string } | undefined;
    try {
      identity = extractPermissionAsked(event);
    } catch {
      return;
    }
    if (identity === undefined) return;
    const { sessionID, requestID } = identity;
    const key = canonicalRequestKey(this.locationDirectory, sessionID, requestID);
    if (this.isTombstoned(key)) return;
    if (this.inFlight.has(key)) return;
    if (this.inFlight.size >= this.maxQueueSize) {
      emitAudit(
        this.audit,
        "request_manual",
        "manual",
        buildRequestMetadata("unknown", [], ["queue_overflow"], {
          redactionComplete: true,
          intentAvailable: false,
          truncated: false,
          parseStatus: "parsed",
        }),
      );
      this.rememberTombstone(key, "queue_overflow");
      return;
    }
    const pipeline = this.runPipeline(sessionID, requestID, key, "event").catch(() => {});
    this.inFlight.set(key, pipeline);
    void pipeline.finally(() => {
      this.inFlight.delete(key);
    });
  }

  /** Handle a prompt-hook input: verify location, cache redacted intent, learn session. */
  public async notifyPrompt(input: unknown): Promise<void> {
    if (this.disposed) return;
    let sessionID: string | undefined;
    let promptText: string | undefined;
    try {
      sessionID = extractPromptSession(input);
      promptText = extractPromptText(input);
    } catch {
      return;
    }
    if (sessionID === undefined || promptText === undefined) return;
    let ownership: Awaited<ReturnType<typeof getSessionDirectory>>;
    try {
      ownership = await getSessionDirectory(this.ports, sessionID, this.locationDirectory);
    } catch {
      return;
    }
    if (this.disposed) return;
    if (ownership.status !== "in_scope") return;
    try {
      this.intentCache.update(sessionID, promptText);
    } catch {
      // Never break the hook on cache failure.
    }
    this.rememberSession(sessionID, ownership.directory);
    // Best-effort catch-up for the newly learned session without blocking the hook.
    void this.reconcileSession(sessionID).catch(() => {});
  }

  /** Reconcile one known session through the same keyed path. */
  public async reconcileSession(sessionID: string): Promise<void> {
    if (this.disposed) return;
    if (!isValidID(sessionID)) return;
    if (!this.knownSessions.has(sessionID)) return;
    let pending: readonly NormalizedPermissionRequest[];
    try {
      pending = await listPendingRequests(this.ports, sessionID);
    } catch {
      return;
    }
    if (this.disposed) return;
    for (const request of pending) {
      if (this.disposed) return;
      if (request.sessionID !== sessionID) continue;
      const key = canonicalRequestKey(this.locationDirectory, request.sessionID, request.requestID);
      if (this.isTombstoned(key)) continue;
      if (this.inFlight.has(key)) continue;
      if (this.inFlight.size >= this.maxQueueSize) {
        emitAudit(
          this.audit,
          "request_manual",
          "manual",
          buildRequestMetadata("unknown", [], ["queue_overflow"], {
            redactionComplete: true,
            intentAvailable: false,
            truncated: false,
            parseStatus: "parsed",
          }),
        );
        this.rememberTombstone(key, "queue_overflow");
        continue;
      }
      const pipeline = this.runPipeline(request.sessionID, request.requestID, key, "reconciliation").catch(
        () => {},
      );
      this.inFlight.set(key, pipeline);
      // Await each to keep reconciliation bounded and deterministic in tests.
      try {
        await pipeline;
      } catch {
        // Pipeline never throws; defensive.
      } finally {
        this.inFlight.delete(key);
      }
    }
  }

  /** Best-effort reconciliation for every known in-scope session. */
  public async reconcileAll(): Promise<void> {
    if (this.disposed) return;
    this.pruneKnownSessions(Date.now());
    const sessions = [...this.knownSessions.keys()];
    for (const sessionID of sessions) {
      if (this.disposed) return;
      try {
        await this.reconcileSession(sessionID);
      } catch {
        // Never break interval/reconnect on one session.
      }
    }
  }

  /** Start the public event consumer with bounded reconnect. */
  public startEventLoop(): void {
    if (this.disposed) return;
    if (this.subscribeEvents === undefined) return;
    if (this.eventLoopRunning) return;
    this.eventLoopRunning = true;
    emitAudit(
      this.audit,
      "stream_started",
      "skipped",
      Object.freeze({ type: "lifecycle" as const, event: "stream_started" as const }),
    );
    void this.runEventLoop().catch(() => {});
  }

  private async runEventLoop(): Promise<void> {
    const subscribe = this.subscribeEvents;
    if (subscribe === undefined) {
      this.eventLoopRunning = false;
      return;
    }
    while (!this.disposed && !this.abortController.signal.aborted) {
      try {
        const iterable = subscribe(this.abortController.signal);
        for await (const event of iterable) {
          if (this.disposed || this.abortController.signal.aborted) break;
          this.backoffAttempts = 0;
          try {
            this.notifyEvent(event);
          } catch {
            // Never break the stream on one event.
          }
        }
        if (this.disposed || this.abortController.signal.aborted) break;
        emitAudit(
          this.audit,
          "stream_error",
          "skipped",
          Object.freeze({ type: "lifecycle" as const, event: "stream_error" as const }),
          "unknown",
        );
        try {
          await this.reconcileAll();
        } catch {
          // Best effort.
        }
        await this.backoffDelay();
      } catch {
        if (this.disposed || this.abortController.signal.aborted) break;
        emitAudit(
          this.audit,
          "stream_error",
          "skipped",
          Object.freeze({ type: "lifecycle" as const, event: "stream_error" as const }),
          "unknown",
        );
        try {
          await this.reconcileAll();
        } catch {
          // Best effort.
        }
        await this.backoffDelay();
      }
    }
    this.eventLoopRunning = false;
  }

  private backoffDelay(): Promise<void> {
    if (this.disposed) return Promise.resolve();
    const delayMs = Math.min(
      BACKOFF_INITIAL_MS * 2 ** Math.min(this.backoffAttempts, 6),
      BACKOFF_MAX_MS,
    );
    this.backoffAttempts += 1;
    return new Promise<void>((resolve) => {
      if (this.disposed) {
        resolve();
        return;
      }
      this.backoffTimer = setTimeout(() => {
        this.backoffTimer = undefined;
        resolve();
      }, delayMs);
    });
  }

  /** Start periodic reconciliation for known sessions only. */
  public startInterval(): void {
    if (this.disposed) return;
    if (this.intervalId !== undefined) return;
    try {
      this.intervalId = setInterval(() => {
        void this.reconcileAll().catch(() => {});
      }, this.reconcileIntervalMs);
    } catch {
      this.intervalId = undefined;
    }
  }

  /** Subscribe, then enable interval work. Callers register prompt hooks first. */
  public start(): void {
    if (this.disposed) return;
    this.startEventLoop();
    this.startInterval();
    void this.reconcileAll().catch(() => {});
  }

  private async acquireJevSlot(): Promise<boolean> {
    if (this.disposed) return false;
    if (this.activeJev < this.maxConcurrency) {
      this.activeJev += 1;
      return true;
    }
    await new Promise<void>((resolve) => {
      this.jevWaiters.push(resolve);
    });
    if (this.disposed) return false;
    this.activeJev += 1;
    return true;
  }

  private releaseJevSlot(): void {
    this.activeJev = Math.max(0, this.activeJev - 1);
    const next = this.jevWaiters.shift();
    if (next !== undefined) {
      try {
        next();
      } catch {
        // Never break on waiter failure.
      }
    }
  }

  private async withSessionLock<T>(sessionID: string, task: () => Promise<T>): Promise<T> {
    const previous = this.sessionChains.get(sessionID) ?? Promise.resolve();
    let releaseTail!: () => void;
    const tail = new Promise<void>((resolve) => {
      releaseTail = resolve;
    });
    this.sessionChains.set(sessionID, tail);
    try {
      await previous.catch(() => {});
    } catch {
      // Previous chain failures never block.
    }
    if (this.disposed) {
      releaseTail();
      if (this.sessionChains.get(sessionID) === tail) this.sessionChains.delete(sessionID);
      return previous.then(task).catch(task) as unknown as Promise<T>;
    }
    try {
      return await task();
    } finally {
      try {
        releaseTail();
      } catch {
        // Never throw from lock release.
      }
      if (this.sessionChains.get(sessionID) === tail) this.sessionChains.delete(sessionID);
    }
  }

  private async runPipeline(
    sessionID: string,
    requestID: string,
    key: string,
    source: "event" | "reconciliation",
  ): Promise<void> {
    void source;
    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }
    // 1. Verify ownership; never assume event ownership.
    let ownership: Awaited<ReturnType<typeof getSessionDirectory>>;
    try {
      ownership = await getSessionDirectory(this.ports, sessionID, this.locationDirectory);
    } catch {
      this.rememberTombstone(key, "transport");
      return;
    }
    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }
    if (ownership.status === "out_of_scope") {
      emitAudit(this.audit, "request_out_of_scope", "skipped");
      this.rememberTombstone(key, "out_of_scope");
      return;
    }
    if (ownership.status === "external") {
      emitAudit(this.audit, "request_external", "external", undefined, "opencode_not_found");
      this.rememberTombstone(key, "external");
      return;
    }
    if (ownership.status !== "in_scope") {
      emitAudit(this.audit, "request_manual", "manual", undefined, "opencode_transport");
      this.rememberTombstone(key, "transport");
      return;
    }
    this.rememberSession(sessionID, ownership.directory);

    // 2. Authoritative get wins over the event payload.
    let authoritative: Awaited<ReturnType<typeof getAuthoritativeRequest>>;
    try {
      authoritative = await getAuthoritativeRequest(this.ports, sessionID, requestID);
    } catch {
      this.rememberTombstone(key, "transport");
      return;
    }
    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }
    if (authoritative.status === "external") {
      emitAudit(this.audit, "request_external", "external", undefined, "opencode_not_found");
      this.rememberTombstone(key, "external");
      return;
    }
    if (authoritative.status === "malformed") {
      emitAudit(this.audit, "request_manual", "manual", undefined, "opencode_invalid_response");
      this.rememberTombstone(key, "malformed");
      return;
    }
    if (authoritative.status !== "pending") {
      emitAudit(this.audit, "request_manual", "manual", undefined, "opencode_transport");
      this.rememberTombstone(key, "transport");
      return;
    }
    const validated: NormalizedPermissionRequest = authoritative.request;

    emitAudit(
      this.audit,
      "request_seen",
      "manual",
      buildRequestMetadata(classifyActionCategory(validated.action), [], [], {
        redactionComplete: true,
        intentAvailable: false,
        truncated: false,
        parseStatus: "parsed",
      }),
    );

    // 3. Relevant intent: bounded cache first, local context fallback second.
    let intentText: string | undefined;
    let intentAvailable = false;
    try {
      const cached = this.intentCache.get(sessionID);
      if (cached !== undefined && typeof cached.text === "string" && cached.text.length > 0) {
        intentText = cached.text;
        intentAvailable = true;
      }
    } catch {
      intentText = undefined;
    }
    if (intentText === undefined) {
      try {
        const rawContext = await fetchSessionContext(this.ports, sessionID);
        if (this.disposed) {
          this.rememberTombstone(key, "cleanup");
          return;
        }
        if (rawContext !== undefined) {
          const normalized = normalizeContextMessages(rawContext);
          const selected = selectRelevantIntent(
            normalized,
            validated.source === undefined
              ? undefined
              : { messageID: validated.source.messageID, sourceID: validated.source.sourceID },
            { maxChars: this.limits.intentChars },
          );
          if (selected !== undefined) {
            intentText = selected.text;
            intentAvailable = true;
          }
        }
      } catch {
        intentText = undefined;
      }
    }

    // 4. Local fact model with conservative classification.
    const actionCategory = classifyActionCategory(validated.action);
    const classified: LocalResource[] = [];
    for (const value of validated.resources) {
      try {
        classified.push(classifyResource(value, actionCategory, this.locationDirectory, this.pathResolver));
      } catch {
        // Skip unclassifiable values; guardrails will see fewer resources and
        // redaction will mark incomplete below.
      }
    }
    const facts: PermissionFacts = Object.freeze({
      key: Object.freeze({
        locationDirectory: this.locationDirectory,
        sessionID,
        requestID,
      }),
      location: Object.freeze({ directory: this.locationDirectory }),
      action: validated.action,
      actionCategory,
      resources: Object.freeze([...classified]),
      ...(validated.source === undefined
        ? {}
        : {
            source: Object.freeze({
              messageID: validated.source.messageID,
              sourceID: validated.source.sourceID,
            }),
          }),
      ...(intentText === undefined
        ? {}
        : {
            intent: Object.freeze({
              text: intentText,
              redacted: true as const,
              truncated: false,
              redactionComplete: true,
            }),
          }),
    });

    // 5. Deterministic guardrails (pure, no I/O).
    let assessment: GuardrailAssessment;
    try {
      assessment = evaluateGuardrails(facts, undefined, this.pathResolver);
    } catch {
      emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
      this.rememberTombstone(key, "manual");
      return;
    }

    // Mandatory local policy is final. Reject before building any hosted
    // context so this path cannot depend on redaction or Jev availability.
    if (assessment.hardDeny) {
      emitAudit(
        this.audit,
        "request_seen",
        "manual",
        buildRequestMetadata(actionCategory, classified, assessment.signals, {
          redactionComplete: true,
          intentAvailable,
          truncated: false,
          parseStatus: assessment.parseStatus,
        }),
      );
      if (this.disposed) {
        this.rememberTombstone(key, "cleanup");
        return;
      }
      await this.replyForDecision(sessionID, requestID, key, "reject", classified, actionCategory);
      return;
    }

    // 6. Allowlisted redacted projection; only this crosses to Jev.
    const policy: RedactedPolicy = Object.freeze({
      version: GUARDRAIL_POLICY_VERSION,
      hardDenyCodes: assessment.hardDenyCodes,
      unknown: "manual_review" as const,
      maximumGrant: "once" as const,
    });
    let redacted: RedactedContext;
    try {
      redacted = buildRedactedContext(
        { ...facts, signals: assessment.signals },
        intentText,
        policy,
        {
          limits: {
            commandChars: this.limits.commandChars,
            intentChars: this.limits.intentChars,
            resources: this.limits.resources,
            resourceChars: this.limits.resourceChars,
          },
          projectRoot: this.locationDirectory,
          signals: assessment.signals,
        },
      );
    } catch {
      emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
      this.rememberTombstone(key, "manual");
      return;
    }

    // Privacy/uncertainty signals that block auto-allow but still permit deny.
    const extraSignals: GuardrailSignalCode[] = [];
    if (!redacted.redactionComplete) extraSignals.push("redaction_incomplete");
    if (redacted.eligibleForAutoAllow === false && redacted.redactionComplete) {
      // Truncation or unknown scope already surfaced via signals/flags still
      // blocks allow; add an explicit manual signal when nothing else does.
      let hasBlocking = false;
      for (const signal of assessment.signals) {
        if (
          signal === "unparseable_syntax" ||
          signal === "unknown_scope" ||
          signal === "unresolved_path" ||
          signal === "ambiguous_resource" ||
          signal === "oversize" ||
          signal === "redaction_incomplete" ||
          signal === "missing_intent" ||
          signal === "intent_ambiguous"
        ) {
          hasBlocking = true;
          break;
        }
      }
      if (!hasBlocking && !intentAvailable) extraSignals.push("missing_intent");
      else if (!hasBlocking) extraSignals.push("redaction_incomplete");
    }
    if (!intentAvailable && !extraSignals.includes("missing_intent")) {
      extraSignals.push("missing_intent");
    }
    let effectiveAssessment: GuardrailAssessment = assessment;
    if (extraSignals.length > 0) {
      const merged = dedupeSignals([...assessment.signals, ...extraSignals]);
      effectiveAssessment = Object.freeze({
        signals: merged,
        parseStatus: assessment.parseStatus,
        hardDeny: assessment.hardDeny,
        policyVersion: assessment.policyVersion,
        hardDenyCodes: assessment.hardDenyCodes,
        eligibleForAutoAllow: false,
      });
    }

    emitAudit(
      this.audit,
      "request_seen",
      "manual",
      buildRequestMetadata(actionCategory, classified, effectiveAssessment.signals, {
        redactionComplete: redacted.redactionComplete,
        intentAvailable,
        truncated: isTruncated(redacted),
        parseStatus: effectiveAssessment.parseStatus,
      }),
    );

    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }

    // 7. Bounded Jev evaluation, at-least-once per pending request.
    const acquired = await this.acquireJevSlot();
    if (!acquired || this.disposed) {
      if (acquired) this.releaseJevSlot();
      emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
      this.rememberTombstone(key, "cleanup");
      return;
    }
    emitAudit(this.audit, "jev_started", "skipped");
    let jevResult: JevEvaluateResult;
    try {
      jevResult = await this.jevEvaluate(redacted, effectiveAssessment, {
        signal: this.abortController.signal,
      });
    } catch {
      this.releaseJevSlot();
      emitAudit(this.audit, "jev_failed", "manual", undefined, "unknown");
      emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
      this.rememberTombstone(key, "manual");
      return;
    }
    this.releaseJevSlot();

    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }

    if (jevResult.ok !== true) {
      const category = jevResult.error.category;
      let manualError: ErrorReason = "unknown";
      if (category === "missing_api_key") manualError = "missing_api_key";
      else if (category === "api_timeout" || category === "api_aborted") manualError = "api_timeout";
      else if (
        category === "api_authentication" ||
        category === "api_rate_limited" ||
        category === "api_server" ||
        category === "api_transport" ||
        category === "api_malformed_response"
      ) {
        manualError = "unknown";
      }
      emitAudit(
        this.audit,
        "jev_failed",
        "manual",
        Object.freeze({ type: "error" as const, category }),
        category,
      );
      void manualError;
      emitAudit(this.audit, "request_manual", "manual", undefined, category);
      this.rememberTombstone(key, "manual");
      return;
    }

    // 8. Pure decision core.
    let decision: ReturnType<typeof decide>;
    try {
      decision = decide(effectiveAssessment, jevResult.value, this.thresholds);
    } catch {
      emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
      this.rememberTombstone(key, "manual");
      return;
    }

    try {
      const label = jevResult.value.final.choice;
      const confidence = toBucket(jevResult.value.final.confidence);
      const selected = jevResult.value.final.probabilities[jevResult.value.final.choice];
      const probability = toBucket(typeof selected === "number" ? selected : 0);
      emitAudit(this.audit, "jev_completed", "manual", {
        type: "jev",
        modelVersion: jevResult.value.modelVersion,
        label,
        confidence,
        probability,
        inputTokens: jevResult.value.usage.inputTokens,
        outputTokens: jevResult.value.usage.outputTokens,
      });
    } catch {
      // Audit failure never blocks the decision.
    }

    const reply = mapAutomaticReply(decision);
    if (reply === undefined) {
      emitAudit(
        this.audit,
        "request_manual",
        "manual",
        buildRequestMetadata(actionCategory, classified, effectiveAssessment.signals, {
          redactionComplete: redacted.redactionComplete,
          intentAvailable,
          truncated: isTruncated(redacted),
          parseStatus: effectiveAssessment.parseStatus,
        }),
      );
      this.rememberTombstone(key, "manual");
      return;
    }

    await this.replyForDecision(sessionID, requestID, key, reply, classified, actionCategory);
  }

  private async replyForDecision(
    sessionID: string,
    requestID: string,
    key: string,
    decision: ReplyDecision,
    classified: readonly LocalResource[],
    actionCategory: ActionCategory,
  ): Promise<void> {
    if (this.disposed) {
      this.rememberTombstone(key, "cleanup");
      return;
    }
    const outcome: AuditOutcome = decision === "once" ? "once" : "reject";
    const reason: AuditReason = decision === "once" ? "request_allow_once" : "request_reject";
    await this.withSessionLock(sessionID, async () => {
      if (this.disposed) {
        emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
        return;
      }
      emitAudit(this.audit, "reply_attempted", outcome);
      let fresh: Awaited<ReturnType<typeof preReplyCheck>>;
      try {
        fresh = await preReplyCheck(this.ports, sessionID, requestID);
      } catch {
        emitAudit(this.audit, "reply_failed", "manual", undefined, "opencode_transport");
        return;
      }
      if (this.disposed) {
        emitAudit(this.audit, "request_manual", "manual", undefined, "unknown");
        return;
      }
      if (fresh.status !== "pending") {
        if (fresh.status === "external") {
          emitAudit(this.audit, "request_external", "external", undefined, "opencode_not_found");
        } else {
          emitAudit(this.audit, "request_manual", "manual", undefined, "opencode_transport");
        }
        return;
      }
      let result: Awaited<ReturnType<typeof replyWithRecovery>>;
      try {
        result = await replyWithRecovery(this.ports, sessionID, requestID, decision);
      } catch {
        emitAudit(this.audit, "reply_failed", "manual", undefined, "opencode_transport");
        return;
      }
      if (this.disposed) {
        // A reply may already be in flight; record but do not emit further transitions.
        return;
      }
      if (result.status === "replied") {
        emitAudit(this.audit, "reply_succeeded", outcome);
        emitAudit(
          this.audit,
          reason,
          outcome,
          buildRequestMetadata(actionCategory, classified, [], {
            redactionComplete: true,
            intentAvailable: true,
            truncated: false,
            parseStatus: "parsed",
          }),
        );
      } else if (result.status === "external") {
        emitAudit(this.audit, "request_external", "external", undefined, "opencode_not_found");
      } else {
        emitAudit(this.audit, "reply_failed", "manual", undefined, "opencode_transport");
        emitAudit(this.audit, "request_manual", "manual", undefined, "opencode_transport");
      }
    });
    this.rememberTombstone(key, decision === "once" ? "once" : "reject");
  }

  /** Synchronously stop new work, abort, clear timers and in-memory data. */
  public dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    try {
      this.abortController.abort();
    } catch {
      // Never throw from cleanup.
    }
    if (this.intervalId !== undefined) {
      try {
        clearInterval(this.intervalId);
      } catch {
        // Ignore.
      }
      this.intervalId = undefined;
    }
    if (this.backoffTimer !== undefined) {
      try {
        clearTimeout(this.backoffTimer);
      } catch {
        // Ignore.
      }
      this.backoffTimer = undefined;
    }
    // Release any Jev waiters so pending pipelines can observe disposal.
    while (this.jevWaiters.length > 0) {
      const waiter = this.jevWaiters.shift();
      if (waiter === undefined) break;
      try {
        waiter();
      } catch {
        // Ignore.
      }
    }
    this.activeJev = 0;
    this.knownSessions.clear();
    this.tombstones.clear();
    // In-flight promises observe `disposed` before replying; drop references.
    this.inFlight.clear();
    this.sessionChains.clear();
    try {
      emitAudit(
        this.audit,
        "cleanup",
        "skipped",
        Object.freeze({ type: "lifecycle" as const, event: "cleanup" as const }),
      );
    } catch {
      // Never throw from cleanup.
    }
  }
}

export type CoordinatorStats = ReturnType<PermissionCoordinator["getStats"]>;

/** Validate that a value can serve as a coordinator port without throwing. */
export function isCoordinatorPorts(value: unknown): value is PermissionPorts {
  if (!isRecord(value)) return false;
  return (
    typeof value.sessionGet === "function" &&
    typeof value.permissionList === "function" &&
    typeof value.permissionGet === "function" &&
    typeof value.permissionReply === "function"
  );
}

export { validatePermissionRequest };
