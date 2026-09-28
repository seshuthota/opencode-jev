/**
 * Runtime-validated, sanitized audit records.
 *
 * This boundary validates a closed union before constructing a fresh object.
 * It never serializes an input object, calls `JSON.stringify` on untrusted
 * data, or attempts to redact a raw value and then log it.
 */

import type {
  ActionCategory,
  AuditEvent,
  AuditMetadata,
  AuditOutcome,
  AuditReason,
  ConfidenceBucket,
  ErrorReason,
  GuardrailSignalCode,
  ParseStatus,
  PolicyDecisionLabel,
  ResourceKindCounts,
  ResourceScopeCounts,
} from "../domain.js";
import { isErrorReason } from "./errors.js";

export const AUDIT_REASONS: readonly AuditReason[] = Object.freeze([
  "config_invalid",
  "request_seen",
  "request_out_of_scope",
  "request_external",
  "request_manual",
  "request_allow_once",
  "request_reject",
  "jev_started",
  "jev_completed",
  "jev_failed",
  "reply_attempted",
  "reply_succeeded",
  "reply_failed",
  "stream_started",
  "stream_error",
  "cleanup",
]);
export const AUDIT_OUTCOMES: readonly AuditOutcome[] = Object.freeze([
  "once",
  "reject",
  "manual",
  "external",
  "skipped",
]);

const AUDIT_REASON_SET: ReadonlySet<string> = new Set(AUDIT_REASONS);
const AUDIT_OUTCOME_SET: ReadonlySet<string> = new Set(AUDIT_OUTCOMES);
const ACTION_CATEGORIES: ReadonlySet<string> = new Set([
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
  "plugin",
  "mcp",
  "other",
  "unknown",
]);
const SIGNAL_CODES: ReadonlySet<string> = new Set([
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
]);
const PARSE_STATUSES: ReadonlySet<string> = new Set(["parsed", "unparseable", "unknown_scope"]);
const POLICY_LABELS: ReadonlySet<string> = new Set(["allow_once", "deny", "manual_review"]);
const CONFIDENCE_BUCKETS: ReadonlySet<string> = new Set(["low", "medium", "high"]);
const LIFECYCLE_EVENTS: ReadonlySet<string> = new Set(["stream_started", "stream_error", "cleanup"]);

const RESOURCE_KINDS = ["path", "url", "command", "query", "generic", "unknown"] as const;
const RESOURCE_SCOPES = ["project", "external", "home", "system", "secret", "protected", "unknown"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as object | null;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Reflect.ownKeys(value).every((key) => typeof key === "string" && allowed.includes(key));
}

function isSafeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000;
}

function isSafeModelVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 64 &&
    /^[A-Za-z0-9._:-]+$/u.test(value) &&
    !/(?:secret|token|password|cookie|authorization|api[-_]?key|sentinel|private)/iu.test(value)
  );
}

function sanitizeKindCounts(input: unknown): ResourceKindCounts | undefined {
  if (!isRecord(input) || !hasOnlyKeys(input, RESOURCE_KINDS)) return undefined;
  const path = input.path;
  const url = input.url;
  const command = input.command;
  const query = input.query;
  const generic = input.generic;
  const unknown = input.unknown;
  if (
    !isSafeCount(path) ||
    !isSafeCount(url) ||
    !isSafeCount(command) ||
    !isSafeCount(query) ||
    !isSafeCount(generic) ||
    !isSafeCount(unknown)
  ) {
    return undefined;
  }
  return Object.freeze({ path, url, command, query, generic, unknown });
}

function sanitizeScopeCounts(input: unknown): ResourceScopeCounts | undefined {
  if (!isRecord(input) || !hasOnlyKeys(input, RESOURCE_SCOPES)) return undefined;
  const project = input.project;
  const external = input.external;
  const home = input.home;
  const system = input.system;
  const secret = input.secret;
  const protectedValue = input.protected;
  const unknown = input.unknown;
  if (
    !isSafeCount(project) ||
    !isSafeCount(external) ||
    !isSafeCount(home) ||
    !isSafeCount(system) ||
    !isSafeCount(secret) ||
    !isSafeCount(protectedValue) ||
    !isSafeCount(unknown)
  ) {
    return undefined;
  }
  return Object.freeze({ project, external, home, system, secret, protected: protectedValue, unknown });
}

function sanitizeSignals(input: unknown): readonly GuardrailSignalCode[] | undefined {
  if (!Array.isArray(input) || input.length > 32) return undefined;
  const result: GuardrailSignalCode[] = [];
  for (const value of input) {
    if (typeof value !== "string" || !SIGNAL_CODES.has(value)) return undefined;
    if (!result.includes(value as GuardrailSignalCode)) result.push(value as GuardrailSignalCode);
  }
  return Object.freeze(result);
}

interface SanitizedAuditFlags extends Readonly<{
  redactionComplete: boolean;
  intentAvailable: boolean;
  truncated: boolean;
  parseStatus: ParseStatus;
}> {}

function sanitizeFlags(input: unknown): SanitizedAuditFlags | undefined {
  if (!isRecord(input) || !hasOnlyKeys(input, ["redactionComplete", "intentAvailable", "truncated", "parseStatus"])) {
    return undefined;
  }
  const redactionComplete = input.redactionComplete;
  const intentAvailable = input.intentAvailable;
  const truncated = input.truncated;
  const parseStatus = input.parseStatus;
  if (
    typeof redactionComplete !== "boolean" ||
    typeof intentAvailable !== "boolean" ||
    typeof truncated !== "boolean" ||
    typeof parseStatus !== "string" ||
    !PARSE_STATUSES.has(parseStatus)
  ) {
    return undefined;
  }
  return Object.freeze({ redactionComplete, intentAvailable, truncated, parseStatus: parseStatus as ParseStatus });
}

function sanitizeRequestMetadata(input: Record<string, unknown>): AuditMetadata | undefined {
  if (!hasOnlyKeys(input, ["type", "action", "resourceCount", "kindCounts", "scopeCounts", "signals", "flags"])) {
    return undefined;
  }
  if (input.type !== "request" || typeof input.action !== "string" || !ACTION_CATEGORIES.has(input.action)) {
    return undefined;
  }
  if (!isSafeCount(input.resourceCount)) return undefined;
  const kindCounts = sanitizeKindCounts(input.kindCounts);
  const scopeCounts = sanitizeScopeCounts(input.scopeCounts);
  const signals = sanitizeSignals(input.signals);
  const flags = sanitizeFlags(input.flags);
  if (kindCounts === undefined || scopeCounts === undefined || signals === undefined || flags === undefined) {
    return undefined;
  }
  return Object.freeze({
    type: "request",
    action: input.action as ActionCategory,
    resourceCount: input.resourceCount,
    kindCounts,
    scopeCounts,
    signals,
    flags,
  });
}

function sanitizeJevMetadata(input: Record<string, unknown>): AuditMetadata | undefined {
  if (!hasOnlyKeys(input, ["type", "modelVersion", "label", "confidence", "probability", "inputTokens", "outputTokens"])) {
    return undefined;
  }
  if (
    input.type !== "jev" ||
    !isSafeModelVersion(input.modelVersion) ||
    typeof input.label !== "string" ||
    !POLICY_LABELS.has(input.label) ||
    typeof input.confidence !== "string" ||
    !CONFIDENCE_BUCKETS.has(input.confidence) ||
    typeof input.probability !== "string" ||
    !CONFIDENCE_BUCKETS.has(input.probability)
  ) {
    return undefined;
  }
  if (hasOwn(input, "inputTokens") && !isSafeCount(input.inputTokens)) return undefined;
  if (hasOwn(input, "outputTokens") && !isSafeCount(input.outputTokens)) return undefined;
  return Object.freeze({
    type: "jev",
    modelVersion: input.modelVersion,
    label: input.label as PolicyDecisionLabel,
    confidence: input.confidence as ConfidenceBucket,
    probability: input.probability as ConfidenceBucket,
    ...(input.inputTokens === undefined ? {} : { inputTokens: input.inputTokens as number }),
    ...(input.outputTokens === undefined ? {} : { outputTokens: input.outputTokens as number }),
  });
}

function sanitizeErrorMetadata(input: Record<string, unknown>): AuditMetadata | undefined {
  if (!hasOnlyKeys(input, ["type", "category", "status"])) return undefined;
  if (input.type !== "error" || !isErrorReason(input.category)) return undefined;
  if (hasOwn(input, "status") && (!isSafeCount(input.status) || input.status < 100 || input.status > 599)) {
    return undefined;
  }
  return Object.freeze({
    type: "error",
    category: input.category,
    ...(input.status === undefined ? {} : { status: input.status as number }),
  });
}

function sanitizeLifecycleMetadata(input: Record<string, unknown>): AuditMetadata | undefined {
  if (!hasOnlyKeys(input, ["type", "event"])) return undefined;
  if (input.type !== "lifecycle" || typeof input.event !== "string" || !LIFECYCLE_EVENTS.has(input.event)) {
    return undefined;
  }
  return Object.freeze({ type: "lifecycle", event: input.event as "stream_started" | "stream_error" | "cleanup" });
}

/** Validate and copy one closed metadata variant. */
function sanitizeAuditMetadataUnsafe(input: unknown): AuditMetadata | undefined {
  if (!isRecord(input) || typeof input.type !== "string") return undefined;
  switch (input.type) {
    case "request":
      return sanitizeRequestMetadata(input);
    case "jev":
      return sanitizeJevMetadata(input);
    case "error":
      return sanitizeErrorMetadata(input);
    case "lifecycle":
      return sanitizeLifecycleMetadata(input);
    default:
      return undefined;
  }
}

export function sanitizeAuditMetadata(input: unknown): AuditMetadata | undefined {
  try {
    return sanitizeAuditMetadataUnsafe(input);
  } catch {
    return undefined;
  }
}

function isAuditReason(value: unknown): value is AuditReason {
  return typeof value === "string" && AUDIT_REASON_SET.has(value);
}

function isAuditOutcome(value: unknown): value is AuditOutcome {
  return typeof value === "string" && AUDIT_OUTCOME_SET.has(value);
}

/** Validate and copy a complete audit event, or reject it without logging. */
function sanitizeAuditEventUnsafe(input: unknown): AuditEvent | undefined {
  if (!isRecord(input)) return undefined;
  if (!hasOnlyKeys(input, ["schemaVersion", "reason", "outcome", "error", "metadata"])) return undefined;
  if (input.schemaVersion !== 1 || !isAuditReason(input.reason) || !isAuditOutcome(input.outcome)) return undefined;

  let error: ErrorReason | undefined;
  if (hasOwn(input, "error")) {
    if (!isErrorReason(input.error)) return undefined;
    error = input.error;
  }
  let metadata: AuditMetadata | undefined;
  if (hasOwn(input, "metadata")) {
    metadata = sanitizeAuditMetadata(input.metadata);
    if (metadata === undefined) return undefined;
  }
  return Object.freeze({
    schemaVersion: 1,
    reason: input.reason,
    outcome: input.outcome,
    ...(error === undefined ? {} : { error }),
    ...(metadata === undefined ? {} : { metadata }),
  });
}

export function sanitizeAuditEvent(input: unknown): AuditEvent | undefined {
  try {
    return sanitizeAuditEventUnsafe(input);
  } catch {
    return undefined;
  }
}

export const createAuditRecord = sanitizeAuditEvent;
export const validateAuditEvent = (input: unknown): input is AuditEvent => sanitizeAuditEvent(input) !== undefined;

export interface AuditSink {
  emit(input: unknown): boolean;
}

/** Create a sink that can only forward validated, freshly copied records. */
export function createAuditSink(sink: (event: AuditEvent) => void): AuditSink {
  if (typeof sink !== "function") throw new TypeError("Invalid audit sink");
  return Object.freeze({
    emit(input: unknown): boolean {
      const event = sanitizeAuditEvent(input);
      if (event === undefined) return false;
      sink(event);
      return true;
    },
  });
}

export function createAuditEvent(
  reason: AuditReason,
  outcome: AuditOutcome,
  metadata?: AuditMetadata,
  error?: ErrorReason,
): AuditEvent | undefined {
  return sanitizeAuditEvent({
    schemaVersion: 1,
    reason,
    outcome,
    ...(metadata === undefined ? {} : { metadata }),
    ...(error === undefined ? {} : { error }),
  });
}
