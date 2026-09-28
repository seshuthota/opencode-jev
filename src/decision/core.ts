/**
 * Pure decision core (Slice 4).
 *
 * Conservative composition of local hard policy, Jev answers, and
 * confidence/probability thresholds. Synchronous, side-effect free, with no
 * I/O, timers, logging, network, filesystem, OpenCode, or TypeSafe imports.
 * Only shared domain/config types are used. All inputs are runtime-validated;
 * validation failure is manual unless a local hard-deny was previously
 * detected, which remains an irrevocable reject. Returned decisions are frozen
 * and contain only closed reason codes and confidence buckets; raw inputs are
 * never copied, logged, or persisted.
 *
 * Evaluation order (plan section 7):
 *  1. validation failure -> MANUAL, except hard-deny remains REJECT;
 *  2. mandatory local guardrail hit -> immediate irrevocable REJECT;
 *  3. unknown final label -> MANUAL;
 *  4. manual_review -> MANUAL at any confidence;
 *  5. deny -> REJECT only when final confidence, selected probability, valid
 *     distribution, and valid model identity meet deny thresholds;
 *  6. allow_once -> only when no hard/uncertain parser signal, relevant intent
 *     exists with supported alignment at the auxiliary floor, risk is routine
 *     at routine thresholds or elevated at stricter elevated thresholds (never
 *     high/unclear), final allow meets confidence/probability thresholds, and
 *     all distributions validate; otherwise MANUAL.
 */

import type {
  AutomaticReply,
  ConfidenceBucket,
  CoreDecision,
  CoreDecisionKind,
  CoreDecisionReason,
  GuardrailSignalCode,
  HardDenySignalCode,
  IntentAlignment,
  ParseStatus,
  PolicyDecisionLabel,
  RiskClass,
} from "../domain.js";
import type { PluginConfigThresholds } from "../config.js";

/** Documented tolerance for probability-distribution sums. */
const PROBABILITY_SUM_TOLERANCE = 0.01 as const;

const HARD_DENY_CODES: readonly HardDenySignalCode[] = Object.freeze([
  "secret_access",
  "destructive_operation",
  "privilege_change",
  "security_boundary_change",
  "obvious_exfiltration",
]);

const KNOWN_SIGNAL_CODES: readonly GuardrailSignalCode[] = Object.freeze([
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

const INTENT_ALIGNMENT_LABELS: readonly IntentAlignment[] = Object.freeze([
  "supported",
  "contradicted",
  "unclear",
]);

const RISK_CLASS_LABELS: readonly RiskClass[] = Object.freeze([
  "routine",
  "elevated",
  "high",
  "unclear",
]);

const POLICY_DECISION_LABELS: readonly PolicyDecisionLabel[] = Object.freeze([
  "allow_once",
  "deny",
  "manual_review",
]);

const HARD_DENY_SET: ReadonlySet<string> = new Set(HARD_DENY_CODES);
const KNOWN_SIGNAL_SET: ReadonlySet<string> = new Set(KNOWN_SIGNAL_CODES);
const INTENT_LABEL_SET: ReadonlySet<string> = new Set(INTENT_ALIGNMENT_LABELS);
const RISK_LABEL_SET: ReadonlySet<string> = new Set(RISK_CLASS_LABELS);
const POLICY_LABEL_SET: ReadonlySet<string> = new Set(POLICY_DECISION_LABELS);

const MANUAL_REASONS: ReadonlySet<string> = new Set([
  "out_of_scope",
  "already_resolved_external",
  "malformed_request",
  "missing_intent",
  "intent_ambiguous",
  "risk_unclear",
  "risk_high",
  "low_confidence",
  "malformed_jev_answer",
  "manual_review",
  "missing_api_key",
  "api_failure",
  "timeout",
  "queue_overflow",
  "event_stream_error",
  "plugin_cleanup",
  "unknown",
]);

const CONFIDENCE_BUCKETS: ReadonlySet<string> = new Set(["low", "medium", "high"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function isProbability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isSafeModelVersion(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 128) return false;
  if (value === "unknown") return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const digit = code >= 48 && code <= 57;
    const upper = code >= 65 && code <= 90;
    const lower = code >= 97 && code <= 122;
    const dot = code === 46;
    const underscore = code === 95;
    const colon = code === 58;
    const dash = code === 45;
    if (!(digit || upper || lower || dot || underscore || colon || dash)) return false;
  }
  return true;
}

function isSafePolicyVersion(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 64) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const digit = code >= 48 && code <= 57;
    const upper = code >= 65 && code <= 90;
    const lower = code >= 97 && code <= 122;
    const dot = code === 46;
    const underscore = code === 95;
    const dash = code === 45;
    if (!(digit || upper || lower || dot || underscore || dash)) return false;
  }
  return true;
}

function isSafeTokenCount(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 1000000000
  );
}

function isKnownSignal(value: unknown): value is GuardrailSignalCode {
  return typeof value === "string" && KNOWN_SIGNAL_SET.has(value);
}

function isHardDenyCode(value: unknown): value is HardDenySignalCode {
  return typeof value === "string" && HARD_DENY_SET.has(value);
}

function toConfidenceBucket(confidence: number): ConfidenceBucket {
  if (confidence >= 0.9) return "high";
  if (confidence >= 0.5) return "medium";
  return "low";
}

function frozenDecision(
  kind: CoreDecisionKind,
  reason: CoreDecisionReason,
  confidence: ConfidenceBucket,
): CoreDecision {
  return Object.freeze({ kind, reason, confidence });
}

function validateThresholds(value: unknown): PluginConfigThresholds | undefined {
  if (!isRecord(value)) return undefined;
  const allowConfidence: unknown = value.allowConfidence;
  const allowProbability: unknown = value.allowProbability;
  const elevatedAllowConfidence: unknown = value.elevatedAllowConfidence;
  const denyConfidence: unknown = value.denyConfidence;
  const denyProbability: unknown = value.denyProbability;
  const auxiliaryConfidence: unknown = value.auxiliaryConfidence;
  if (
    !isProbability(allowConfidence) ||
    !isProbability(allowProbability) ||
    !isProbability(elevatedAllowConfidence) ||
    !isProbability(denyConfidence) ||
    !isProbability(denyProbability) ||
    !isProbability(auxiliaryConfidence)
  ) {
    return undefined;
  }
  if (elevatedAllowConfidence < allowConfidence) return undefined;
  return Object.freeze({
    allowConfidence,
    allowProbability,
    elevatedAllowConfidence,
    denyConfidence,
    denyProbability,
    auxiliaryConfidence,
  });
}

interface ValidatedGuardrails {
  readonly signals: readonly GuardrailSignalCode[];
  readonly parseStatus: ParseStatus;
  readonly hardDeny: boolean;
  readonly policyVersion: string;
  readonly hardDenyCodes: readonly HardDenySignalCode[];
}

function readSignalList(value: unknown): GuardrailSignalCode[] | undefined {
  if (!Array.isArray(value) || value.length > 64) return undefined;
  const collected: GuardrailSignalCode[] = [];
  for (const entry of value) {
    if (!isKnownSignal(entry)) return undefined;
    if (!collected.includes(entry)) collected.push(entry);
  }
  return collected;
}

function readHardDenyList(value: unknown): HardDenySignalCode[] | undefined {
  if (!Array.isArray(value) || value.length > 16) return undefined;
  const collected: HardDenySignalCode[] = [];
  for (const entry of value) {
    if (!isHardDenyCode(entry)) return undefined;
    if (!collected.includes(entry)) collected.push(entry);
  }
  return collected;
}

function validateGuardrails(value: unknown): ValidatedGuardrails | undefined {
  if (!isRecord(value)) return undefined;
  const signalsRaw: unknown = value.signals;
  const parseStatusRaw: unknown = value.parseStatus;
  const hardDenyRaw: unknown = value.hardDeny;
  const policyVersionRaw: unknown = value.policyVersion;
  const hardDenyCodesRaw: unknown = value.hardDenyCodes;
  const eligibleRaw: unknown = value.eligibleForAutoAllow;
  const signals = readSignalList(signalsRaw);
  const hardDenyCodes = readHardDenyList(hardDenyCodesRaw);
  if (signals === undefined || hardDenyCodes === undefined) return undefined;
  if (
    parseStatusRaw !== "parsed" &&
    parseStatusRaw !== "unparseable" &&
    parseStatusRaw !== "unknown_scope"
  ) {
    return undefined;
  }
  if (typeof hardDenyRaw !== "boolean") return undefined;
  if (!isSafePolicyVersion(policyVersionRaw)) return undefined;
  if (typeof eligibleRaw !== "boolean") return undefined;
  return Object.freeze({
    signals: Object.freeze(signals),
    parseStatus: parseStatusRaw,
    hardDeny: hardDenyRaw,
    policyVersion: policyVersionRaw,
    hardDenyCodes: Object.freeze(hardDenyCodes),
  });
}

/**
 * Detect a previously detected local hard-deny even when the surrounding
 * assessment envelope is otherwise malformed. True when the input record
 * carries `hardDeny === true`, a valid hard-deny code in `hardDenyCodes`, or a
 * valid hard-deny code in `signals`. Used to keep validation failures as
 * reject for hard-denied requests.
 */
function detectHardDeny(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value.hardDeny === true) return true;
  const codes: unknown = value.hardDenyCodes;
  if (Array.isArray(codes)) {
    for (const entry of codes) {
      if (isHardDenyCode(entry)) return true;
    }
  }
  const signals: unknown = value.signals;
  if (Array.isArray(signals)) {
    for (const entry of signals) {
      if (isHardDenyCode(entry)) return true;
    }
  }
  return false;
}

function containsHardDenySignal(signals: readonly GuardrailSignalCode[]): boolean {
  for (const signal of signals) {
    if (isHardDenyCode(signal)) return true;
  }
  return false;
}

interface ValidatedChoice<Label extends string> {
  readonly choice: Label;
  readonly confidence: number;
  readonly selectedProbability: number;
}

function validateChoice<Label extends string>(
  raw: unknown,
  expected: readonly Label[],
  labelSet: ReadonlySet<string>,
): ValidatedChoice<Label> | undefined {
  if (!isRecord(raw)) return undefined;
  if (raw.type !== "choice") return undefined;
  const choice: unknown = raw.choice;
  if (typeof choice !== "string" || !labelSet.has(choice)) return undefined;
  let expectedFound = false;
  for (const label of expected) {
    if (choice === label) {
      expectedFound = true;
      break;
    }
  }
  if (!expectedFound) return undefined;
  const confidence: unknown = raw.confidence;
  if (!isProbability(confidence)) return undefined;
  const probabilities: unknown = raw.probabilities;
  if (!isRecord(probabilities)) return undefined;
  const keys = Reflect.ownKeys(probabilities);
  if (keys.length !== expected.length) return undefined;
  for (const label of expected) {
    if (!Object.prototype.hasOwnProperty.call(probabilities, label)) return undefined;
  }
  for (const key of keys) {
    if (typeof key !== "string" || !labelSet.has(key)) return undefined;
  }
  let sum = 0;
  for (const label of expected) {
    const probability: unknown = probabilities[label];
    if (!isProbability(probability)) return undefined;
    sum += probability;
  }
  if (!Number.isFinite(sum)) return undefined;
  if (Math.abs(sum - 1) > PROBABILITY_SUM_TOLERANCE) return undefined;
  const selected: unknown = probabilities[choice];
  if (!isProbability(selected)) return undefined;
  return { choice: choice as Label, confidence, selectedProbability: selected };
}

interface ValidatedJev {
  readonly intent: ValidatedChoice<IntentAlignment>;
  readonly risk: ValidatedChoice<RiskClass>;
  readonly final: ValidatedChoice<PolicyDecisionLabel>;
  readonly modelVersion: string;
}

function validateJev(value: unknown): ValidatedJev | undefined {
  if (!isRecord(value)) return undefined;
  const modelVersion: unknown = value.modelVersion;
  if (!isSafeModelVersion(modelVersion)) return undefined;
  const usage: unknown = value.usage;
  if (!isRecord(usage)) return undefined;
  if (!isSafeTokenCount(usage.inputTokens) || !isSafeTokenCount(usage.outputTokens)) {
    return undefined;
  }
  const auxiliary: unknown = value.auxiliary;
  if (!isRecord(auxiliary)) return undefined;
  const finalRaw: unknown = value.final;
  const intent = validateChoice<IntentAlignment>(
    auxiliary.intent_alignment,
    INTENT_ALIGNMENT_LABELS,
    INTENT_LABEL_SET,
  );
  const risk = validateChoice<RiskClass>(auxiliary.risk_class, RISK_CLASS_LABELS, RISK_LABEL_SET);
  const final = validateChoice<PolicyDecisionLabel>(
    finalRaw,
    POLICY_DECISION_LABELS,
    POLICY_LABEL_SET,
  );
  if (intent === undefined || risk === undefined || final === undefined) return undefined;
  return { intent, risk, final, modelVersion };
}

type SignalBlockReason =
  | "missing_intent"
  | "intent_ambiguous"
  | "risk_unclear"
  | "risk_high"
  | "low_confidence"
  | "malformed_jev_answer"
  | "queue_overflow"
  | "malformed_request";

/**
 * Map a non-empty guardrail signal set to the most specific manual reason for
 * blocking auto-allow. Returns undefined only when no signal blocks allow.
 * Hard-deny signals are handled by the caller as reject and never reach the
 * manual mapping in the valid path; they map here to malformed_request only
 * as a defensive fallback.
 */
function signalBlockingReason(
  signals: readonly GuardrailSignalCode[],
): SignalBlockReason | undefined {
  if (signals.length === 0) return undefined;
  if (signals.includes("missing_intent")) return "missing_intent";
  if (signals.includes("intent_ambiguous")) return "intent_ambiguous";
  if (signals.includes("risk_unclear")) return "risk_unclear";
  if (signals.includes("high_risk")) return "risk_high";
  if (signals.includes("low_confidence")) return "low_confidence";
  if (signals.includes("invalid_answer")) return "malformed_jev_answer";
  if (signals.includes("queue_overflow")) return "queue_overflow";
  return "malformed_request";
}

/**
 * Conservative composition of local hard policy and Jev answers.
 *
 * Pure and synchronous with no I/O. Validates all three inputs; any
 * validation failure is manual except a previously detected hard-deny, which
 * stays reject. Hard-deny signals, parse status, and uncertainty signals are
 * checked directly rather than trusting earlier eligibility flags.
 */
export function decide(
  guardrails: unknown,
  jev: unknown,
  thresholds: unknown,
): CoreDecision {
  const hardDenyDetected = detectHardDeny(guardrails);
  const validThresholds = validateThresholds(thresholds);
  const validGuardrails = validateGuardrails(guardrails);
  const validJev = validateJev(jev);

  if (validThresholds === undefined || validGuardrails === undefined || validJev === undefined) {
    if (hardDenyDetected) {
      return frozenDecision("REJECT", "hard_deny", "high");
    }
    if (validJev === undefined) {
      return frozenDecision("MANUAL_PENDING", "malformed_jev_answer", "low");
    }
    return frozenDecision("MANUAL_PENDING", "malformed_request", "low");
  }

  if (
    validGuardrails.hardDeny ||
    validGuardrails.hardDenyCodes.length > 0 ||
    containsHardDenySignal(validGuardrails.signals)
  ) {
    return frozenDecision("REJECT", "hard_deny", "high");
  }

  if (validJev.final.choice === "manual_review") {
    return frozenDecision(
      "MANUAL_PENDING",
      "manual_review",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  if (validJev.final.choice === "deny") {
    if (
      validJev.final.confidence >= validThresholds.denyConfidence &&
      validJev.final.selectedProbability >= validThresholds.denyProbability
    ) {
      return frozenDecision("REJECT", "confident_deny", "high");
    }
    return frozenDecision(
      "MANUAL_PENDING",
      "low_confidence",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  if (validJev.final.choice !== "allow_once") {
    return frozenDecision("MANUAL_PENDING", "malformed_jev_answer", "low");
  }

  if (validGuardrails.parseStatus !== "parsed") {
    return frozenDecision(
      "MANUAL_PENDING",
      "malformed_request",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  const blocked = signalBlockingReason(validGuardrails.signals);
  if (blocked !== undefined) {
    return frozenDecision(
      "MANUAL_PENDING",
      blocked,
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  if (validJev.intent.choice !== "supported") {
    return frozenDecision(
      "MANUAL_PENDING",
      "intent_ambiguous",
      toConfidenceBucket(validJev.final.confidence),
    );
  }
  if (
    validJev.intent.confidence < validThresholds.auxiliaryConfidence ||
    validJev.intent.selectedProbability < validThresholds.auxiliaryConfidence
  ) {
    return frozenDecision(
      "MANUAL_PENDING",
      "low_confidence",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  if (validJev.risk.choice === "high") {
    return frozenDecision(
      "MANUAL_PENDING",
      "risk_high",
      toConfidenceBucket(validJev.final.confidence),
    );
  }
  if (validJev.risk.choice === "unclear") {
    return frozenDecision(
      "MANUAL_PENDING",
      "risk_unclear",
      toConfidenceBucket(validJev.final.confidence),
    );
  }
  if (
    validJev.risk.confidence < validThresholds.auxiliaryConfidence ||
    validJev.risk.selectedProbability < validThresholds.auxiliaryConfidence
  ) {
    return frozenDecision(
      "MANUAL_PENDING",
      "low_confidence",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  const requiredConfidence =
    validJev.risk.choice === "elevated"
      ? validThresholds.elevatedAllowConfidence
      : validThresholds.allowConfidence;
  if (
    validJev.final.confidence < requiredConfidence ||
    validJev.final.selectedProbability < validThresholds.allowProbability
  ) {
    return frozenDecision(
      "MANUAL_PENDING",
      "low_confidence",
      toConfidenceBucket(validJev.final.confidence),
    );
  }

  return frozenDecision("ALLOW_ONCE", "allow_once", "high");
}

function isValidDecisionShape(value: Record<string, unknown>): boolean {
  const kind: unknown = value.kind;
  const reason: unknown = value.reason;
  const confidence: unknown = value.confidence;
  if (kind !== "ALLOW_ONCE" && kind !== "REJECT" && kind !== "MANUAL_PENDING") return false;
  if (typeof reason !== "string") return false;
  if (typeof confidence !== "string" || !CONFIDENCE_BUCKETS.has(confidence)) return false;
  if (kind === "ALLOW_ONCE" && reason !== "allow_once") return false;
  if (kind === "REJECT" && reason !== "hard_deny" && reason !== "confident_deny") return false;
  if (kind === "MANUAL_PENDING" && !MANUAL_REASONS.has(reason)) return false;
  return true;
}

/**
 * Map a core decision to the only automatic replies permitted.
 *
 * Returns `"once"` for a valid `ALLOW_ONCE`, `"reject"` for a valid `REJECT`,
 * and no reply (`undefined`) for `MANUAL_PENDING` or any malformed decision.
 * The `AutomaticReply` return type (`"once" | "reject"`) makes `"always"`
 * unrepresentable; this function never constructs, stores, or emits it.
 */
export function mapAutomaticReply(decision: unknown): AutomaticReply | undefined {
  if (!isRecord(decision)) return undefined;
  if (!isValidDecisionShape(decision)) return undefined;
  const kind = decision.kind as CoreDecisionKind;
  if (kind === "ALLOW_ONCE") return "once";
  if (kind === "REJECT") return "reject";
  return undefined;
}
