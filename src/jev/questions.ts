/**
 * Pure Jev question/state boundary (Slice 3).
 *
 * This module has no OpenCode, TypeSafe SDK, filesystem, shell, or network
 * imports. It builds a fresh allowlisted outbound state from named
 * `RedactedContext` fields plus an optional guardrail assessment, and three
 * static atomic Choice questions evaluated in parallel by one `systemOne`
 * call. It never spreads its inputs and never copies identifiers, raw paths,
 * transcripts, file contents, secrets, prompts, headers, or API keys.
 */

import type {
  ActionCategory,
  GuardrailAssessment,
  GuardrailSignalCode,
  HardDenySignalCode,
  RedactedContext,
  ResourceKind,
  ResourceScope,
} from "../domain.js";

/** Canonical Jev question names for the single parallel `systemOne` call. */
export const INTENT_ALIGNMENT_QUESTION = "intent_alignment" as const;
export const RISK_CLASS_QUESTION = "risk_class" as const;
export const POLICY_DECISION_QUESTION = "policy_decision" as const;

export type IntentAlignmentQuestionName = typeof INTENT_ALIGNMENT_QUESTION;
export type RiskClassQuestionName = typeof RISK_CLASS_QUESTION;
export type PolicyDecisionQuestionName = typeof POLICY_DECISION_QUESTION;

/** Exact labels accepted for each Choice answer. */
export const INTENT_ALIGNMENT_LABELS = ["supported", "contradicted", "unclear"] as const;
export const RISK_CLASS_LABELS = ["routine", "elevated", "high", "unclear"] as const;
export const POLICY_DECISION_LABELS = ["allow_once", "deny", "manual_review"] as const;

export type IntentAlignmentLabel = (typeof INTENT_ALIGNMENT_LABELS)[number];
export type RiskClassLabel = (typeof RISK_CLASS_LABELS)[number];
export type PolicyDecisionLabel = (typeof POLICY_DECISION_LABELS)[number];

/**
 * Documented tolerance for probability-distribution sums.
 *
 * Each Choice answer must satisfy `|sum(probabilities) - 1| <= tolerance`.
 * The tolerance accommodates server-side rounding while still rejecting
 * ambiguous or malformed distributions.
 */
export const PROBABILITY_SUM_TOLERANCE = 0.01 as const;

/** Outbound-safe Jev state: an allowlisted projection only. */
export interface JevOutboundState {
  readonly request: Readonly<{
    action: string;
    action_category: string;
    tool?: string;
  }>;
  /** Redacted shell commands; present only for shell actions. */
  readonly commands?: readonly string[];
  readonly resources: readonly Readonly<{
    kind: string;
    scope: string;
    display: string;
  }>[];
  readonly signals: readonly string[];
  readonly counts: Readonly<{
    total: number;
    included: number;
    omitted: number;
  }>;
  readonly user_intent?: string;
  readonly local_policy: Readonly<{
    version: string;
    hard_deny_codes: readonly string[];
    unknown: "manual_review";
    maximum_grant: "once";
  }>;
  readonly redaction_complete: boolean;
}

export interface JevChoiceQuestion {
  readonly type: "choice";
  readonly instructions: string;
  readonly criteria: Readonly<Record<string, string>>;
}

export interface JevOutboundQuestions {
  readonly intent_alignment: JevChoiceQuestion;
  readonly risk_class: JevChoiceQuestion;
  readonly policy_decision: JevChoiceQuestion;
}

export interface JevOutboundRequest {
  readonly state: JevOutboundState;
  readonly questions: JevOutboundQuestions;
}

const ACTION_CATEGORIES: readonly ActionCategory[] = Object.freeze([
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

const SIGNAL_CODES: readonly GuardrailSignalCode[] = Object.freeze([
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

const HARD_DENY_CODES: readonly HardDenySignalCode[] = Object.freeze([
  "secret_access",
  "destructive_operation",
  "privilege_change",
  "security_boundary_change",
  "obvious_exfiltration",
]);

const RESOURCE_KINDS: readonly ResourceKind[] = Object.freeze([
  "path",
  "url",
  "command",
  "query",
  "generic",
  "unknown",
]);

const RESOURCE_SCOPES: readonly ResourceScope[] = Object.freeze([
  "project",
  "external",
  "home",
  "system",
  "secret",
  "protected",
  "unknown",
]);

const ACTION_CATEGORY_SET: ReadonlySet<string> = new Set(ACTION_CATEGORIES);
const SIGNAL_SET: ReadonlySet<string> = new Set(SIGNAL_CODES);
const HARD_DENY_SET: ReadonlySet<string> = new Set(HARD_DENY_CODES);
const KIND_SET: ReadonlySet<string> = new Set(RESOURCE_KINDS);
const SCOPE_SET: ReadonlySet<string> = new Set(RESOURCE_SCOPES);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function isSafeAction(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function isSafeTool(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function isSafeDisplay(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512;
}

function isSafeCommand(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4096;
}

function isSafeIntent(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 8192;
}

function isSafeVersion(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 64 && /^[A-Za-z0-9._-]+$/.test(value);
}

function isSafeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1000000;
}

function readSignals(context: RedactedContext): readonly GuardrailSignalCode[] {
  const candidate: unknown = context.signals;
  if (!Array.isArray(candidate)) return Object.freeze([]);
  const admitted = new Set<GuardrailSignalCode>();
  for (const value of candidate.slice(0, 64)) {
    if (typeof value === "string" && SIGNAL_SET.has(value)) {
      admitted.add(value as GuardrailSignalCode);
    }
  }
  return Object.freeze(SIGNAL_CODES.filter((signal) => admitted.has(signal)));
}

function readHardDenyCodes(
  context: RedactedContext,
  assessment: GuardrailAssessment | undefined,
): readonly HardDenySignalCode[] {
  const fromAssessment: unknown = assessment?.hardDenyCodes;
  const fromContext: unknown = context.policy?.hardDenyCodes;
  const candidate: unknown = Array.isArray(fromAssessment) ? fromAssessment : fromContext;
  if (!Array.isArray(candidate)) return Object.freeze([]);
  const admitted: HardDenySignalCode[] = [];
  for (const value of candidate.slice(0, 16)) {
    if (typeof value === "string" && HARD_DENY_SET.has(value) && !admitted.includes(value as HardDenySignalCode)) {
      admitted.push(value as HardDenySignalCode);
    }
  }
  return Object.freeze(HARD_DENY_CODES.filter((code) => admitted.includes(code)));
}

function readPolicyVersion(
  context: RedactedContext,
  assessment: GuardrailAssessment | undefined,
): string {
  const fromAssessment: unknown = assessment?.policyVersion;
  if (isSafeVersion(fromAssessment)) return fromAssessment;
  const fromContext: unknown = context.policy?.version;
  if (isSafeVersion(fromContext)) return fromContext;
  return "unknown";
}

function readCounts(context: RedactedContext, included: number): Readonly<{ total: number; included: number; omitted: number }> {
  const summary: unknown = context.summary;
  if (isRecord(summary)) {
    const total = summary.total;
    const summaryIncluded = summary.included;
    const omitted = summary.omitted;
    if (isSafeCount(total) && isSafeCount(summaryIncluded) && isSafeCount(omitted)) {
      const safeIncluded = Math.min(summaryIncluded, 1000000);
      const safeTotal = Math.min(Math.max(total, safeIncluded), 1000000);
      return Object.freeze({
        total: safeTotal,
        included: Math.min(included, safeTotal),
        omitted: Math.max(0, safeTotal - Math.min(included, safeTotal)),
      });
    }
  }
  const safeIncluded = Math.max(0, Math.min(included, 1000000));
  return Object.freeze({ total: safeIncluded, included: safeIncluded, omitted: 0 });
}

function readResources(context: RedactedContext): ReadonlyArray<Readonly<{ kind: string; scope: string; display: string }>> {
  const candidate: unknown = context.resources;
  if (!Array.isArray(candidate)) return Object.freeze([]);
  const projected: Array<Readonly<{ kind: string; scope: string; display: string }>> = [];
  for (const entry of candidate.slice(0, 64)) {
    if (!isRecord(entry)) continue;
    const kind: unknown = entry.kind;
    const scope: unknown = entry.scope;
    const display: unknown = entry.display;
    if (typeof kind !== "string" || !KIND_SET.has(kind)) continue;
    if (typeof scope !== "string" || !SCOPE_SET.has(scope)) continue;
    if (!isSafeDisplay(display)) continue;
    projected.push(Object.freeze({ kind, scope, display }));
  }
  return Object.freeze(projected);
}

function readCommands(context: RedactedContext, actionCategory: string): readonly string[] | undefined {
  if (actionCategory !== "shell") return undefined;
  const candidate: unknown = context.commands;
  if (candidate === undefined) return undefined;
  if (!Array.isArray(candidate)) return undefined;
  const projected: string[] = [];
  for (const entry of candidate.slice(0, 8)) {
    if (isSafeCommand(entry)) projected.push(entry);
  }
  if (projected.length === 0) return undefined;
  return Object.freeze(projected);
}

/**
 * Build only the outbound Jev state from allowlisted fields.
 *
 * Reads `action`, `actionCategory`, `tool`, shell-only `commands`,
 * `resources` (kind/scope/display), `signals`, bounded `summary` counts,
 * redacted `intent`, and `policy` version/hard-deny codes. An optional
 * guardrail assessment supplies only `policyVersion`/`hardDenyCodes` when
 * valid; every other input property (including any extra identifier,
 * metadata, transcript, or raw fields smuggled through a cast object) is
 * ignored and never copied.
 */
export function buildJevState(
  context: RedactedContext,
  assessment?: GuardrailAssessment,
): JevOutboundState {
  try {
    if (!isRecord(context)) {
      return Object.freeze({
        request: Object.freeze({ action: "unknown", action_category: "unknown" }),
        resources: Object.freeze([]),
        signals: Object.freeze([]),
        counts: Object.freeze({ total: 0, included: 0, omitted: 0 }),
        local_policy: Object.freeze({
          version: "unknown",
          hard_deny_codes: Object.freeze([]) as readonly string[],
          unknown: "manual_review" as const,
          maximum_grant: "once" as const,
        }),
        redaction_complete: false,
      });
    }
    const rawAction: unknown = context.action;
    const rawCategory: unknown = context.actionCategory;
    const action = isSafeAction(rawAction) ? rawAction : "unknown";
    const actionCategory =
      typeof rawCategory === "string" && ACTION_CATEGORY_SET.has(rawCategory) ? rawCategory : "unknown";
    const rawTool: unknown = context.tool;
    const tool = isSafeTool(rawTool) ? rawTool : undefined;
    const resources = readResources(context);
    const signals = readSignals(context);
    const commands = readCommands(context, actionCategory);
    const rawIntent: unknown = context.intent;
    const userIntent = isSafeIntent(rawIntent) ? rawIntent : undefined;
    const version = readPolicyVersion(context, assessment);
    const hardDeny = readHardDenyCodes(context, assessment);
    const counts = readCounts(context, resources.length + (commands?.length ?? 0));
    const redactionComplete = context.redactionComplete === true;

    return Object.freeze({
      request: Object.freeze({
        action,
        action_category: actionCategory,
        ...(tool === undefined ? {} : { tool }),
      }),
      ...(commands === undefined ? {} : { commands }),
      resources,
      signals,
      counts,
      ...(userIntent === undefined ? {} : { user_intent: userIntent }),
      local_policy: Object.freeze({
        version,
        hard_deny_codes: hardDeny,
        unknown: "manual_review",
        maximum_grant: "once",
      }),
      redaction_complete: redactionComplete,
    });
  } catch {
    return Object.freeze({
      request: Object.freeze({ action: "unknown", action_category: "unknown" }),
      resources: Object.freeze([]),
      signals: Object.freeze([]),
      counts: Object.freeze({ total: 0, included: 0, omitted: 0 }),
      local_policy: Object.freeze({
        version: "unknown",
        hard_deny_codes: Object.freeze([]),
        unknown: "manual_review",
        maximum_grant: "once",
      }),
      redaction_complete: false,
    });
  }
}

/**
 * Build the three static parallel atomic Choice questions.
 *
 * Instructions and criteria are fixed strings with no request data, so the
 * returned JSON can never carry identifiers, paths, transcripts, secrets,
 * prompts, headers, or API keys.
 */
export function buildJevQuestions(): JevOutboundQuestions {
  return Object.freeze({
    intent_alignment: Object.freeze({
      type: "choice",
      instructions: "Does the requested action align with the user's stated relevant intent?",
      criteria: Object.freeze({
        supported: "The request directly implements the user's stated relevant intent with no conflict.",
        contradicted: "The request conflicts with or contradicts the user's stated relevant intent.",
        unclear: "Alignment cannot be determined, or relevant intent is missing or ambiguous.",
      }),
    }),
    risk_class: Object.freeze({
      type: "choice",
      instructions: "What is the risk class of the requested action given its scope and deterministic signals?",
      criteria: Object.freeze({
        routine: "Routine low-risk operation with narrow scope and no concerning signals.",
        elevated: "Elevated risk that needs stricter scrutiny but is not clearly dangerous.",
        high: "High-risk, destructive, privileged, secret-accessing, or exfiltrative operation.",
        unclear: "Risk cannot be determined from the available state or signals are ambiguous.",
      }),
    }),
    policy_decision: Object.freeze({
      type: "choice",
      instructions:
        "What is the policy decision for this request under non-negotiable local policy and relevant intent?",
      criteria: Object.freeze({
        allow_once:
          "Compatible with non-negotiable local policy and relevant intent; grant exactly once.",
        deny: "Clear policy or intent safety conflict; deny.",
        manual_review: "Ambiguous, uncertain, or insufficient information; require manual review.",
      }),
    }),
  });
}

/**
 * Build the single outbound `systemOne` payload from allowlisted inputs only.
 *
 * Accepts only `RedactedContext` plus an optional guardrail assessment (used
 * solely for `policyVersion`/`hardDenyCodes`). Never accepts raw facts,
 * session/message identifiers, metadata, transcripts, file contents, or
 * environment data.
 */
export function buildJevRequest(
  context: RedactedContext,
  assessment?: GuardrailAssessment,
): JevOutboundRequest {
  const state = buildJevState(context, assessment);
  const questions = buildJevQuestions();
  return Object.freeze({ state, questions });
}

export const buildQuestions = buildJevQuestions;
export const buildState = buildJevState;
export const buildRequest = buildJevRequest;
