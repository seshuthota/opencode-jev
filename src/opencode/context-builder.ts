/**
 * The explicit outbound projection boundary.
 *
 * This module has no OpenCode or TypeSafe imports. It reads only named fields
 * from a normalized local fact object and constructs a fresh JSON-safe value;
 * it never spreads a request, metadata, message, source, environment, or tool
 * result into the outbound state.
 */

import type {
  ActionCategory,
  GuardrailSignalCode,
  HardDenySignalCode,
  LocalIntentCandidate,
  PermissionFacts,
  RedactedContext,
  RedactedPolicy,
  RedactionSummary,
  RedactionTruncation,
  ResourceKind,
  ResourceScope,
} from "../domain.js";
import {
  redactCommandDetailed,
  redactIntentDetailed,
  redactResourceDetailed,
  redactTextDetailed,
  type ResourceRedactionOptions,
} from "../redaction/index.js";
import type { PathRedactionOptions } from "../redaction/paths.js";

export interface ContextBuilderLimits {
  readonly commandChars: number;
  readonly intentChars: number;
  readonly resources: number;
  readonly resourceChars: number;
}

export interface ContextSummaryInput {
  readonly total?: number;
  readonly included?: number;
  readonly omitted?: number;
  readonly kindCounts?: Readonly<Partial<Record<ResourceKind, number>>>;
  readonly scopeCounts?: Readonly<Partial<Record<ResourceScope, number>>>;
}

export interface ContextBuilderOptions {
  readonly limits?: Partial<ContextBuilderLimits>;
  readonly projectRoot?: string;
  readonly homeDirectory?: string;
  readonly systemRoots?: readonly string[];
  readonly signals?: readonly GuardrailSignalCode[];
  /** Optional deterministic counts from a local normalizer; never copied blindly. */
  readonly summary?: ContextSummaryInput;
}

export type ContextIntent = LocalIntentCandidate | string | undefined;

const DEFAULT_LIMITS: ContextBuilderLimits = Object.freeze({
  commandChars: 4096,
  intentChars: 2000,
  resources: 16,
  resourceChars: 512,
});

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
const PRIVACY_INELIGIBLE_SIGNALS: ReadonlySet<GuardrailSignalCode> = new Set([
  "unknown_scope",
  "unresolved_path",
  "ambiguous_resource",
  "oversize",
  "redaction_incomplete",
  "missing_intent",
  "intent_ambiguous",
]);

const RESOURCE_KIND_SET: ReadonlySet<string> = new Set(RESOURCE_KINDS);
const RESOURCE_SCOPE_SET: ReadonlySet<string> = new Set(RESOURCE_SCOPES);
const ACTION_CATEGORY_SET: ReadonlySet<string> = new Set(ACTION_CATEGORIES);
const SIGNAL_SET: ReadonlySet<string> = new Set(SIGNAL_CODES);
const HARD_DENY_SET: ReadonlySet<string> = new Set(HARD_DENY_CODES);

interface BuildState {
  redactionComplete: boolean;
  truncation: {
    commands: boolean;
    intent: boolean;
    resources: boolean;
    resource: boolean;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Reflect.ownKeys(value).every((key) => typeof key === "string" && allowed.includes(key));
}

function isFiniteInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
}

function isResourceKind(value: unknown): value is ResourceKind {
  return typeof value === "string" && RESOURCE_KIND_SET.has(value);
}

function isResourceScope(value: unknown): value is ResourceScope {
  return typeof value === "string" && RESOURCE_SCOPE_SET.has(value);
}

function isActionCategory(value: unknown): value is ActionCategory {
  return typeof value === "string" && ACTION_CATEGORY_SET.has(value);
}

function isSignalCode(value: unknown): value is GuardrailSignalCode {
  return typeof value === "string" && SIGNAL_SET.has(value);
}

function isHardDenyCode(value: unknown): value is HardDenySignalCode {
  return typeof value === "string" && HARD_DENY_SET.has(value);
}

function isSafeVersion(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && /^[A-Za-z0-9._-]+$/u.test(value);
}

type MutableKindCounts = { -readonly [Key in ResourceKind]: number };
type MutableScopeCounts = { -readonly [Key in ResourceScope]: number };

function mutableKindCounts(): MutableKindCounts {
  return { path: 0, url: 0, command: 0, query: 0, generic: 0, unknown: 0 };
}

function mutableScopeCounts(): MutableScopeCounts {
  return { project: 0, external: 0, home: 0, system: 0, secret: 0, protected: 0, unknown: 0 };
}

function normalizeLimits(
  input: Partial<ContextBuilderLimits> | undefined,
  state: BuildState,
): ContextBuilderLimits {
  if (input === undefined) return DEFAULT_LIMITS;
  if (!isRecord(input)) {
    state.redactionComplete = false;
    return DEFAULT_LIMITS;
  }
  const allowed = ["commandChars", "intentChars", "resources", "resourceChars"] as const;
  if (!hasOnlyKeys(input, allowed)) state.redactionComplete = false;
  const commandChars = input.commandChars ?? DEFAULT_LIMITS.commandChars;
  const intentChars = input.intentChars ?? DEFAULT_LIMITS.intentChars;
  const resources = input.resources ?? DEFAULT_LIMITS.resources;
  const resourceChars = input.resourceChars ?? DEFAULT_LIMITS.resourceChars;
  if (
    !isFiniteInteger(commandChars, 16, 100_000) ||
    !isFiniteInteger(intentChars, 16, 100_000) ||
    !isFiniteInteger(resources, 1, 256) ||
    !isFiniteInteger(resourceChars, 16, 100_000)
  ) {
    state.redactionComplete = false;
    return DEFAULT_LIMITS;
  }
  return Object.freeze({ commandChars, intentChars, resources, resourceChars });
}

function validateSummaryInput(input: unknown, state: BuildState): void {
  if (input === undefined) return;
  if (!isRecord(input) || !hasOnlyKeys(input, ["total", "included", "omitted", "kindCounts", "scopeCounts"])) {
    state.redactionComplete = false;
    return;
  }
  for (const key of ["total", "included", "omitted"] as const) {
    if (input[key] !== undefined && !isFiniteInteger(input[key], 0, 1_000_000)) {
      state.redactionComplete = false;
    }
  }
  const validateCounts = (value: unknown, keys: readonly string[]): void => {
    if (value === undefined) return;
    if (!isRecord(value) || !hasOnlyKeys(value, keys)) {
      state.redactionComplete = false;
      return;
    }
    for (const key of keys) {
      const count = value[key];
      if (count !== undefined && !isFiniteInteger(count, 0, 1_000_000)) state.redactionComplete = false;
    }
  };
  validateCounts(input.kindCounts, RESOURCE_KINDS);
  validateCounts(input.scopeCounts, RESOURCE_SCOPES);
}

function readSignals(
  facts: PermissionFacts,
  options: ContextBuilderOptions | readonly GuardrailSignalCode[] | undefined,
  state: BuildState,
): readonly GuardrailSignalCode[] {
  let candidate: unknown = facts.signals;
  if (Array.isArray(options)) candidate = options;
  else if (isRecord(options) && hasOwn(options, "signals")) candidate = options.signals;
  if (candidate === undefined) return Object.freeze([]);
  if (!Array.isArray(candidate)) {
    state.redactionComplete = false;
    return Object.freeze([]);
  }
  const admitted = new Set<GuardrailSignalCode>();
  for (const value of candidate.slice(0, 64)) {
    if (isSignalCode(value)) admitted.add(value);
    else state.redactionComplete = false;
  }
  if (candidate.length > 64) state.redactionComplete = false;
  return Object.freeze(SIGNAL_CODES.filter((signal) => admitted.has(signal)));
}

function fallbackPolicy(): RedactedPolicy {
  return Object.freeze({
    version: "unknown",
    hardDenyCodes: Object.freeze([]) as readonly HardDenySignalCode[],
    unknown: "manual_review",
    maximumGrant: "once",
  });
}

function normalizePolicy(input: RedactedPolicy, state: BuildState): RedactedPolicy {
  if (!isRecord(input) || !hasOnlyKeys(input, ["version", "hardDenyCodes", "unknown", "maximumGrant"])) {
    state.redactionComplete = false;
    return fallbackPolicy();
  }
  if (!isSafeVersion(input.version) || input.unknown !== "manual_review" || input.maximumGrant !== "once") {
    state.redactionComplete = false;
    return fallbackPolicy();
  }
  if (!Array.isArray(input.hardDenyCodes)) {
    state.redactionComplete = false;
    return fallbackPolicy();
  }
  const codes: HardDenySignalCode[] = [];
  for (const value of input.hardDenyCodes.slice(0, 16)) {
    if (isHardDenyCode(value) && !codes.includes(value)) codes.push(value);
    else state.redactionComplete = false;
  }
  if (input.hardDenyCodes.length > 16) state.redactionComplete = false;
  return Object.freeze({
    version: input.version,
    hardDenyCodes: Object.freeze(HARD_DENY_CODES.filter((code) => codes.includes(code))),
    unknown: "manual_review",
    maximumGrant: "once",
  });
}

function projectNamedText(
  input: unknown,
  maxChars: number,
  state: BuildState,
  pathOptions?: PathRedactionOptions,
): string | undefined {
  if (input === undefined) return undefined;
  const projection = redactTextDetailed(
    input,
    pathOptions === undefined ? { maxChars } : { maxChars, pathOptions },
  );
  if (!projection.complete || projection.value.length === 0) {
    state.redactionComplete = false;
    return undefined;
  }
  return projection.value;
}

function readIntentText(intent: ContextIntent, facts: PermissionFacts, state: BuildState): string | undefined {
  const candidate = intent === undefined ? facts.intent : intent;
  if (candidate === undefined) return undefined;
  if (typeof candidate === "string") {
    return candidate.length === 0 ? undefined : candidate;
  }
  if (isRecord(candidate) && typeof candidate.text === "string" && candidate.text.length > 0) {
    if (
      candidate.role !== undefined &&
      (typeof candidate.role !== "string" || candidate.role.toLowerCase() !== "user")
    ) {
      state.redactionComplete = false;
      return undefined;
    }
    return candidate.text;
  }
  state.redactionComplete = false;
  return undefined;
}

function capResourceList(
  resources: readonly Readonly<{ kind: ResourceKind; scope: ResourceScope; display: string }>[],
  maximum: number,
): Readonly<{
  resources: readonly Readonly<{ kind: ResourceKind; scope: ResourceScope; display: string }>[];
  truncated: boolean;
}> {
  if (resources.length <= maximum) return { resources, truncated: false };
  const markerIndex = Math.max(0, maximum - 1);
  const remaining = markerIndex;
  const headLength = Math.ceil(remaining / 2);
  const tailLength = remaining - headLength;
  const selected = [
    ...resources.slice(0, headLength),
    {
      kind: "generic" as const,
      scope: "unknown" as const,
      display: `<resources-omitted:${resources.length - remaining}>`,
    },
    ...resources.slice(resources.length - tailLength),
  ];
  return { resources: selected, truncated: true };
}

function capCommands(
  commands: readonly string[],
  maximum: number,
): Readonly<{ commands: readonly string[]; truncated: boolean }> {
  if (commands.length <= maximum) return { commands, truncated: false };
  const marker = "<commands-omitted>";
  const remaining = Math.max(0, maximum - 1);
  const headLength = Math.ceil(remaining / 2);
  const tailLength = remaining - headLength;
  return {
    commands: [
      ...commands.slice(0, headLength),
      marker,
      ...commands.slice(commands.length - tailLength),
    ],
    truncated: true,
  };
}

function redactionOptions(
  options: ContextBuilderOptions,
  state: BuildState,
): PathRedactionOptions {
  const pathOptions: PathRedactionOptions = {
    ...(options.projectRoot === undefined ? {} : { projectRoot: options.projectRoot }),
    ...(options.homeDirectory === undefined ? {} : { homeDirectory: options.homeDirectory }),
    ...(options.systemRoots === undefined ? {} : { systemRoots: options.systemRoots }),
  };
  if (options.projectRoot !== undefined && typeof options.projectRoot !== "string") {
    state.redactionComplete = false;
  }
  if (options.homeDirectory !== undefined && typeof options.homeDirectory !== "string") {
    state.redactionComplete = false;
  }
  return pathOptions;
}

function makeSummary(
  total: number,
  included: number,
  kindCounts: MutableKindCounts,
  scopeCounts: MutableScopeCounts,
): RedactionSummary {
  return Object.freeze({
    total,
    included,
    omitted: Math.max(0, total - included),
    kindCounts: Object.freeze({ ...kindCounts }),
    scopeCounts: Object.freeze({ ...scopeCounts }),
  });
}

function makeTruncation(state: BuildState): RedactionTruncation {
  return Object.freeze({ ...state.truncation });
}

function isContextOptions(
  value: ContextBuilderOptions | readonly GuardrailSignalCode[] | undefined,
): value is ContextBuilderOptions {
  return value !== undefined && !Array.isArray(value);
}

function buildContextInternal(
  facts: PermissionFacts,
  intent: ContextIntent,
  policy: RedactedPolicy,
  options: ContextBuilderOptions | readonly GuardrailSignalCode[] | undefined,
): RedactedContext {
  const state: BuildState = {
    redactionComplete: true,
    truncation: { commands: false, intent: false, resources: false, resource: false },
  };
  const normalizedOptions: ContextBuilderOptions = isContextOptions(options) ? options : {};
  const limits = normalizeLimits(normalizedOptions.limits, state);
  validateSummaryInput(normalizedOptions.summary, state);
  const signals = readSignals(facts, options, state);
  const safePolicy = normalizePolicy(policy, state);
  const pathOptions = redactionOptions(normalizedOptions, state);

  let action = "unknown";
  let actionCategory: ActionCategory = "unknown";
  if (typeof facts.action === "string" && facts.action.length > 0 && facts.action.length <= 256) {
    const projection = redactTextDetailed(facts.action, { maxChars: 256, pathOptions });
    if (projection.complete && projection.value.length > 0) action = projection.value;
    else state.redactionComplete = false;
  } else {
    state.redactionComplete = false;
  }
  if (isActionCategory(facts.actionCategory) && facts.actionCategory !== "unknown") {
    actionCategory = facts.actionCategory;
  } else {
    state.redactionComplete = false;
  }

  const tool = projectNamedText(facts.tool, 128, state, pathOptions);
  const rawIntent = readIntentText(intent, facts, state);
  let projectedIntent: string | undefined;
  let intentAvailable = false;
  if (rawIntent !== undefined) {
    const projection = redactIntentDetailed(rawIntent, {
      maxChars: limits.intentChars,
      pathOptions,
    });
    if (projection.complete && projection.value.length > 0 && projection.value !== "<redacted-omitted>") {
      projectedIntent = projection.value;
      intentAvailable = true;
      state.truncation.intent = projection.truncated;
    } else {
      state.redactionComplete = false;
    }
  }

  const kindCounts = mutableKindCounts();
  const scopeCounts = mutableScopeCounts();
  const projectedResources: Array<Readonly<{ kind: ResourceKind; scope: ResourceScope; display: string }>> = [];
  const commandValues: string[] = [];
  let totalResources = 0;
  const resourcesInput = facts.resources;
  if (!Array.isArray(resourcesInput)) {
    state.redactionComplete = false;
  } else {
    totalResources = resourcesInput.length;
    for (const candidate of resourcesInput.slice(0, 10_000)) {
      if (!isRecord(candidate) || typeof candidate.value !== "string" || candidate.value.length === 0) {
        state.redactionComplete = false;
        continue;
      }
      const kind = candidate.kind;
      const scope = candidate.scope;
      if (!isResourceKind(kind) || !isResourceScope(scope)) {
        state.redactionComplete = false;
        continue;
      }
      kindCounts[kind] += 1;
      scopeCounts[scope] += 1;
      if (kind === "command" && actionCategory !== "shell") {
        // Command text is only an outbound field for shell actions.
        state.redactionComplete = false;
        continue;
      }
      const resourceOptions: ResourceRedactionOptions = {
        maxChars: kind === "command" ? limits.commandChars : limits.resourceChars,
        pathOptions,
      };
      if (kind === "command") {
        const command = redactCommandDetailed(candidate.value, {
          maxChars: limits.commandChars,
          pathOptions,
        });
        if (!command.complete || command.value.length === 0) {
          state.redactionComplete = false;
          continue;
        }
        commandValues.push(command.value);
        state.truncation.commands = state.truncation.commands || command.truncated;
      } else {
        const projection = redactResourceDetailed(candidate.value, kind, scope, resourceOptions);
        if (!projection.complete || projection.resource === undefined) {
          state.redactionComplete = false;
          continue;
        }
        projectedResources.push(projection.resource);
        state.truncation.resource = state.truncation.resource || projection.truncated;
      }
    }
    if (resourcesInput.length > 10_000) state.redactionComplete = false;
  }

  const cappedCommands = capCommands(commandValues, Math.min(8, limits.resources));
  state.truncation.commands = state.truncation.commands || cappedCommands.truncated;
  const combinedCount = cappedCommands.commands.length + projectedResources.length;
  let cappedResources = capResourceList(projectedResources, limits.resources);
  if (combinedCount > limits.resources) {
    const remaining = Math.max(0, limits.resources - cappedCommands.commands.length);
    cappedResources = {
      resources: projectedResources.slice(0, remaining),
      truncated: true,
    };
  }
  state.truncation.resources = cappedResources.truncated;
  const resourceMarkerCount = cappedResources.resources.filter((resource) =>
    resource.display.startsWith("<resources-omitted:"),
  ).length;
  const actualResourceIncluded = Math.max(0, cappedResources.resources.length - resourceMarkerCount);
  const actualCommandIncluded = cappedCommands.commands.filter((command) => command !== "<commands-omitted>").length;
  const summary = makeSummary(totalResources, actualResourceIncluded + actualCommandIncluded, kindCounts, scopeCounts);
  const hasPrivacySignal = signals.some((signal) => PRIVACY_INELIGIBLE_SIGNALS.has(signal));
  const hasUnknownScope = projectedResources.some((resource) => resource.scope === "unknown");
  const eligibleForAutoAllow =
    state.redactionComplete &&
    intentAvailable &&
    !state.truncation.commands &&
    !state.truncation.intent &&
    !state.truncation.resources &&
    !state.truncation.resource &&
    !hasPrivacySignal &&
    !hasUnknownScope;

  const truncation = makeTruncation(state);
  const context: RedactedContext = {
    action,
    actionCategory,
    ...(tool === undefined ? {} : { tool }),
    ...(cappedCommands.commands.length === 0 ? {} : { commands: cappedCommands.commands }),
    resources: cappedResources.resources,
    signals,
    ...(projectedIntent === undefined ? {} : { intent: projectedIntent }),
    policy: safePolicy,
    summary,
    truncation,
    redactionComplete: state.redactionComplete,
    eligibleForAutoAllow,
  };
  return Object.freeze({
    ...context,
    resources: Object.freeze([...context.resources]),
    signals: Object.freeze([...context.signals]),
    ...(context.commands === undefined ? {} : { commands: Object.freeze([...context.commands]) }),
    policy: Object.freeze({ ...context.policy, hardDenyCodes: Object.freeze([...context.policy.hardDenyCodes]) }),
    summary: Object.freeze({
      ...summary,
      kindCounts: Object.freeze({ ...summary.kindCounts }),
      scopeCounts: Object.freeze({ ...summary.scopeCounts }),
    }),
    truncation,
  });
}

/** Build a fresh outbound-safe context from named normalized fields. */
export function buildRedactedContext(
  facts: PermissionFacts,
  intent: ContextIntent,
  policy: RedactedPolicy,
  options?: ContextBuilderOptions | readonly GuardrailSignalCode[],
): RedactedContext {
  try {
    return buildContextInternal(facts, intent, policy, options);
  } catch {
    const state: BuildState = {
      redactionComplete: false,
      truncation: { commands: false, intent: false, resources: false, resource: false },
    };
    return Object.freeze({
      action: "unknown",
      actionCategory: "unknown",
      resources: Object.freeze([]),
      signals: Object.freeze([]),
      policy: fallbackPolicy(),
      truncation: makeTruncation(state),
      redactionComplete: false,
      eligibleForAutoAllow: false,
    });
  }
}

export const buildContext = buildRedactedContext;

/** Small state-free facade for callers that want a named builder. */
export class ContextBuilder {
  public constructor(private readonly options: ContextBuilderOptions = {}) {}

  public build(
    facts: PermissionFacts,
    intent: ContextIntent,
    policy: RedactedPolicy,
    overrides?: ContextBuilderOptions | readonly GuardrailSignalCode[],
  ): RedactedContext {
    const merged: ContextBuilderOptions = Array.isArray(overrides)
      ? { ...this.options, signals: overrides }
      : { ...this.options, ...(overrides ?? {}) };
    return buildRedactedContext(facts, intent, policy, merged);
  }
}
