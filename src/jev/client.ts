/**
 * Bounded Jev evaluator boundary (Slice 3).
 *
 * Sends one structured `systemOne` call with three parallel atomic Choice
 * questions, then runtime-validates the response. Transport/API failures map
 * to closed sanitized categories without interpolating raw messages, bodies,
 * headers, or request state. No OpenCode imports; no filesystem/shell access.
 */

import { TypeSafeClient } from "@typesafe-ai/sdk";
import type {
  Fetch,
  Logger,
  RequestOptions,
  SystemOneRequest,
  TypeSafeClientConfig,
} from "@typesafe-ai/sdk";

import type {
  GuardrailAssessment,
  IntentAlignment,
  JevChoiceAnswer,
  JevChoiceLabel,
  JevEvaluation,
  PolicyDecisionLabel,
  RedactedContext,
  RiskClass,
} from "../domain.js";
import { sanitizeHttpError, type SanitizedError } from "../observability/errors.js";
import {
  INTENT_ALIGNMENT_LABELS,
  POLICY_DECISION_LABELS,
  PROBABILITY_SUM_TOLERANCE,
  RISK_CLASS_LABELS,
  buildJevRequest,
  type JevOutboundRequest,
} from "./questions.js";

/** Official hosted API root. No configurable base URL or proxy is accepted. */
export const JEV_BASE_URL = "https://api.typesafe.ai" as const;
/** Default hosted Jev model alias. Only `jev-*` names are accepted. */
export const JEV_DEFAULT_MODEL = "jev-latest" as const;
/** Total wall-clock deadline across SDK attempts (milliseconds). */
export const JEV_TOTAL_DEADLINE_MS = 8000 as const;
/** Bounded retries after the initial attempt. */
export const JEV_MAX_RETRIES = 1 as const;
/** First backoff delay for SDK retries (milliseconds). */
export const JEV_BACKOFF_INITIAL_MS = 100 as const;
/** Maximum backoff delay for SDK retries (milliseconds). */
export const JEV_BACKOFF_MAX_MS = 1000 as const;
/** Per-attempt SDK timeout used at construction (milliseconds). */
export const JEV_PER_ATTEMPT_TIMEOUT_MS = 8000 as const;
/** Maximum server retry delay honored before falling back to backoff. */
export const JEV_MAX_RETRY_AFTER_MS = 5000 as const;

const NOOP_LOGGER: Logger = Object.freeze({
  debug: (): void => {},
  info: (): void => {},
  warn: (): void => {},
  error: (): void => {},
});

export interface JevSystemOnePort {
  systemOne(request: SystemOneRequest, options?: RequestOptions): PromiseLike<unknown>;
}

export type JevClientFactory = (config: TypeSafeClientConfig) => JevSystemOnePort;

function defaultCreateClient(config: TypeSafeClientConfig): JevSystemOnePort {
  const client = new TypeSafeClient(config);
  return {
    systemOne: (request, options): PromiseLike<unknown> => client.systemOne(request, options),
  };
}

export interface JevClientOptions {
  readonly model?: string;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly fetch?: Fetch;
  readonly logger?: Logger;
  readonly createClient?: JevClientFactory;
}

export interface JevEvaluateOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export type JevEvaluateResult =
  | Readonly<{ ok: true; value: JevEvaluation }>
  | Readonly<{ ok: false; error: SanitizedError }>;

type PortResult =
  | Readonly<{ ok: true; port: JevSystemOnePort }>
  | Readonly<{ ok: false; error: SanitizedError }>;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function isJevModelName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim() === value &&
    /^jev-[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
  );
}

function isTotalTimeout(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 30000;
}

function isBoundedRetries(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 2;
}

function isProbability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isSafeModelVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

function isSafeTokenCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 1000000000;
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

function retryStatuses(): ReadonlySet<number> {
  const statuses = new Set<number>([408, 429]);
  for (let status = 500; status <= 599; status += 1) statuses.add(status);
  return statuses;
}

function validateChoice<Label extends JevChoiceLabel>(
  raw: unknown,
  expected: readonly Label[],
): JevChoiceAnswer<Label> | undefined {
  if (!isRecord(raw)) return undefined;
  if (raw.type !== "choice") return undefined;
  const choice: unknown = raw.choice;
  if (typeof choice !== "string") return undefined;
  let found = false;
  for (const label of expected) {
    if (choice === label) {
      found = true;
      break;
    }
  }
  if (!found) return undefined;
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
    if (typeof key !== "string") return undefined;
    let known = false;
    for (const label of expected) {
      if (key === label) {
        known = true;
        break;
      }
    }
    if (!known) return undefined;
  }
  let sum = 0;
  for (const label of expected) {
    const probability: unknown = probabilities[label];
    if (!isProbability(probability)) return undefined;
    sum += probability;
  }
  if (!Number.isFinite(sum)) return undefined;
  if (Math.abs(sum - 1) > PROBABILITY_SUM_TOLERANCE) return undefined;
  const frozenProbabilities = Object.freeze({ ...(probabilities as Record<string, number>) }) as Readonly<
    Record<Label, number>
  >;
  return Object.freeze({
    type: "choice",
    choice: choice as Label,
    confidence,
    probabilities: frozenProbabilities,
  });
}

function malformed(): JevEvaluateResult {
  return Object.freeze({ ok: false, error: Object.freeze({ category: "api_malformed_response" }) });
}

/**
 * Runtime-validate an unknown `systemOne` result.
 *
 * Rejects ambiguous/invalid answers (wrong type, unknown labels, non-finite
 * or out-of-range confidence/probabilities, missing labels, bad sums, bad
 * model/usage) as `api_malformed_response` so no invalid answer can reach
 * the later decision core. Never throws and never includes raw data.
 */
export function validateJevEvaluation(raw: unknown): JevEvaluateResult {
  try {
    if (!isRecord(raw)) return malformed();
    const model: unknown = raw.model;
    if (!isSafeModelVersion(model)) return malformed();
    const usage: unknown = raw.usage;
    if (!isRecord(usage)) return malformed();
    const inputTokens: unknown = usage.input_tokens;
    const outputTokens: unknown = usage.output_tokens;
    if (!isSafeTokenCount(inputTokens) || !isSafeTokenCount(outputTokens)) return malformed();
    const answers: unknown = raw.answers;
    if (!isRecord(answers)) return malformed();
    const intentRaw: unknown = answers.intent_alignment;
    const riskRaw: unknown = answers.risk_class;
    const finalRaw: unknown = answers.policy_decision;
    const intent = validateChoice<IntentAlignment>(intentRaw, INTENT_ALIGNMENT_LABELS);
    const risk = validateChoice<RiskClass>(riskRaw, RISK_CLASS_LABELS);
    const final = validateChoice<PolicyDecisionLabel>(finalRaw, POLICY_DECISION_LABELS);
    if (intent === undefined || risk === undefined || final === undefined) return malformed();
    const value: JevEvaluation = Object.freeze({
      auxiliary: Object.freeze({ intent_alignment: intent, risk_class: risk }),
      final,
      modelVersion: model,
      usage: Object.freeze({ inputTokens, outputTokens }),
    });
    return Object.freeze({ ok: true, value });
  } catch {
    return malformed();
  }
}

export const parseJevEvaluation = validateJevEvaluation;
export const isJevModel = isJevModelName;

/**
 * Single-call structured Jev evaluator with lazy client creation.
 *
 * The constructor never creates the SDK client and never throws for a
 * missing key. `evaluate` creates the client on first use with fixed
 * `baseURL`, Jev-only `defaultModel`, `logLevel: "off"`, bounded retry, and
 * a per-attempt timeout; it enforces an additional total wall-clock deadline
 * via an abort signal that also honors caller cleanup. The SDK reads
 * `TYPESAFE_API_KEY` itself; this module never reads, logs, or forwards it.
 */
export class JevClient {
  private cachedPort: JevSystemOnePort | undefined;

  public constructor(private readonly options: JevClientOptions = {}) {}

  private ensurePort(model: string, maxRetries: number): PortResult {
    if (this.cachedPort !== undefined) {
      return Object.freeze({ ok: true, port: this.cachedPort });
    }
    const fetchImpl: Fetch | undefined = this.options.fetch;
    const logger: Logger = this.options.logger ?? NOOP_LOGGER;
    const factory: JevClientFactory = this.options.createClient ?? defaultCreateClient;
    const config: TypeSafeClientConfig = {
      baseURL: JEV_BASE_URL,
      defaultModel: model,
      logLevel: "off",
      logger,
      retry: {
        maxRetries,
        backoffInitialMs: JEV_BACKOFF_INITIAL_MS,
        backoffMaxMs: JEV_BACKOFF_MAX_MS,
        backoffJitter: 0,
        httpStatuses: retryStatuses(),
        respectRetryAfter: true,
        maxRetryAfterMs: JEV_MAX_RETRY_AFTER_MS,
        apiConnectionError: true,
        apiTimeoutError: true,
      },
      timeout: JEV_PER_ATTEMPT_TIMEOUT_MS,
      ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
    };
    try {
      const port = factory(config);
      if (port === null || port === undefined) {
        return Object.freeze({ ok: false, error: Object.freeze({ category: "missing_api_key" }) });
      }
      const systemOne: unknown = (port as JevSystemOnePort).systemOne;
      if (typeof systemOne !== "function") {
        return Object.freeze({ ok: false, error: Object.freeze({ category: "missing_api_key" }) });
      }
      this.cachedPort = port;
      return Object.freeze({ ok: true, port });
    } catch {
      return Object.freeze({ ok: false, error: Object.freeze({ category: "missing_api_key" }) });
    }
  }

  public async evaluate(
    context: RedactedContext,
    assessment?: GuardrailAssessment,
    options?: JevEvaluateOptions,
  ): Promise<JevEvaluateResult> {
    const model: unknown = this.options.model ?? JEV_DEFAULT_MODEL;
    if (!isJevModelName(model)) {
      return Object.freeze({ ok: false, error: Object.freeze({ category: "config_invalid" }) });
    }
    const totalMs: unknown = options?.timeoutMs ?? this.options.timeoutMs ?? JEV_TOTAL_DEADLINE_MS;
    if (!isTotalTimeout(totalMs)) {
      return Object.freeze({ ok: false, error: Object.freeze({ category: "config_invalid" }) });
    }
    const maxRetries: unknown = this.options.maxRetries ?? JEV_MAX_RETRIES;
    if (!isBoundedRetries(maxRetries)) {
      return Object.freeze({ ok: false, error: Object.freeze({ category: "config_invalid" }) });
    }
    if (!isRecord(context)) {
      return malformed();
    }

    let outbound: JevOutboundRequest;
    try {
      outbound = buildJevRequest(context, assessment);
    } catch {
      return malformed();
    }

    const callerSignal: AbortSignal | undefined = options?.signal;
    if (isAborted(callerSignal)) {
      return Object.freeze({ ok: false, error: Object.freeze({ category: "api_aborted" }) });
    }

    const ensured: PortResult = this.ensurePort(model, maxRetries);
    if (ensured.ok !== true) {
      return Object.freeze({ ok: false, error: ensured.error });
    }
    const port = ensured.port;

    const deadlineController = new AbortController();
    const combinedController = new AbortController();
    let deadlineFired = false;
    const onCallerAbort = (): void => {
      combinedController.abort();
    };
    const onDeadlineAbort = (): void => {
      deadlineFired = true;
      combinedController.abort();
    };
    if (callerSignal !== undefined) {
      callerSignal.addEventListener("abort", onCallerAbort, { once: true });
    }
    deadlineController.signal.addEventListener("abort", onDeadlineAbort, { once: true });
    const timer = setTimeout(() => {
      deadlineController.abort();
    }, totalMs);

    try {
      const sdkRequest = {
        state: outbound.state,
        questions: outbound.questions,
        model,
      } as unknown as SystemOneRequest;
      const sdkOptions: RequestOptions = {
        signal: combinedController.signal,
        timeout: totalMs,
      };
      const raw: unknown = await port.systemOne(sdkRequest, sdkOptions);
      return validateJevEvaluation(raw);
    } catch (error) {
      if (deadlineFired) {
        return Object.freeze({ ok: false, error: Object.freeze({ category: "api_timeout" }) });
      }
      if (isAborted(callerSignal)) {
        return Object.freeze({ ok: false, error: Object.freeze({ category: "api_aborted" }) });
      }
      const sanitized: SanitizedError = sanitizeHttpError(error);
      return Object.freeze({ ok: false, error: sanitized });
    } finally {
      clearTimeout(timer);
      if (callerSignal !== undefined) {
        callerSignal.removeEventListener("abort", onCallerAbort);
      }
      deadlineController.signal.removeEventListener("abort", onDeadlineAbort);
    }
  }
}

export const JevEvaluator = JevClient;
export type JevEvaluator = JevClient;
