/**
 * Deterministic fake OpenCode location/event stream with a fake Jev port (Slice 6).
 *
 * Offline only. No network, filesystem, shell, timers, credentials, or private
 * OpenCode imports. All fakes are in-memory, synchronous where possible, and
 * controllable through deferred gates so integration tests are deterministic.
 */

import type {
  ErrorReason,
  GuardrailAssessment,
  JevEvaluation,
  RedactedContext,
} from "../../src/domain.js";
import type { JevEvaluateResult } from "../../src/jev/client.js";

/** Sentinel values that must never appear in Jev state or audit logs. */
export const SENTINELS = Object.freeze({
  secret: "INTEG_SENTINEL_SECRET_0123456789abcdef",
  bearer: "INTEG_SENTINEL_BEARER_0123456789abcdef",
  session: "session-INTEG-SENTINEL-001",
  message: "message-INTEG-SENTINEL-002",
  rawPath: "/home/integ-sentinel-user/secret/file.txt",
  metadata: "INTEG_SENTINEL_METADATA_0123456789abcdef",
  transcript: "INTEG_SENTINEL_TRANSCRIPT_0123456789abcdef",
  prompt: "INTEG_SENTINEL_PROMPT_0123456789abcdef",
  header: "INTEG_SENTINEL_HEADER_0123456789abcdef",
  apiKey: "sk-live-INTEG-SENTINEL-0123456789abcdef",
  rawError: "INTEG_SENTINEL_RAW_ERROR_0123456789abcdef",
  command: "INTEG_SENTINEL_COMMAND_0123456789abcdef",
});

export type SentinelName = keyof typeof SENTINELS;

/** Minimal deferred gate for deterministic Jev/reply delays without timers. */
export class Deferred<T> {
  public readonly promise: Promise<T>;
  private resolveFn: ((value: T | PromiseLike<T>) => void) | undefined;
  private rejectFn: ((reason?: unknown) => void) | undefined;
  public settled = false;

  public constructor() {
    let resolveCapture: ((value: T | PromiseLike<T>) => void) | undefined;
    let rejectCapture: ((reason?: unknown) => void) | undefined;
    this.promise = new Promise<T>((resolve, reject) => {
      resolveCapture = resolve;
      rejectCapture = reject;
    });
    this.resolveFn = resolveCapture;
    this.rejectFn = rejectCapture;
  }

  public resolve(value: T): void {
    if (this.settled) return;
    this.settled = true;
    const fn = this.resolveFn;
    this.resolveFn = undefined;
    this.rejectFn = undefined;
    if (fn !== undefined) {
      try {
        fn(value);
      } catch {
        // Never throw from test harness.
      }
    }
  }

  public reject(reason?: unknown): void {
    if (this.settled) return;
    this.settled = true;
    const fn = this.rejectFn;
    this.resolveFn = undefined;
    this.rejectFn = undefined;
    if (fn !== undefined) {
      try {
        fn(reason);
      } catch {
        // Never throw from test harness.
      }
    }
  }
}

export function makeNotFoundError(): Error {
  return Object.assign(new Error("not found"), {
    name: "NotFoundError",
    code: "not_found",
    status: 404,
    statusCode: 404,
  });
}

export function makeTransportError(): Error {
  return Object.assign(new Error("transport"), {
    name: "InternalServerError",
    status: 500,
    statusCode: 500,
  });
}

export interface FakeStoredRequest {
  readonly action: string;
  readonly resources: readonly string[];
  readonly source?: Readonly<{ type: "tool"; messageID: string; id: string }>;
}

/**
 * Fake permission store modeling request removal and documented session-wide
 * `reject` behavior. Only the verified public port methods are exposed.
 */
export class FakeOpenCode {
  public readonly locationDirectory: string;
  public readonly sessions = new Map<string, string>();
  public readonly requests = new Map<string, FakeStoredRequest>();
  public readonly replies: Array<{
    readonly sessionID: string;
    readonly requestID: string;
    readonly decision: "once" | "reject";
  }> = [];
  public readonly listCalls: string[] = [];
  public readonly getCalls: Array<{ readonly sessionID: string; readonly requestID: string }> = [];
  public readonly replyCalls: Array<{
    readonly sessionID: string;
    readonly requestID: string;
    readonly decision: string;
  }> = [];
  public readonly sessionGetCalls: string[] = [];
  public readonly contextCalls: string[] = [];
  public failNextReplies = 0;
  public failAllReplies = false;
  public readonly contextMessages = new Map<string, readonly unknown[]>();
  private replyGate: Deferred<void> | undefined;
  private replyGateSeen = 0;

  public constructor(locationDirectory = "/project") {
    this.locationDirectory = locationDirectory;
  }

  public addSession(sessionID: string, directory?: string): void {
    this.sessions.set(sessionID, directory ?? this.locationDirectory);
  }

  public addRequest(
    sessionID: string,
    requestID: string,
    action = "read",
    resources: readonly string[] = ["/project/notes.txt"],
  ): void {
    this.requests.set(`${sessionID}:${requestID}`, {
      action,
      resources: Object.freeze([...resources]),
    });
  }

  public addRequestWithSource(
    sessionID: string,
    requestID: string,
    action: string,
    resources: readonly string[],
    messageID: string,
    sourceID: string,
  ): void {
    this.requests.set(`${sessionID}:${requestID}`, {
      action,
      resources: Object.freeze([...resources]),
      source: Object.freeze({ type: "tool" as const, messageID, id: sourceID }),
    });
  }

  /** Simulate manual user resolution: the request disappears (404 afterwards). */
  public removeRequest(sessionID: string, requestID: string): boolean {
    return this.requests.delete(`${sessionID}:${requestID}`);
  }

  public hasRequest(sessionID: string, requestID: string): boolean {
    return this.requests.has(`${sessionID}:${requestID}`);
  }

  public pendingInSession(sessionID: string): number {
    let count = 0;
    for (const key of this.requests.keys()) {
      if (key.startsWith(`${sessionID}:`)) count += 1;
    }
    return count;
  }

  /** Delay the next N reply completions behind a gate (unload-during-reply). */
  public delayNextReplies(gate: Deferred<void>, count = 1): void {
    this.replyGate = gate;
    this.replyGateSeen = count;
  }

  public clearReplyGate(): void {
    this.replyGate = undefined;
    this.replyGateSeen = 0;
  }

  public async sessionGet(input: Readonly<{ sessionID: string }>): Promise<unknown> {
    this.sessionGetCalls.push(input.sessionID);
    const directory = this.sessions.get(input.sessionID);
    if (directory === undefined) throw makeNotFoundError();
    return Object.freeze({ id: input.sessionID, location: Object.freeze({ directory }) });
  }

  public async permissionList(input: Readonly<{ sessionID: string }>): Promise<unknown> {
    this.listCalls.push(input.sessionID);
    if (!this.sessions.has(input.sessionID)) throw makeNotFoundError();
    const result: unknown[] = [];
    for (const [key, stored] of this.requests) {
      const separator = key.indexOf(":");
      const storedSession = key.slice(0, separator);
      const storedRequest = key.slice(separator + 1);
      if (storedSession !== input.sessionID) continue;
      result.push(
        Object.freeze({
          id: storedRequest,
          sessionID: storedSession,
          action: stored.action,
          resources: Object.freeze([...stored.resources]),
          ...(stored.source === undefined ? {} : { source: stored.source }),
        }),
      );
    }
    return Object.freeze(result);
  }

  public async permissionGet(input: Readonly<{ sessionID: string; requestID: string }>): Promise<unknown> {
    this.getCalls.push({ sessionID: input.sessionID, requestID: input.requestID });
    const stored = this.requests.get(`${input.sessionID}:${input.requestID}`);
    if (stored === undefined) throw makeNotFoundError();
    return Object.freeze({
      id: input.requestID,
      sessionID: input.sessionID,
      action: stored.action,
      resources: Object.freeze([...stored.resources]),
      ...(stored.source === undefined ? {} : { source: stored.source }),
    });
  }

  public async permissionReply(
    input: Readonly<{ sessionID: string; requestID: string; decision: "once" | "reject" }>,
  ): Promise<void> {
    this.replyCalls.push({
      sessionID: input.sessionID,
      requestID: input.requestID,
      decision: input.decision,
    });
    if (input.decision !== "once" && input.decision !== "reject") {
      throw makeTransportError();
    }
    const gate = this.replyGate;
    if (gate !== undefined && this.replyGateSeen > 0) {
      this.replyGateSeen -= 1;
      if (this.replyGateSeen <= 0) this.replyGate = undefined;
      await gate.promise;
    }
    const key = `${input.sessionID}:${input.requestID}`;
    if (!this.requests.has(key)) throw makeNotFoundError();
    if (this.failAllReplies || this.failNextReplies > 0) {
      if (this.failNextReplies > 0) this.failNextReplies -= 1;
      throw makeTransportError();
    }
    this.replies.push({
      sessionID: input.sessionID,
      requestID: input.requestID,
      decision: input.decision,
    });
    if (input.decision === "reject") {
      for (const existing of [...this.requests.keys()]) {
        if (existing.startsWith(`${input.sessionID}:`)) this.requests.delete(existing);
      }
    } else {
      this.requests.delete(key);
    }
  }

  public async sessionContext(input: Readonly<{ sessionID: string }>): Promise<unknown> {
    this.contextCalls.push(input.sessionID);
    const preset = this.contextMessages.get(input.sessionID);
    if (preset !== undefined) return Object.freeze([...preset]);
    return Object.freeze([{ type: "user", id: "u1", text: "please read the project notes" }]);
  }

  /** This fake intentionally has no session-list, HTTP, Core, or SDK-client method. */
  public assertNoForbiddenSurface(): void {
    if ("sessionList" in this) throw new Error("forbidden sessionList present");
    if ("listAllSessions" in this) throw new Error("forbidden listAllSessions present");
    if ("httpRequest" in this) throw new Error("forbidden httpRequest present");
    if ("sdkClient" in this) throw new Error("forbidden sdkClient present");
  }
}

/**
 * Fake event source honoring abort and backpressure with terminate/reconnect.
 *
 * Each `subscribe` returns a fresh async iterable for one generation. Enqueued
 * events are delivered in order. `terminate` completes the current generation
 * (triggering coordinator reconnect), `fail` throws in it, and abort exits
 * immediately. Buffering is bounded to model backpressure.
 */
export class FakeEventStream {
  private pending: unknown[] = [];
  private waiters: Array<() => void> = [];
  private terminateRequested = false;
  private failure: unknown = undefined;
  private hasFailure = false;
  public subscribeCalls = 0;
  public readonly observedSignals: AbortSignal[] = [];
  private readonly maxBuffer: number;

  public constructor(maxBuffer = 256) {
    this.maxBuffer = maxBuffer;
  }

  public enqueue(event: unknown): void {
    if (this.pending.length >= this.maxBuffer) return;
    this.pending.push(event);
    this.flushWaiters();
  }

  public terminate(): void {
    this.terminateRequested = true;
    this.flushWaiters();
  }

  public fail(error: unknown): void {
    this.failure = error;
    this.hasFailure = true;
    this.flushWaiters();
  }

  public get pendingCount(): number {
    return this.pending.length;
  }

  private flushWaiters(): void {
    while (this.waiters.length > 0) {
      const waiter = this.waiters.shift();
      if (waiter === undefined) break;
      try {
        waiter();
      } catch {
        // Never throw from harness.
      }
    }
  }

  public subscribe(signal: AbortSignal): AsyncIterable<unknown> {
    this.subscribeCalls += 1;
    this.observedSignals.push(signal);
    const self = this;
    async function* generate(): AsyncGenerator<unknown, void, unknown> {
      for (;;) {
        if (signal.aborted) return;
        if (self.hasFailure) {
          const error = self.failure;
          self.hasFailure = false;
          self.failure = undefined;
          throw error;
        }
        if (self.pending.length > 0) {
          const next = self.pending.shift();
          if (next !== undefined) {
            yield next;
            continue;
          }
        }
        if (self.terminateRequested) {
          self.terminateRequested = false;
          return;
        }
        await new Promise<void>((resolve) => {
          const onWake = (): void => {
            try {
              signal.removeEventListener("abort", onAbort);
            } catch {
              // Ignore.
            }
            resolve();
          };
          const onAbort = (): void => {
            const index = self.waiters.indexOf(onWake);
            if (index >= 0) self.waiters.splice(index, 1);
            try {
              signal.removeEventListener("abort", onAbort);
            } catch {
              // Ignore.
            }
            resolve();
          };
          if (signal.aborted) {
            resolve();
            return;
          }
          self.waiters.push(onWake);
          try {
            signal.addEventListener("abort", onAbort, { once: true });
          } catch {
            resolve();
          }
        });
      }
    }
    return generate();
  }
}

export interface FakeJevCall {
  readonly index: number;
  readonly context: RedactedContext;
  readonly assessment: GuardrailAssessment;
}

function probsFor(labels: readonly string[], selected: string, selectedProb: number): Record<string, number> {
  const others = labels.filter((label) => label !== selected);
  const each = others.length === 0 ? 0 : (1 - selectedProb) / others.length;
  const probs: Record<string, number> = {};
  for (const label of labels) probs[label] = label === selected ? selectedProb : each;
  return probs;
}

function choiceFor(choice: string, labels: readonly string[], confidence: number, selectedProb: number): unknown {
  return Object.freeze({
    type: "choice",
    choice,
    confidence,
    probabilities: Object.freeze(probsFor(labels, choice, selectedProb)),
  });
}

function baseEvaluation(
  intentChoice: string,
  intentConfidence: number,
  riskChoice: string,
  riskConfidence: number,
  finalChoice: string,
  finalConfidence: number,
  finalProb: number,
): JevEvaluation {
  const intentLabels = ["supported", "contradicted", "unclear"] as const;
  const riskLabels = ["routine", "elevated", "high", "unclear"] as const;
  const finalLabels = ["allow_once", "deny", "manual_review"] as const;
  const intentProb = 0.95;
  const riskProb = 0.95;
  void intentConfidence;
  void riskConfidence;
  return Object.freeze({
    auxiliary: Object.freeze({
      intent_alignment: choiceFor(
        intentChoice,
        intentLabels as unknown as readonly string[],
        intentConfidence,
        intentProb,
      ),
      risk_class: choiceFor(riskChoice, riskLabels as unknown as readonly string[], riskConfidence, riskProb),
    }),
    final: choiceFor(finalChoice, finalLabels as unknown as readonly string[], finalConfidence, finalProb),
    modelVersion: "jev-test-v1",
    usage: Object.freeze({ inputTokens: 1, outputTokens: 1 }),
  }) as unknown as JevEvaluation;
}

/** High-confidence routine allow that satisfies default thresholds. */
export function makeAllowEvaluation(): JevEvaluation {
  return baseEvaluation("supported", 0.95, "routine", 0.95, "allow_once", 0.99, 0.96);
}

/** High-confidence deny that satisfies default thresholds. */
export function makeDenyEvaluation(): JevEvaluation {
  return baseEvaluation("supported", 0.95, "routine", 0.95, "deny", 0.97, 0.93);
}

/** Manual review at any confidence. */
export function makeManualEvaluation(): JevEvaluation {
  return baseEvaluation("unclear", 0.9, "unclear", 0.9, "manual_review", 0.9, 0.9);
}

/** Low-confidence allow that must stay manual. */
export function makeLowConfidenceAllow(): JevEvaluation {
  return baseEvaluation("supported", 0.95, "routine", 0.95, "allow_once", 0.79, 0.84);
}

/** High-risk allow that must stay manual. */
export function makeHighRiskAllow(): JevEvaluation {
  return baseEvaluation("supported", 0.95, "high", 0.95, "allow_once", 0.99, 0.96);
}

export function okResult(value: JevEvaluation): JevEvaluateResult {
  return Object.freeze({ ok: true as const, value });
}

export function errResult(category: ErrorReason): JevEvaluateResult {
  return Object.freeze({ ok: false as const, error: Object.freeze({ category }) });
}

/**
 * Deterministic fake Jev evaluator with concurrency tracking and captured
 * outbound states. The handler is fully scripted by tests; no timers or
 * network are used unless a test explicitly awaits a deferred gate.
 */
export class FakeJev {
  public readonly calls: FakeJevCall[] = [];
  public readonly contexts: RedactedContext[] = [];
  public active = 0;
  public maxActive = 0;
  public handler: (
    context: RedactedContext,
    assessment: GuardrailAssessment,
    options: Readonly<{ signal?: AbortSignal }>,
  ) => Promise<JevEvaluateResult>;

  public constructor(handler?: FakeJev["handler"]) {
    if (handler === undefined) {
      const fixed = makeAllowEvaluation();
      this.handler = async (): Promise<JevEvaluateResult> => okResult(fixed);
    } else {
      this.handler = handler;
    }
  }

  public async evaluate(
    context: RedactedContext,
    assessment: GuardrailAssessment,
    options: Readonly<{ signal?: AbortSignal }>,
  ): Promise<JevEvaluateResult> {
    const index = this.calls.length;
    this.calls.push({ index, context, assessment });
    this.contexts.push(context);
    this.active += 1;
    if (this.active > this.maxActive) this.maxActive = this.active;
    try {
      return await this.handler(context, assessment, options);
    } finally {
      this.active = Math.max(0, this.active - 1);
    }
  }

  public get callCount(): number {
    return this.calls.length;
  }
}

/** Valid `permission.asked` event at the installed `data` path. */
export function makeAskedEvent(
  sessionID: string,
  requestID: string,
  action = "read",
  resources: readonly string[] = ["/project/notes.txt"],
): unknown {
  return Object.freeze({
    type: "permission.asked",
    data: Object.freeze({
      id: requestID,
      sessionID,
      action,
      resources: Object.freeze([...resources]),
    }),
  });
}

/** Prompt-hook input shape accepted by the coordinator contract. */
export function makePromptInput(sessionID: string, text: string): unknown {
  return Object.freeze({
    sessionID,
    prompt: Object.freeze({ text }),
  });
}

/** Assert that no sentinel value appears in the JSON projection of a value. */
export function collectSentinelHits(value: unknown): string[] {
  let serialized = "";
  try {
    serialized = JSON.stringify(value) ?? "";
  } catch {
    return [];
  }
  const hits: string[] = [];
  for (const sentinel of Object.values(SENTINELS)) {
    if (serialized.includes(sentinel)) hits.push(sentinel);
  }
  return hits;
}

export function isValidTestID(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.trim().length > 0;
}

export function isFakeOpenCode(value: unknown): value is FakeOpenCode {
  return value instanceof FakeOpenCode;
}
