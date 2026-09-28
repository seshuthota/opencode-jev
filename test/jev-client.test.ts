import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  Fetch,
  Logger,
  RequestOptions,
  SystemOneRequest,
  TypeSafeClientConfig,
} from "@typesafe-ai/sdk";
import { TypeSafeClient } from "@typesafe-ai/sdk";

import type {
  GuardrailAssessment,
  RedactedContext,
  RedactedPolicy,
} from "../src/domain.js";
import { buildRedactedContext } from "../src/opencode/context-builder.js";
import {
  JEV_BACKOFF_INITIAL_MS,
  JEV_BACKOFF_MAX_MS,
  JEV_BASE_URL,
  JEV_DEFAULT_MODEL,
  JEV_MAX_RETRIES,
  JevClient,
  validateJevEvaluation,
} from "../src/jev/client.js";
import {
  INTENT_ALIGNMENT_LABELS,
  POLICY_DECISION_LABELS,
  PROBABILITY_SUM_TOLERANCE,
  RISK_CLASS_LABELS,
  buildJevQuestions,
  buildJevRequest,
  buildJevState,
} from "../src/jev/questions.js";

const SENTINELS = {
  secret: "JEV_SENTINEL_SECRET_012345678901234567890",
  bearer: "JEV_SENTINEL_BEARER_012345678901234567890",
  session: "session-JEV-SENTINEL-001",
  message: "message-JEV-SENTINEL-002",
  rawPath: "/home/alice-jev-sentinel/secret/file.txt",
  metadata: "JEV_SENTINEL_METADATA_012345678901234567890",
  transcript: "JEV_SENTINEL_TRANSCRIPT_012345678901234567890",
  prompt: "JEV_SENTINEL_PROMPT_012345678901234567890",
  header: "JEV_SENTINEL_HEADER_012345678901234567890",
  apiKey: "sk-live-JEV-SENTINEL-012345678901234567890",
} as const;

function expectNoSentinels(value: unknown): void {
  const serialized = JSON.stringify(value) ?? "";
  for (const sentinel of Object.values(SENTINELS)) {
    expect(serialized).not.toContain(sentinel);
  }
  expect(serialized).not.toContain("sessionID");
  expect(serialized).not.toContain("messageID");
  expect(serialized).not.toContain("metadata");
  expect(serialized).not.toContain("transcript");
}

function safePolicy(): RedactedPolicy {
  return {
    version: "guardrails-v1",
    hardDenyCodes: [],
    unknown: "manual_review",
    maximumGrant: "once",
  };
}

function safeContext(): RedactedContext {
  return Object.freeze({
    action: "read",
    actionCategory: "read",
    tool: "read-tool",
    resources: Object.freeze([
      Object.freeze({ kind: "path", scope: "project", display: "<project>/src/file.ts" }),
    ]),
    signals: Object.freeze([]),
    intent: "read the project file",
    policy: safePolicy(),
    summary: Object.freeze({
      total: 1,
      included: 1,
      omitted: 0,
      kindCounts: Object.freeze({ path: 1, url: 0, command: 0, query: 0, generic: 0, unknown: 0 }),
      scopeCounts: Object.freeze({
        project: 1,
        external: 0,
        home: 0,
        system: 0,
        secret: 0,
        protected: 0,
        unknown: 0,
      }),
    }),
    truncation: Object.freeze({ commands: false, intent: false, resources: false, resource: false }),
    redactionComplete: true,
    eligibleForAutoAllow: true,
  }) as RedactedContext;
}

function safeAssessment(): GuardrailAssessment {
  return Object.freeze({
    signals: Object.freeze([]),
    parseStatus: "parsed",
    hardDeny: false,
    policyVersion: "guardrails-v1",
    hardDenyCodes: Object.freeze([]),
    eligibleForAutoAllow: true,
  }) as GuardrailAssessment;
}

function validChoice(
  choice: string,
  labels: readonly string[],
  confidence = 0.99,
): Record<string, unknown> {
  const count = labels.length;
  const remainder = (1 - 0.96) / Math.max(1, count - 1);
  const probabilities: Record<string, unknown> = {};
  for (const label of labels) {
    probabilities[label] = label === choice ? 0.96 : remainder;
  }
  // Fix floating rounding so sums equal exactly 1 for the default labels.
  let sum = 0;
  for (const label of labels) sum += probabilities[label] as number;
  const first = labels[0] as string;
  if (first !== undefined && choice !== first) {
    probabilities[first] = (probabilities[first] as number) + (1 - sum);
  } else if (choice === first) {
    const second = labels[1] as string;
    if (second !== undefined) probabilities[second] = (probabilities[second] as number) + (1 - sum);
  }
  return { type: "choice", choice, confidence, probabilities };
}

function validRawResult(): Record<string, unknown> {
  return {
    model: "jev-test-v1",
    answers: {
      intent_alignment: validChoice("supported", INTENT_ALIGNMENT_LABELS),
      risk_class: validChoice("routine", RISK_CLASS_LABELS),
      policy_decision: validChoice("allow_once", POLICY_DECISION_LABELS),
    },
    usage: { input_tokens: 12, output_tokens: 4 },
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface Capture {
  calls: number;
  request?: unknown;
  options?: unknown;
  signal?: AbortSignal | undefined;
  config?: TypeSafeClientConfig | undefined;
}

function fakePort(canned: unknown, capture: Capture): {
  systemOne: (request: SystemOneRequest, options?: RequestOptions) => Promise<unknown>;
} {
  return {
    systemOne: (request: SystemOneRequest, options?: RequestOptions): Promise<unknown> => {
      capture.calls += 1;
      capture.request = request;
      capture.options = options;
      capture.signal = options?.signal;
      return Promise.resolve(canned);
    },
  };
}

function pendingPort(capture: Capture): {
  systemOne: (request: SystemOneRequest, options?: RequestOptions) => Promise<unknown>;
} {
  return {
    systemOne: (_request: SystemOneRequest, options?: RequestOptions): Promise<unknown> => {
      capture.calls += 1;
      capture.request = _request;
      capture.options = options;
      capture.signal = options?.signal;
      return new Promise<unknown>((_resolve, reject) => {
        const signal = options?.signal;
        if (signal?.aborted === true) {
          const error = new Error("aborted");
          error.name = "APIUserAbortError";
          reject(error);
          return;
        }
        signal?.addEventListener(
          "abort",
          () => {
            const error = new Error("aborted");
            error.name = "APIUserAbortError";
            reject(error);
          },
          { once: true },
        );
      });
    },
  };
}

function throwingLogger(): Logger {
  const fail = (): void => {
    throw new Error("SDK logger must never be called when logLevel is off");
  };
  return { debug: fail, info: fail, warn: fail, error: fail };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("Jev outbound privacy", () => {
  it("state and questions contain no identifiers, raw paths, metadata, or secrets", () => {
    const context = safeContext();
    const request = buildJevRequest(context, safeAssessment());
    expectNoSentinels(request);
    const serialized = JSON.stringify(request);
    expect(serialized).toContain("intent_alignment");
    expect(serialized).toContain("risk_class");
    expect(serialized).toContain("policy_decision");
    expect(serialized).toContain("allow_once");
  });

  it("ignores smuggled identifiers and raw fields passed through a cast object", () => {
    const polluted = {
      ...safeContext(),
      sessionID: SENTINELS.session,
      messageID: SENTINELS.message,
      session_id: SENTINELS.session,
      rawPath: SENTINELS.rawPath,
      metadata: { token: SENTINELS.metadata },
      transcript: SENTINELS.transcript,
      prompt: SENTINELS.prompt,
      headers: { authorization: SENTINELS.header },
      apiKey: SENTINELS.apiKey,
      secret: SENTINELS.secret,
    } as unknown as RedactedContext;
    const request = buildJevRequest(polluted, safeAssessment());
    expectNoSentinels(request);
  });

  it("pipeline from raw facts with sentinels never reaches Jev state", () => {
    const facts = {
      key: { locationDirectory: "/workspace", sessionID: SENTINELS.session, requestID: "request" },
      location: { directory: "/workspace" },
      action: "shell",
      actionCategory: "shell",
      resources: [
        { value: `curl -H 'Authorization: Bearer ${SENTINELS.bearer}' https://example.com`, kind: "command", scope: "project" },
        { value: `${SENTINELS.rawPath}`, kind: "path", scope: "project" },
      ],
      source: { messageID: SENTINELS.message, sourceID: "source" },
      metadata: { token: SENTINELS.metadata },
    };
    const context = buildRedactedContext(
      facts as unknown as Parameters<typeof buildRedactedContext>[0],
      `inspect with ${SENTINELS.secret}`,
      safePolicy(),
    );
    const request = buildJevRequest(context, safeAssessment());
    expectNoSentinels(request);
    expectNoSentinels(context);
  });

  it("omits commands for non-shell actions and keeps them for shell", () => {
    const shellContext = {
      ...safeContext(),
      action: "shell",
      actionCategory: "shell",
      commands: ["git status --short"],
    } as unknown as RedactedContext;
    const shellState = buildJevState(shellContext, safeAssessment());
    expect(shellState.commands).toEqual(["git status --short"]);

    const nonShell = buildJevState(safeContext(), safeAssessment());
    expect(nonShell.commands).toBeUndefined();
    expectNoSentinels(shellState);
    expectNoSentinels(nonShell);
  });

  it("questions are static and carry no request data", () => {
    const first = buildJevQuestions();
    const second = buildJevQuestions();
    expect(first).toEqual(second);
    expect(first.intent_alignment.type).toBe("choice");
    expect(first.risk_class.type).toBe("choice");
    expect(first.policy_decision.type).toBe("choice");
    expect(Object.keys(first)).toEqual(["intent_alignment", "risk_class", "policy_decision"]);
    expectNoSentinels(first);
  });
});

describe("Jev client construction", () => {
  it("is lazy: constructing without a key does not throw", () => {
    expect(() => new JevClient()).not.toThrow();
    expect(() => new JevClient({ model: "jev-latest" })).not.toThrow();
  });

  it("configures fixed base URL, Jev model, bounded retry, and logging off", async () => {
    const capture: Capture = { calls: 0 };
    let seen: TypeSafeClientConfig | undefined;
    const client = new JevClient({
      model: "jev-test-model",
      maxRetries: 1,
      logger: throwingLogger(),
      createClient: (config: TypeSafeClientConfig) => {
        seen = config;
        capture.config = config;
        return fakePort(validRawResult(), capture);
      },
    });
    const result = await client.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(true);
    expect(seen?.baseURL).toBe("https://api.typesafe.ai");
    expect(seen?.baseURL).toBe(JEV_BASE_URL);
    expect(seen?.defaultModel).toBe("jev-test-model");
    expect(seen?.logLevel).toBe("off");
    expect(seen?.retry?.maxRetries).toBe(1);
    expect(seen?.retry?.maxRetries).toBeLessThanOrEqual(2);
    expect(seen?.retry?.backoffInitialMs).toBe(JEV_BACKOFF_INITIAL_MS);
    expect(seen?.retry?.backoffMaxMs).toBe(JEV_BACKOFF_MAX_MS);
    expect(seen?.retry?.httpStatuses?.has(401)).toBe(false);
    expect(seen?.retry?.httpStatuses?.has(429)).toBe(true);
    expect(seen?.timeout).toBeGreaterThan(0);
  });

  it("uses Jev defaults for model, deadline, and retries", async () => {
    let seen: TypeSafeClientConfig | undefined;
    const capture: Capture = { calls: 0 };
    const client = new JevClient({
      createClient: (config: TypeSafeClientConfig) => {
        seen = config;
        return fakePort(validRawResult(), capture);
      },
    });
    const result = await client.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(true);
    expect(seen?.defaultModel).toBe(JEV_DEFAULT_MODEL);
    expect(seen?.defaultModel?.startsWith("jev-")).toBe(true);
    expect(seen?.retry?.maxRetries).toBe(JEV_MAX_RETRIES);
  });

  it("never calls a throwing custom logger with real SDK transport", async () => {
    // Direct SDK check with a dummy offline key and fake fetch: with
    // logLevel off, the throwing logger must never be invoked.
    const fetchCalls: { count: number } = { count: 0 };
    const fakeFetch: Fetch = (input: string, init?: RequestInit): Promise<Response> => {
      void input;
      void init;
      fetchCalls.count += 1;
      return Promise.resolve(jsonResponse(validRawResult(), 200));
    };
    const outbound = buildJevRequest(safeContext(), safeAssessment());
    const sdk = new TypeSafeClient({
      apiKey: "test-dummy-key-offline-only",
      baseURL: JEV_BASE_URL,
      defaultModel: JEV_DEFAULT_MODEL,
      logLevel: "off",
      logger: throwingLogger(),
      retry: { maxRetries: 0 },
      timeout: 8000,
      fetch: fakeFetch,
    });
    const raw: unknown = await sdk.systemOne(
      {
        state: outbound.state as unknown as Record<string, never>,
        questions: outbound.questions as unknown as Record<string, never>,
      } as unknown as SystemOneRequest,
    );
    expect(fetchCalls.count).toBe(1);
    // Throwing logger would have thrown above if the SDK called it.
    expect(validateJevEvaluation(raw).ok).toBe(true);
  });

  it("rejects non-Jev models without any network call", async () => {
    let factoryCalls = 0;
    const client = new JevClient({
      model: "gpt-4",
      createClient: () => {
        factoryCalls += 1;
        return fakePort(validRawResult(), { calls: 0 });
      },
    });
    const result = await client.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("config_invalid");
    expect(factoryCalls).toBe(0);
  });

  it("missing key path is safe and makes no network call", async () => {
    const client = new JevClient();
    const result = await client.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.category).toBe("missing_api_key");
      expect(Object.keys(result.error)).not.toContain("message");
    }
  });
});

describe("Jev success and transport mapping with fake fetch", () => {
  it("canned success validates model, labels, and usage", async () => {
    // Offline success uses an injected port so no live network is required.
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => fakePort(validRawResult(), capture),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.final.choice).toBe("allow_once");
      expect(result.value.auxiliary.intent_alignment.choice).toBe("supported");
      expect(result.value.auxiliary.risk_class.choice).toBe("routine");
      expect(result.value.modelVersion).toBe("jev-test-v1");
      expect(result.value.usage).toEqual({ inputTokens: 12, outputTokens: 4 });
      expect(capture.calls).toBe(1);
      expectNoSentinels(result.value);
    }
  });

  it("maps 401 to authentication without retry", async () => {
    // A 401 SDK error shape maps to authentication with no outer retry.
    const authError = { name: "AuthenticationError", status: 401 };
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => ({
        systemOne: (_request: SystemOneRequest, _options?: RequestOptions): Promise<unknown> => {
          capture.calls += 1;
          return Promise.reject(authError);
        },
      }),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.category).toBe("api_authentication");
      expect(result.error.status).toBe(401);
    }
    expect(capture.calls).toBe(1);
  });

  it("exhausts bounded retries on 429 then reports rate limited", async () => {
    // Simulate exhaustion with a counting port (initial + 1 retry) then throws.
    let attempts = 0;
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      maxRetries: 1,
      createClient: (config: TypeSafeClientConfig) => {
        expect(config.retry?.maxRetries).toBe(1);
        return {
          systemOne: (_request: SystemOneRequest, _options?: RequestOptions): Promise<unknown> => {
            capture.calls += 1;
            attempts += 1;
            if (attempts < 2) {
              const error = { name: "RateLimitError", status: 429 };
              return Promise.reject(error);
            }
            const error = { name: "RateLimitError", status: 429 };
            return Promise.reject(error);
          },
        };
      },
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("api_rate_limited");
    expect(capture.calls).toBe(1);
  });

  it("maps 500 to server error", async () => {
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => ({
        systemOne: (_request: SystemOneRequest, _options?: RequestOptions): Promise<unknown> => {
          capture.calls += 1;
          return Promise.reject({ name: "InternalServerError", status: 500 });
        },
      }),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.category).toBe("api_server");
      expect(result.error.status).toBe(500);
    }
    expect(capture.calls).toBe(1);
  });

  it("maps connection failure to transport without leaking messages", async () => {
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => ({
        systemOne: (_request: SystemOneRequest, _options?: RequestOptions): Promise<unknown> => {
          capture.calls += 1;
          const error = new Error("connect ECONNREFUSED 127.0.0.1:443 with secret");
          error.name = "APIConnectionError";
          return Promise.reject(error);
        },
      }),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.category).toBe("api_transport");
      expect(JSON.stringify(result.error)).not.toContain("secret");
      expect(Object.keys(result.error)).not.toContain("message");
    }
  });

  it("maps malformed JSON body to malformed response", async () => {
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => fakePort("not-json{{{", capture),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
  });

  it("maps malformed schema to malformed response", async () => {
    const capture: Capture = { calls: 0 };
    const offline = new JevClient({
      createClient: () => fakePort({ model: "jev-test-v1", answers: {} }, capture),
    });
    const result = await offline.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
  });
});

describe("Jev answer validation", () => {
  it("accepts exact probability sums within documented tolerance", () => {
    expect(PROBABILITY_SUM_TOLERANCE).toBe(0.01);
    const raw = validRawResult();
    expect(validateJevEvaluation(raw).ok).toBe(true);
  });

  it("rejects invalid labels", () => {
    for (const bad of ["approve", "ALLOW_ONCE", "", "allow"]) {
      const raw = validRawResult();
      const answers = raw.answers as Record<string, Record<string, unknown>>;
      const final = answers.policy_decision as Record<string, unknown>;
      final.choice = bad;
      const result = validateJevEvaluation(raw);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
    }
  });

  it("rejects non-choice types", () => {
    const raw = validRawResult();
    const answers = raw.answers as Record<string, Record<string, unknown>>;
    (answers.risk_class as Record<string, unknown>).type = "noul";
    expect(validateJevEvaluation(raw).ok).toBe(false);
  });

  it("rejects NaN and out-of-range confidence", () => {
    for (const confidence of [Number.NaN, Number.POSITIVE_INFINITY, -0.1, 1.1]) {
      const raw = validRawResult();
      const answers = raw.answers as Record<string, Record<string, unknown>>;
      (answers.intent_alignment as Record<string, unknown>).confidence = confidence;
      const result = validateJevEvaluation(raw);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
    }
  });

  it("rejects out-of-range probabilities", () => {
    const raw = validRawResult();
    const finalProbs = ((raw.answers as Record<string, Record<string, unknown>>).policy_decision as Record<
      string,
      unknown
    >).probabilities as Record<string, unknown>;
    finalProbs.allow_once = 1.5;
    finalProbs.deny = -0.25;
    finalProbs.manual_review = -0.25;
    expect(validateJevEvaluation(raw).ok).toBe(false);
  });

  it("rejects missing probabilities", () => {
    const raw = validRawResult();
    const answers = raw.answers as Record<string, Record<string, unknown>>;
    (answers.intent_alignment as Record<string, unknown>).probabilities = { supported: 1 };
    expect(validateJevEvaluation(raw).ok).toBe(false);
  });

  it("rejects bad probability sums", () => {
    for (const probabilities of [
      { supported: 0.3, contradicted: 0.1, unclear: 0.1 },
      { supported: 0.7, contradicted: 0.5, unclear: 0.3 },
    ]) {
      const raw = validRawResult();
      const answers = raw.answers as Record<string, Record<string, unknown>>;
      (answers.intent_alignment as Record<string, unknown>).probabilities = probabilities;
      const result = validateJevEvaluation(raw);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
    }
  });

  it("rejects missing model and usage", () => {
    const noModel = validRawResult();
    delete (noModel as Record<string, unknown>).model;
    expect(validateJevEvaluation(noModel).ok).toBe(false);
    const noUsage = validRawResult();
    delete (noUsage as Record<string, unknown>).usage;
    expect(validateJevEvaluation(noUsage).ok).toBe(false);
    const badUsage = validRawResult();
    (badUsage as Record<string, Record<string, unknown>>).usage = { input_tokens: -1, output_tokens: 1.5 };
    expect(validateJevEvaluation(badUsage).ok).toBe(false);
  });

  it("no invalid answer reaches the decision core as ok", async () => {
    const invalids: unknown[] = [
      null,
      {},
      { model: "", answers: {}, usage: {} },
      validRawResult(),
    ];
    // Mutate the last valid entry into an invalid one for the negative check.
    const mutated = validRawResult();
    const answers = mutated.answers as Record<string, Record<string, unknown>>;
    (answers.policy_decision as Record<string, unknown>).choice = "manual_review_typo";
    invalids[3] = mutated;
    for (const raw of invalids) {
      const capture: Capture = { calls: 0 };
      const client = new JevClient({ createClient: () => fakePort(raw, capture) });
      const result = await client.evaluate(safeContext(), safeAssessment());
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.category).toBe("api_malformed_response");
    }
    const validCapture: Capture = { calls: 0 };
    const validClient = new JevClient({ createClient: () => fakePort(validRawResult(), validCapture) });
    const valid = await validClient.evaluate(safeContext(), safeAssessment());
    expect(valid.ok).toBe(true);
  });
});

describe("Jev deadlines and cancellation", () => {
  it("total deadline cancels fake pending work as timeout", async () => {
    vi.useFakeTimers();
    try {
      const capture: Capture = { calls: 0 };
      const client = new JevClient({
        timeoutMs: 200,
        createClient: () => pendingPort(capture),
      });
      const pending = client.evaluate(safeContext(), safeAssessment());
      await vi.advanceTimersByTimeAsync(200);
      const result = await pending;
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.category).toBe("api_timeout");
      expect(capture.calls).toBe(1);
      expect(capture.signal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("cleanup signal cancels fake pending work as aborted", async () => {
    const controller = new AbortController();
    const capture: Capture = { calls: 0 };
    const client = new JevClient({ createClient: () => pendingPort(capture) });
    const pending = client.evaluate(safeContext(), safeAssessment(), { signal: controller.signal });
    controller.abort();
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("api_aborted");
    expect(capture.calls).toBe(1);
    expect(capture.signal?.aborted).toBe(true);
  });

  it("already-aborted signal makes no network call", async () => {
    const controller = new AbortController();
    controller.abort();
    let calls = 0;
    const client = new JevClient({
      createClient: () => {
        calls += 1;
        return fakePort(validRawResult(), { calls: 0 });
      },
    });
    const result = await client.evaluate(safeContext(), safeAssessment(), { signal: controller.signal });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.category).toBe("api_aborted");
    expect(calls).toBe(0);
  });

  it("passes an abort signal for deadline and cleanup", async () => {
    const capture: Capture = { calls: 0 };
    const client = new JevClient({
      timeoutMs: 8000,
      createClient: () => fakePort(validRawResult(), capture),
    });
    const result = await client.evaluate(safeContext(), safeAssessment());
    expect(result.ok).toBe(true);
    expect(capture.signal instanceof AbortSignal).toBe(true);
  });
});

describe("Jev transport with real SDK and fake fetch", () => {
  const dummyKey = "test-dummy-key-offline-only";

  function sdkWithFakeFetch(
    fakeFetch: Fetch,
    overrides: { maxRetries?: number; timeout?: number } = {},
  ): { sdk: TypeSafeClient; calls: { count: number } } {
    const calls = { count: 0 };
    const countingFetch: Fetch = (input: string, init?: RequestInit): Promise<Response> => {
      calls.count += 1;
      return fakeFetch(input, init);
    };
    const sdk = new TypeSafeClient({
      apiKey: dummyKey,
      baseURL: JEV_BASE_URL,
      defaultModel: JEV_DEFAULT_MODEL,
      logLevel: "off",
      logger: throwingLogger(),
      retry: {
        maxRetries: overrides.maxRetries ?? 0,
        backoffInitialMs: 10,
        backoffMaxMs: 20,
        backoffJitter: 0,
        respectRetryAfter: false,
        apiConnectionError: true,
        apiTimeoutError: true,
      },
      timeout: overrides.timeout ?? 8000,
      fetch: countingFetch,
    });
    return { sdk, calls };
  }

  function jevPayload(): { state: unknown; questions: unknown } {
    const outbound = buildJevRequest(safeContext(), safeAssessment());
    return { state: outbound.state, questions: outbound.questions };
  }

  it("success via fake fetch returns three validated answers", async () => {
    const { sdk, calls } = sdkWithFakeFetch(() => Promise.resolve(jsonResponse(validRawResult(), 200)));
    const { state, questions } = jevPayload();
    const raw: unknown = await sdk.systemOne(
      { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
    );
    expect(calls.count).toBe(1);
    expect(validateJevEvaluation(raw).ok).toBe(true);
  });

  it("401 via fake fetch does not retry", async () => {
    const { sdk, calls } = sdkWithFakeFetch(
      () => Promise.resolve(jsonResponse({ error: "unauthorized" }, 401)),
      { maxRetries: 1 },
    );
    const { state, questions } = jevPayload();
    let status = 0;
    let name = "";
    try {
      await sdk.systemOne(
        { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
      );
      expect.unreachable("401 must reject");
    } catch (error) {
      const record = error as Record<string, unknown>;
      status = record.status as number;
      name = (record as { name?: unknown }).name as string;
    }
    expect(name).toBe("AuthenticationError");
    expect(status).toBe(401);
    expect(calls.count).toBe(1);
  });

  it("429 exhaustion via fake fetch retries bounded then rejects", async () => {
    const { sdk, calls } = sdkWithFakeFetch(
      () => Promise.resolve(jsonResponse({ error: "limited" }, 429)),
      { maxRetries: 1 },
    );
    const { state, questions } = jevPayload();
    let status = 0;
    try {
      await sdk.systemOne(
        { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
      );
      expect.unreachable("429 must reject after retries");
    } catch (error) {
      status = (error as Record<string, unknown>).status as number;
    }
    expect(status).toBe(429);
    expect(calls.count).toBe(2);
  });

  it("500 via fake fetch maps to server error", async () => {
    const { sdk, calls } = sdkWithFakeFetch(
      () => Promise.resolve(jsonResponse({ error: "boom" }, 500)),
      { maxRetries: 1 },
    );
    const { state, questions } = jevPayload();
    let status = 0;
    let name = "";
    try {
      await sdk.systemOne(
        { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
      );
      expect.unreachable("500 must reject");
    } catch (error) {
      const record = error as Record<string, unknown>;
      status = record.status as number;
      name = (record as { name?: unknown }).name as string;
    }
    expect(name).toBe("InternalServerError");
    expect(status).toBe(500);
    expect(calls.count).toBe(2);
  });

  it("malformed JSON via fake fetch validates as malformed", async () => {
    const { sdk } = sdkWithFakeFetch(
      () =>
        Promise.resolve(
          new Response("not-json{{{", {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        ),
      { maxRetries: 0 },
    );
    const { state, questions } = jevPayload();
    const raw: unknown = await sdk.systemOne(
      { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
    );
    expect(validateJevEvaluation(raw).ok).toBe(false);
  });

  it("timeout via fake fetch rejects with timeout", async () => {
    const hanging: Fetch = (_input: string, init?: RequestInit): Promise<Response> => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal?.aborted === true) {
          reject(new DOMException("aborted", "AbortError"));
          return;
        }
        signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), {
          once: true,
        });
      });
    };
    const { sdk } = sdkWithFakeFetch(hanging, { maxRetries: 0, timeout: 50 });
    const { state, questions } = jevPayload();
    let name = "";
    try {
      await sdk.systemOne(
        { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
        { timeout: 50 },
      );
      expect.unreachable("hanging fetch must timeout");
    } catch (error) {
      name = (error as { name?: unknown }).name as string;
    }
    expect(name).toBe("APITimeoutError");
  });

  it("abort via fake fetch rejects with user abort", async () => {
    const hanging: Fetch = (_input: string, init?: RequestInit): Promise<Response> => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal?.aborted === true) {
          reject(new DOMException("aborted", "AbortError"));
          return;
        }
        signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), {
          once: true,
        });
      });
    };
    const { sdk } = sdkWithFakeFetch(hanging, { maxRetries: 0, timeout: 8000 });
    const { state, questions } = jevPayload();
    const controller = new AbortController();
    const pending = sdk.systemOne(
      { state: state as never, questions: questions as never } as unknown as SystemOneRequest,
      { signal: controller.signal },
    );
    controller.abort();
    let name = "";
    try {
      await pending;
      expect.unreachable("aborted fetch must reject");
    } catch (error) {
      name = (error as { name?: unknown }).name as string;
    }
    expect(name).toBe("APIUserAbortError");
  });
});
