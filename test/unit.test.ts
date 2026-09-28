import { describe, expect, it, vi } from "vitest";

import {
  createAuditEvent,
  createAuditSink,
  sanitizeAuditEvent,
  sanitizeAuditMetadata,
  type AuditSink,
} from "../src/observability/audit.js";
import {
  sanitizeErrorCategory,
  sanitizeHttpError,
} from "../src/observability/errors.js";
import {
  fallbackIntent,
  RelevantIntentCache,
  selectRelevantIntent,
} from "../src/opencode/intent-cache.js";
import {
  canonicalRequestKey,
  extractPermissionAsked,
  extractPromptSession,
  extractPromptText,
  extractSessionDirectory,
  isValidAction,
  isValidID,
  locationsEqual,
  normalizeLocationDirectory,
  validatePermissionRequest,
} from "../src/opencode/contract.js";
import {
  getAuthoritativeRequest,
  getSessionDirectory,
  listPendingRequests,
  preReplyCheck,
  replyWithRecovery,
} from "../src/opencode/permissions.js";
import {
  classifyActionCategory,
  classifyResource,
  PermissionCoordinator,
  type CoordinatorOptions,
  type JevEvaluatePort,
} from "../src/opencode/coordinator.js";
import { DEFAULT_PLUGIN_CONFIG } from "../src/config.js";
import type { JevEvaluation } from "../src/domain.js";
import type { JevEvaluateResult } from "../src/jev/client.js";

const SECRET = "UNIT_SENTINEL_SECRET_012345678901234567890";
const PRIVATE = "UNIT_SENTINEL_PRIVATE_KEY_012345678901234567890";
const INTERNAL = "db.internal.corp";

function expectAbsent(value: unknown, sentinels: readonly string[] = [SECRET, PRIVATE, INTERNAL]): void {
  const serialized = JSON.stringify(value);
  for (const sentinel of sentinels) expect(serialized).not.toContain(sentinel);
}

describe("RelevantIntentCache", () => {
  it("replaces the latest admitted prompt and never concatenates prompts", () => {
    let now = 0;
    const cache = new RelevantIntentCache({ now: () => now, maxChars: 128 });
    cache.update("session", "first prompt about the repository");
    cache.update("session", "second prompt about the tests");

    const stored = cache.get("session");
    expect(stored?.text).toBe("second prompt about the tests");
    expect(stored?.text).not.toContain("first prompt");
    expect(stored?.revision).toBe(2);
  });

  it("redacts before retaining intent and never stores raw sentinels", () => {
    const cache = new RelevantIntentCache({ maxChars: 256 });
    const result = cache.update(
      "session",
      `Use ${SECRET} from https://alice:${SECRET}@${INTERNAL}/v1?token=${SECRET}#fragment and /home/alice/file`,
    );

    expect(result.admitted).toBe(true);
    expectAbsent(cache.snapshot());
    expect(cache.get("session")?.text).toContain("<redacted");
  });

  it("does not admit an unsafe projection", () => {
    const cache = new RelevantIntentCache();
    const result = cache.update("session", `-----BEGIN RSA PRIVATE KEY-----\n${PRIVATE}`);

    expect(result.admitted).toBe(false);
    expect(result.redactionComplete).toBe(false);
    expect(cache.get("session")).toBeUndefined();
  });

  it("enforces TTL and capacity deterministically with a fake clock", () => {
    let now = 100;
    const cache = new RelevantIntentCache({ maxEntries: 2, ttlMs: 10, now: () => now });
    cache.update("one", "one");
    now = 105;
    cache.update("two", "two");
    now = 106;
    cache.update("three", "three");

    expect(cache.get("one")).toBeUndefined();
    expect(cache.get("two")?.text).toBe("two");
    expect(cache.get("three")?.text).toBe("three");
    now = 116;
    expect(cache.get("three")).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it("cleans up expired entries and clears all state", () => {
    let now = 0;
    const cache = new RelevantIntentCache({ ttlMs: 5, now: () => now });
    cache.update("a", "alpha");
    cache.update("b", "beta");
    now = 5;
    expect(cache.cleanup()).toBe(2);
    cache.update("c", "gamma");
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.snapshot()).toEqual([]);
  });

  it("caps stored intent with head/tail markers", () => {
    const cache = new RelevantIntentCache({ maxChars: 32 });
    const result = cache.update("session", `HEAD${"x".repeat(100)}TAIL`);
    const stored = cache.get("session");

    expect(result.truncated).toBe(true);
    expect(stored?.truncated).toBe(true);
    expect(stored?.text).toContain("<truncated-head>");
    expect(stored?.text).toContain("<truncated-tail>");
    expect(stored?.text.length).toBeLessThanOrEqual(32);
  });

  it("expires entries with fake timers and no wall-clock dependency", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(1_000);
      const cache = new RelevantIntentCache({ ttlMs: 50 });
      cache.update("session", "fake timer intent");
      expect(cache.get("session")?.text).toBe("fake timer intent");

      vi.advanceTimersByTime(49);
      expect(cache.get("session")?.text).toBe("fake timer intent");

      vi.advanceTimersByTime(1);
      expect(cache.get("session")).toBeUndefined();
      expect(cache.cleanup()).toBe(0);
      expect(cache.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects non-string prompts without retaining raw values", () => {
    const cache = new RelevantIntentCache();
    for (const prompt of [undefined, null, 42, {}, []] as const) {
      const result = cache.update("session", prompt);
      expect(result.admitted).toBe(false);
    }
    expect(cache.get("session")).toBeUndefined();
    expectAbsent(cache.snapshot());
  });
});

describe("local fallback intent selection", () => {
  const context = {
    messages: [
      { id: "u1", role: "user", text: "first user request" },
      { id: "a1", role: "assistant", text: "assistant reasoning" },
      { id: "t1", role: "tool", text: "tool output" },
      { id: "u2", role: "user", text: "latest user request" },
      { id: "a2", role: "assistant", text: "latest assistant reasoning" },
    ],
  };

  it("chooses the nearest preceding user message for a source correlation", () => {
    const selected = selectRelevantIntent(context, { messageID: "a1", sourceID: "source-a1" });
    expect(selected?.text).toBe("first user request");
    expect(selected?.source).toBe("correlated");
    expect(selected?.text).not.toContain("assistant");
    expect(selected?.text).not.toContain("tool output");
  });

  it("chooses the latest user message when no source is supplied", () => {
    const selected = selectRelevantIntent(context);
    expect(selected?.text).toBe("latest user request");
    expect(selected?.source).toBe("latest");
  });

  it("never returns assistant, tool, or system content", () => {
    const selected = selectRelevantIntent({
      messages: [
        { role: "assistant", text: "assistant secret" },
        { role: "tool", text: "tool secret" },
        { role: "system", text: "system secret" },
      ],
    });
    expect(selected).toBeUndefined();
  });

  it("does not guess a latest prompt when a supplied correlation is absent", () => {
    const selected = selectRelevantIntent(context, { messageID: "missing", sourceID: "missing" });
    expect(selected).toBeUndefined();
  });

  it("redacts and bounds a selected user message immediately", () => {
    const selected = fallbackIntent(
      {
        messages: [
          {
            role: "user",
            text: `HEAD${SECRET}${"x".repeat(100)} https://${INTERNAL}/v1?token=${SECRET} TAIL`,
          },
        ],
      },
      undefined,
      { maxChars: 64 },
    );

    expect(selected?.text).toContain("<truncated-head>");
    expect(selected?.text).toContain("TAIL");
    expect(selected?.text.length).toBeLessThanOrEqual(64);
    expectAbsent(selected);
  });

  it("selects a single user message while omitting unknown shapes", () => {
    const selected = selectRelevantIntent({
      messages: [
        null,
        42,
        { role: "assistant", text: "assistant reasoning" },
        { unexpected: "shape" },
        { role: "user", text: "only user fragment" },
        { role: "tool", text: "tool output" },
      ],
    });

    expect(selected?.text).toBe("only user fragment");
    expect(selected?.source).toBe("latest");
    expectAbsent(selected);
  });

  it("omits unsafe user text instead of projecting it", () => {
    const selected = selectRelevantIntent({
      messages: [{ role: "user", text: `-----BEGIN RSA PRIVATE KEY-----\n${PRIVATE}` }],
    });
    expect(selected).toBeUndefined();
  });
});

describe("sanitized error primitives", () => {
  it("maps statuses and aborts to closed categories", () => {
    expect(sanitizeErrorCategory({ status: 401 })).toBe("api_authentication");
    expect(sanitizeErrorCategory({ status: 429 })).toBe("api_rate_limited");
    expect(sanitizeErrorCategory({ status: 503 })).toBe("api_server");
    expect(sanitizeErrorCategory({ name: "AbortError" })).toBe("api_aborted");
    expect(sanitizeErrorCategory({ name: "TimeoutError" })).toBe("api_timeout");
  });

  it("never returns a raw error message or stack", () => {
    const error = new Error(`${SECRET}: ${PRIVATE}`);
    const sanitized = sanitizeHttpError(error);
    expect(sanitized.category).toBe("unknown");
    expectAbsent(sanitized);
    expect(Object.keys(sanitized)).not.toContain("message");
    expect(Object.keys(sanitized)).not.toContain("stack");
  });
});

describe("closed audit boundary", () => {
  const requestMetadata = {
    type: "request" as const,
    action: "shell" as const,
    resourceCount: 2,
    kindCounts: { path: 1, url: 0, command: 1, query: 0, generic: 0, unknown: 0 },
    scopeCounts: { project: 2, external: 0, home: 0, system: 0, secret: 0, protected: 0, unknown: 0 },
    signals: [],
    flags: { redactionComplete: true, intentAvailable: true, truncated: false, parseStatus: "parsed" as const },
  };

  it("accepts and copies only the closed sanitized metadata union", () => {
    const record = createAuditEvent("request_seen", "manual", requestMetadata);
    expect(record).toBeDefined();
    expect(record?.metadata).toEqual(requestMetadata);
    expectAbsent(record);
  });

  it("rejects raw/unknown fields instead of serializing them", () => {
    expect(
      sanitizeAuditEvent({
        schemaVersion: 1,
        reason: "request_seen",
        outcome: "manual",
        rawSecret: SECRET,
      }),
    ).toBeUndefined();
    expect(
      sanitizeAuditMetadata({
        ...requestMetadata,
        rawSecret: SECRET,
      }),
    ).toBeUndefined();
    expect(
      sanitizeAuditEvent({
        schemaVersion: 1,
        reason: "jev_failed",
        outcome: "manual",
        error: new Error(SECRET),
      }),
    ).toBeUndefined();
  });

  it("does not log rejected records and never includes raw error messages", () => {
    const records: unknown[] = [];
    const sink = createAuditSink((event) => records.push(event));

    expect(
      sink.emit({
        schemaVersion: 1,
        reason: "request_manual",
        outcome: "manual",
        rawSecret: SECRET,
      }),
    ).toBe(false);
    expect(
      sink.emit({
        schemaVersion: 1,
        reason: "reply_failed",
        outcome: "manual",
        error: { message: SECRET },
      }),
    ).toBe(false);
    expect(records).toEqual([]);

    expect(
      sink.emit({
        schemaVersion: 1,
        reason: "jev_failed",
        outcome: "manual",
        error: "api_transport",
        metadata: { type: "error", category: "api_transport" },
      }),
    ).toBe(true);
    expect(records).toHaveLength(1);
    expectAbsent(records);
  });

  it("keeps Jev audit values bucketed and bounded", () => {
    const record = createAuditEvent("jev_completed", "manual", {
      type: "jev",
      modelVersion: "jev-test-v1",
      label: "manual_review",
      confidence: "medium",
      probability: "low",
      inputTokens: 12,
      outputTokens: 4,
    });
    expect(record).toBeDefined();
    expectAbsent(record, [SECRET]);
  });
});

// ---------------------------------------------------------------------------
// Slice 5: contract narrowing, permission port, coordinator, plugin wiring.
// All fakes are local to this file (offline, no network, no real key).
// ---------------------------------------------------------------------------

function makeNotFoundError(): Error {
  return Object.assign(new Error("not found"), {
    name: "NotFoundError",
    code: "not_found",
    status: 404,
    statusCode: 404,
  });
}

function makeTransportError(): Error {
  return Object.assign(new Error("transport"), {
    name: "InternalServerError",
    status: 500,
    statusCode: 500,
  });
}

function makePermissionEvent(sessionID: string, requestID: string): unknown {
  return Object.freeze({
    type: "permission.asked",
    data: Object.freeze({
      id: requestID,
      sessionID,
      action: "read",
      resources: Object.freeze(["/project/notes.txt"]),
    }),
  });
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

function makeJevAllow(): JevEvaluation {
  const intentLabels = ["supported", "contradicted", "unclear"] as const;
  const riskLabels = ["routine", "elevated", "high", "unclear"] as const;
  const finalLabels = ["allow_once", "deny", "manual_review"] as const;
  return Object.freeze({
    auxiliary: Object.freeze({
      intent_alignment: choiceFor("supported", intentLabels as unknown as readonly string[], 0.95, 0.95),
      risk_class: choiceFor("routine", riskLabels as unknown as readonly string[], 0.95, 0.95),
    }),
    final: choiceFor("allow_once", finalLabels as unknown as readonly string[], 0.99, 0.96),
    modelVersion: "jev-test-v1",
    usage: Object.freeze({ inputTokens: 1, outputTokens: 1 }),
  }) as unknown as JevEvaluation;
}

function makeJevDeny(): JevEvaluation {
  const intentLabels = ["supported", "contradicted", "unclear"] as const;
  const riskLabels = ["routine", "elevated", "high", "unclear"] as const;
  const finalLabels = ["allow_once", "deny", "manual_review"] as const;
  return Object.freeze({
    auxiliary: Object.freeze({
      intent_alignment: choiceFor("supported", intentLabels as unknown as readonly string[], 0.95, 0.95),
      risk_class: choiceFor("routine", riskLabels as unknown as readonly string[], 0.95, 0.95),
    }),
    final: choiceFor("deny", finalLabels as unknown as readonly string[], 0.97, 0.93),
    modelVersion: "jev-test-v1",
    usage: Object.freeze({ inputTokens: 1, outputTokens: 1 }),
  }) as unknown as JevEvaluation;
}

function makeJevManual(): JevEvaluation {
  const intentLabels = ["supported", "contradicted", "unclear"] as const;
  const riskLabels = ["routine", "elevated", "high", "unclear"] as const;
  const finalLabels = ["allow_once", "deny", "manual_review"] as const;
  return Object.freeze({
    auxiliary: Object.freeze({
      intent_alignment: choiceFor("unclear", intentLabels as unknown as readonly string[], 0.9, 0.9),
      risk_class: choiceFor("unclear", riskLabels as unknown as readonly string[], 0.9, 0.9),
    }),
    final: choiceFor("manual_review", finalLabels as unknown as readonly string[], 0.9, 0.9),
    modelVersion: "jev-test-v1",
    usage: Object.freeze({ inputTokens: 1, outputTokens: 1 }),
  }) as unknown as JevEvaluation;
}

interface FakeStoredRequest {
  readonly action: string;
  readonly resources: readonly string[];
  readonly source?: Readonly<{ type: "tool"; messageID: string; id: string }>;
}

class FakeOpenCode {
  public readonly locationDirectory: string;
  public readonly sessions = new Map<string, string>();
  public readonly requests = new Map<string, FakeStoredRequest>();
  public readonly replies: Array<{ sessionID: string; requestID: string; decision: "once" | "reject" }> = [];
  public readonly listCalls: string[] = [];
  public readonly getCalls: Array<{ sessionID: string; requestID: string }> = [];
  public readonly replyCalls: Array<{ sessionID: string; requestID: string; decision: string }> = [];
  public readonly sessionGetCalls: string[] = [];
  public failNextReplies = 0;
  public failAllReplies = false;
  public readonly contextMessages = new Map<string, unknown[]>();

  public constructor(locationDirectory = "/project") {
    this.locationDirectory = locationDirectory;
  }

  public addSession(sessionID: string, directory?: string): void {
    this.sessions.set(sessionID, directory ?? this.locationDirectory);
  }

  public addRequest(sessionID: string, requestID: string, action = "read", resources: readonly string[] = ["/project/notes.txt"]): void {
    this.requests.set(`${sessionID}:${requestID}`, {
      action,
      resources: Object.freeze([...resources]),
    });
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
    this.replyCalls.push({ sessionID: input.sessionID, requestID: input.requestID, decision: input.decision });
    if (input.decision !== "once" && input.decision !== "reject") {
      throw makeTransportError();
    }
    const key = `${input.sessionID}:${input.requestID}`;
    if (!this.requests.has(key)) throw makeNotFoundError();
    if (this.failAllReplies || this.failNextReplies > 0) {
      if (this.failNextReplies > 0) this.failNextReplies -= 1;
      throw makeTransportError();
    }
    this.replies.push({ sessionID: input.sessionID, requestID: input.requestID, decision: input.decision });
    if (input.decision === "reject") {
      // Documented session-wide behavior: reject clears every pending request in the session.
      for (const existing of [...this.requests.keys()]) {
        if (existing.startsWith(`${input.sessionID}:`)) this.requests.delete(existing);
      }
    } else {
      this.requests.delete(key);
    }
  }

  public async sessionContext(input: Readonly<{ sessionID: string }>): Promise<unknown> {
    const preset = this.contextMessages.get(input.sessionID);
    if (preset !== undefined) return Object.freeze([...preset]);
    return Object.freeze([{ type: "user", id: "u1", text: "please read the project notes" }]);
  }
}

async function settle(coordinator: PermissionCoordinator, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (coordinator.getStats().inFlight === 0) return;
    if (Date.now() - start > timeoutMs) throw new Error("settle timeout");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function makeCoordinator(
  fake: FakeOpenCode,
  overrides: {
    jev?: JevEvaluation | undefined;
    jevResult?: JevEvaluateResult | undefined;
    jevCalls?: { count: number } | undefined;
    maxQueueSize?: number | undefined;
    maxConcurrency?: number | undefined;
    auditEvents?: unknown[] | undefined;
  } = {},
): { coordinator: PermissionCoordinator; intentCache: RelevantIntentCache; audit: AuditSink } {
  const auditEvents: unknown[] = overrides.auditEvents ?? [];
  const audit: AuditSink = createAuditSink((event) => {
    auditEvents.push(event);
  });
  const intentCache = new RelevantIntentCache();
  const counter = overrides.jevCalls ?? { count: 0 };
  const fixed: JevEvaluation = overrides.jev ?? makeJevAllow();
  const fixedResult: JevEvaluateResult =
    overrides.jevResult ?? Object.freeze({ ok: true as const, value: fixed });
  const jevEvaluate: JevEvaluatePort = async (context, assessment, options) => {
    counter.count += 1;
    void context;
    void assessment;
    void options;
    return fixedResult;
  };
  const options: CoordinatorOptions = {
    locationDirectory: fake.locationDirectory,
    maxConcurrency: overrides.maxConcurrency ?? DEFAULT_PLUGIN_CONFIG.maxConcurrency,
    maxQueueSize: overrides.maxQueueSize ?? DEFAULT_PLUGIN_CONFIG.maxQueueSize,
    reconcileIntervalMs: DEFAULT_PLUGIN_CONFIG.reconcileIntervalMs,
    thresholds: DEFAULT_PLUGIN_CONFIG.thresholds,
    limits: {
      commandChars: DEFAULT_PLUGIN_CONFIG.limits.commandChars,
      intentChars: DEFAULT_PLUGIN_CONFIG.limits.intentChars,
      resources: DEFAULT_PLUGIN_CONFIG.limits.resources,
      resourceChars: DEFAULT_PLUGIN_CONFIG.limits.resourceChars,
    },
    ports: {
      sessionGet: (input) => fake.sessionGet(input),
      permissionList: (input) => fake.permissionList(input),
      permissionGet: (input) => fake.permissionGet(input),
      permissionReply: (input) => fake.permissionReply(input),
      sessionContext: (input) => fake.sessionContext(input),
    },
    intentCache,
    jevEvaluate,
    audit,
  };
  const coordinator = new PermissionCoordinator(options);
  return { coordinator, intentCache, audit };
}

describe("contract narrowing", () => {
  it("extracts permission.asked ids from the installed data path", () => {
    expect(extractPermissionAsked(makePermissionEvent("s1", "r1"))).toEqual({
      sessionID: "s1",
      requestID: "r1",
    });
    expect(extractPermissionAsked({ type: "session.created", data: {} })).toBeUndefined();
    expect(extractPermissionAsked({ type: "permission.asked", data: { id: "", sessionID: "s" } })).toBeUndefined();
    expect(extractPermissionAsked({ type: "permission.asked", data: { id: "r", sessionID: "" } })).toBeUndefined();
    expect(extractPermissionAsked(undefined)).toBeUndefined();
  });

  it("validates request envelopes without copying raw metadata", () => {
    const good = validatePermissionRequest({
      id: "r1",
      sessionID: "s1",
      action: "read",
      resources: ["/project/a.txt"],
      metadata: { secret: SECRET },
      message: SECRET,
    });
    expect(good.ok).toBe(true);
    if (good.ok === true) {
      expect(good.value.requestID).toBe("r1");
      expectAbsent(good.value);
    }
    expect(validatePermissionRequest({ id: "", sessionID: "s", action: "read", resources: [] }).ok).toBe(false);
    expect(validatePermissionRequest({ id: "r", sessionID: "s", action: "", resources: [] }).ok).toBe(false);
    expect(validatePermissionRequest({ id: "r", sessionID: "s", action: "read", resources: "nope" }).ok).toBe(
      false,
    );
  });

  it("normalizes locations and builds canonical keys", () => {
    expect(normalizeLocationDirectory("/project/")).toBe("/project");
    expect(locationsEqual("/project/", "/project")).toBe(true);
    expect(locationsEqual("/project", "/other")).toBe(false);
    expect(canonicalRequestKey("/project/", "s", "r")).toBe("/project|s|r");
    expect(isValidID("ok")).toBe(true);
    expect(isValidID("")).toBe(false);
    expect(isValidID("   ")).toBe(false);
    expect(isValidAction("shell")).toBe(true);
    expect(isValidAction("")).toBe(false);
  });

  it("extracts session locations and prompt inputs without raw leakage", () => {
    expect(extractSessionDirectory({ location: { directory: "/project/" } })).toBe("/project");
    expect(extractSessionDirectory({ location: { directory: "" } })).toBeUndefined();
    expect(extractPromptSession({ sessionID: "s1", prompt: { text: "hi" } })).toBe("s1");
    expect(extractPromptText({ sessionID: "s1", prompt: { text: "hello" } })).toBe("hello");
    expect(extractPromptText({ sessionID: "s1" })).toBeUndefined();
    expectAbsent(extractSessionDirectory({ location: { directory: "/project" } }));
  });

  it("classifies actions and resources without allowlist skipping", () => {
    expect(classifyActionCategory("read")).toBe("read");
    expect(classifyActionCategory("shell")).toBe("shell");
    expect(classifyActionCategory("custom-tool")).toBe("other");
    expect(classifyActionCategory("mcp__tool")).toBe("mcp");
    const command = classifyResource("echo hi", "shell", "/project");
    expect(command.kind).toBe("command");
    const path = classifyResource("/project/a.txt", "read", "/project");
    expect(path.kind).toBe("path");
    const url = classifyResource("https://example.com/x", "webfetch", "/project");
    expect(url.kind).toBe("url");
  });

  it("classifies bare file-action values as project-relative paths", () => {
    for (const action of ["read", "edit", "glob", "grep"] as const) {
      for (const value of ["scratch.txt", "notes.md", "a"]) {
        const resource = classifyResource(value, action, "/project");
        expect(resource.kind).toBe("path");
        expect(resource.scope).toBe("project");
        expect(resource.value).toBe(value);
        expect(Object.isFrozen(resource)).toBe(true);
      }
    }
  });

  it("pins non-file-action classification behavior", () => {
    const command = classifyResource("echo hi", "shell", "/project");
    expect(command.kind).toBe("command");
    expect(Object.isFrozen(command)).toBe(true);

    const fileUrl = classifyResource("https://example.com/x", "read", "/project");
    expect(fileUrl.kind).toBe("url");
    expect(fileUrl.scope).toBe("external");

    const webUrl = classifyResource("https://example.com/x", "webfetch", "/project");
    expect(webUrl.kind).toBe("url");
    expect(webUrl.scope).toBe("external");

    const query = classifyResource("how do I test this", "websearch", "/project");
    expect(query.kind).toBe("query");
    expect(query.scope).toBe("external");

    const projectAbsolute = classifyResource("/project/a.txt", "read", "/project");
    expect(projectAbsolute.kind).toBe("path");
    expect(projectAbsolute.scope).toBe("project");

    const homeAbsolute = classifyResource("/home/alice/notes.txt", "read", "/project");
    expect(homeAbsolute.kind).toBe("path");
    expect(homeAbsolute.scope).toBe("home");
  });
});

describe("permission port", () => {
  it("resolves in-scope sessions and rejects unknown sessions as external", async () => {
    const fake = new FakeOpenCode("/project");
    fake.addSession("s1", "/project");
    const inScope = await getSessionDirectory(
      { sessionGet: (input) => fake.sessionGet(input) },
      "s1",
      "/project",
    );
    expect(inScope.status).toBe("in_scope");
    fake.addSession("foreign", "/other");
    const out = await getSessionDirectory(
      { sessionGet: (input) => fake.sessionGet(input) },
      "foreign",
      "/project",
    );
    expect(out.status).toBe("out_of_scope");
    const missing = await getSessionDirectory(
      { sessionGet: (input) => fake.sessionGet(input) },
      "missing",
      "/project",
    );
    expect(missing.status).toBe("external");
  });

  it("lists only validated pending requests for known sessions", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1");
    const pending = await listPendingRequests({ permissionList: (input) => fake.permissionList(input) }, "s1");
    expect(pending).toHaveLength(1);
    expect(pending[0]?.requestID).toBe("r1");
    const unknown = await listPendingRequests({ permissionList: (input) => fake.permissionList(input) }, "nope");
    expect(unknown).toEqual([]);
  });

  it("treats missing requests as external and malformed as malformed", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1");
    const pending = await getAuthoritativeRequest(
      { permissionGet: (input) => fake.permissionGet(input) },
      "s1",
      "r1",
    );
    expect(pending.status).toBe("pending");
    const missing = await getAuthoritativeRequest(
      { permissionGet: (input) => fake.permissionGet(input) },
      "s1",
      "absent",
    );
    expect(missing.status).toBe("external");
    const pre = await preReplyCheck({ permissionGet: (input) => fake.permissionGet(input) }, "s1", "absent");
    expect(pre.status).toBe("external");
  });

  it("retries the same decision once after transport failure then leaves pending", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1");
    fake.failNextReplies = 1;
    const ports = {
      permissionGet: (input: Readonly<{ sessionID: string; requestID: string }>) => fake.permissionGet(input),
      permissionReply: (input: Readonly<{ sessionID: string; requestID: string; decision: "once" | "reject" }>) =>
        fake.permissionReply(input),
    };
    const recovered = await replyWithRecovery(ports, "s1", "r1", "once");
    expect(recovered.status).toBe("replied");
    expect(fake.replyCalls).toHaveLength(2);
    expect(fake.replyCalls[0]?.decision).toBe("once");
    expect(fake.replyCalls[1]?.decision).toBe("once");

    fake.addRequest("s1", "r2");
    fake.failAllReplies = true;
    const stuck = await replyWithRecovery(ports, "s1", "r2", "reject");
    expect(stuck.status).toBe("pending");
    // Bounded: exactly one retry, never a third attempt.
    expect(fake.replyCalls.filter((call) => call.requestID === "r2")).toHaveLength(2);
  });

  it("maps 404 replies to external without retry", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    const ports = {
      permissionGet: (input: Readonly<{ sessionID: string; requestID: string }>) => fake.permissionGet(input),
      permissionReply: (input: Readonly<{ sessionID: string; requestID: string; decision: "once" | "reject" }>) =>
        fake.permissionReply(input),
    };
    const result = await replyWithRecovery(ports, "s1", "missing", "once");
    expect(result.status).toBe("external");
    expect(fake.replyCalls).toHaveLength(1);
  });
});

describe("coordinator state machine", () => {
  it("processes a valid event to once with one Jev call and one reply", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/notes.txt"]);
    const auditEvents: unknown[] = [];
    const { coordinator, intentCache } = makeCoordinator(fake, { auditEvents });
    intentCache.update("s1", "please read the project notes");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(fake.replies).toEqual([{ sessionID: "s1", requestID: "r1", decision: "once" }]);
    expectAbsent(auditEvents);
    coordinator.dispose();
  });

  it("ignores non-permission variants and malformed payloads", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1");
    const counter = { count: 0 };
    const { coordinator } = makeCoordinator(fake, { jevCalls: counter });
    coordinator.notifyEvent({ type: "session.created", data: { sessionID: "s1" } });
    coordinator.notifyEvent({ type: "permission.asked", data: { sessionID: "", id: "" } });
    coordinator.notifyEvent(undefined);
    await settle(coordinator);
    expect(counter.count).toBe(0);
    expect(fake.replies).toEqual([]);
    coordinator.dispose();
  });

  it("ignores out-of-location events without Jev or reply", async () => {
    const fake = new FakeOpenCode("/project");
    fake.addSession("foreign", "/other");
    fake.requests.set("foreign:r1", { action: "read", resources: Object.freeze(["/other/a.txt"]) });
    const counter = { count: 0 };
    const auditEvents: unknown[] = [];
    const { coordinator } = makeCoordinator(fake, { jevCalls: counter, auditEvents });
    coordinator.notifyEvent(makePermissionEvent("foreign", "r1"));
    await settle(coordinator);
    expect(counter.count).toBe(0);
    expect(fake.replies).toEqual([]);
    expect(coordinator.getKnownSessionIDs()).not.toContain("foreign");
    expectAbsent(auditEvents);
    coordinator.dispose();
  });

  it("suppresses duplicate events to one Jev call and one reply", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    intentCache.update("s1", "please read the project file");
    const event = makePermissionEvent("s1", "r1");
    coordinator.notifyEvent(event);
    coordinator.notifyEvent(event);
    coordinator.notifyEvent(event);
    await settle(coordinator);
    expect(counter.count).toBe(1);
    expect(fake.replies).toHaveLength(1);
    // Post-terminal duplicates stay suppressed via tombstones.
    coordinator.notifyEvent(event);
    await settle(coordinator);
    expect(counter.count).toBe(1);
    expect(fake.replies).toHaveLength(1);
    coordinator.dispose();
  });

  it("reconciles known sessions after reconnect without duplicate replies", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    intentCache.update("s1", "please read the project file");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(fake.replies).toHaveLength(1);
    const listsBefore = fake.listCalls.length;
    await coordinator.reconcileAll();
    expect(fake.listCalls.length).toBeGreaterThan(listsBefore);
    expect(fake.listCalls).toContain("s1");
    expect(counter.count).toBe(1);
    expect(fake.replies).toHaveLength(1);
    coordinator.dispose();
  });

  it("reconciles only known sessions and never enumerates unknown sessions", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("known");
    fake.addRequest("known", "r1", "read", ["/project/a.txt"]);
    fake.addSession("unknown-old", "/project");
    fake.addRequest("unknown-old", "r9", "read", ["/project/old.txt"]);
    const { coordinator, intentCache } = makeCoordinator(fake);
    intentCache.update("known", "please read the project file");
    coordinator.notifyEvent(makePermissionEvent("known", "r1"));
    await settle(coordinator);
    fake.listCalls.length = 0;
    await coordinator.reconcileAll();
    expect(fake.listCalls).toContain("known");
    expect(fake.listCalls).not.toContain("unknown-old");
    coordinator.dispose();
  });

  it("learns prompt-hook sessions and makes them eligible for reconciliation", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("prompted");
    fake.addRequest("prompted", "r1", "read", ["/project/a.txt"]);
    const counter = { count: 0 };
    const { coordinator } = makeCoordinator(fake, { jevCalls: counter });
    await coordinator.notifyPrompt({ sessionID: "prompted", messageID: "m1", prompt: { text: "please read it" } });
    expect(coordinator.getKnownSessionIDs()).toContain("prompted");
    // Background catch-up is fire-and-forget; drive reconciliation explicitly for determinism.
    await coordinator.reconcileAll();
    await settle(coordinator);
    // Prompt learning triggers best-effort reconciliation of its pending request.
    expect(counter.count).toBe(1);
    expect(fake.replies).toHaveLength(1);
    await coordinator.notifyPrompt({ sessionID: "missing", messageID: "m2", prompt: { text: "hi" } });
    expect(coordinator.getKnownSessionIDs()).not.toContain("missing");
    coordinator.dispose();
  });

  it("never replies for missing, resolved, or 404 paths", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    intentCache.update("s1", "please read it");
    coordinator.notifyEvent(makePermissionEvent("s1", "absent"));
    await settle(coordinator);
    expect(counter.count).toBe(0);
    expect(fake.replies).toEqual([]);
    expect(fake.replyCalls).toEqual([]);
    coordinator.dispose();
  });

  it("follows bounded same-decision recovery on reply transport failure", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    fake.failNextReplies = 1;
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    intentCache.update("s1", "please read the project file");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(counter.count).toBe(1);
    expect(fake.replies).toHaveLength(1);
    expect(fake.replyCalls).toHaveLength(2);
    expect(fake.replyCalls[0]?.decision).toBe("once");
    expect(fake.replyCalls[1]?.decision).toBe("once");
    coordinator.dispose();
  });

  it("leaves pending after exhausted reply retries without a third attempt", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    fake.failAllReplies = true;
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    intentCache.update("s1", "please read the project file");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(counter.count).toBe(1);
    expect(fake.replies).toEqual([]);
    expect(fake.replyCalls).toHaveLength(2);
    coordinator.dispose();
  });

  it("models session-wide reject: peers re-check and do not reply again", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    fake.addRequest("s1", "r2", "read", ["/project/b.txt"]);
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, {
      jev: makeJevDeny(),
      jevCalls: counter,
    });
    intentCache.update("s1", "please handle the session");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    coordinator.notifyEvent(makePermissionEvent("s1", "r2"));
    await settle(coordinator);
    expect(counter.count).toBe(2);
    expect(fake.replies).toHaveLength(1);
    expect(fake.replies[0]?.decision).toBe("reject");
    expect(fake.replyCalls).toHaveLength(1);
    coordinator.dispose();
  });

  it("leaves manual Jev outcomes pending without reply", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    const { coordinator, intentCache } = makeCoordinator(fake, { jev: makeJevManual() });
    intentCache.update("s1", "please read it");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(fake.replies).toEqual([]);
    expect(fake.replyCalls).toEqual([]);
    coordinator.dispose();
  });

  it("rejects hard-deny requests without spending a Jev call", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "shell", ["rm -rf /tmp/target"]);
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, {
      jev: makeJevAllow(),
      jevCalls: counter,
    });
    intentCache.update("s1", "please clean up");
    coordinator.notifyEvent({
      type: "permission.asked",
      data: { id: "r1", sessionID: "s1", action: "shell", resources: ["rm -rf /tmp/target"] },
    });
    await settle(coordinator);
    expect(counter.count).toBe(0);
    expect(fake.replies).toEqual([{ sessionID: "s1", requestID: "r1", decision: "reject" }]);
    coordinator.dispose();
  });

  it("treats queue overflow as manual without network calls", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    fake.addRequest("s1", "r2", "read", ["/project/b.txt"]);
    const counter = { count: 0 };
    const { coordinator, intentCache } = makeCoordinator(fake, {
      jevCalls: counter,
      maxQueueSize: 1,
      maxConcurrency: 1,
    });
    intentCache.update("s1", "please read both");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    coordinator.notifyEvent(makePermissionEvent("s1", "r2"));
    await settle(coordinator);
    // One slot means the second discovery overflows without a Jev call.
    expect(counter.count).toBeLessThanOrEqual(1);
    expect(fake.replies.length).toBeLessThanOrEqual(1);
    coordinator.dispose();
  });

  it("keeps audit sanitized with no raw secrets, paths, or prompts", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/notes.txt"]);
    const auditEvents: unknown[] = [];
    const { coordinator, intentCache } = makeCoordinator(fake, { auditEvents });
    intentCache.update("s1", "please read the project notes");
    coordinator.notifyEvent(makePermissionEvent("s1", "r1"));
    await settle(coordinator);
    expect(auditEvents.length).toBeGreaterThan(0);
    expectAbsent(auditEvents);
    coordinator.dispose();
  });

  it("clears timers and data on dispose and prevents post-cleanup transitions", async () => {
    const fake = new FakeOpenCode();
    fake.addSession("s1");
    fake.addRequest("s1", "r1", "read", ["/project/a.txt"]);
    const counter = { count: 0 };
    const subscribeCalls: number[] = [];
    const { coordinator, intentCache } = makeCoordinator(fake, { jevCalls: counter });
    const withStream = new PermissionCoordinator({
      locationDirectory: fake.locationDirectory,
      maxConcurrency: 1,
      maxQueueSize: 16,
      reconcileIntervalMs: 20,
      thresholds: DEFAULT_PLUGIN_CONFIG.thresholds,
      limits: {
        commandChars: DEFAULT_PLUGIN_CONFIG.limits.commandChars,
        intentChars: DEFAULT_PLUGIN_CONFIG.limits.intentChars,
        resources: DEFAULT_PLUGIN_CONFIG.limits.resources,
        resourceChars: DEFAULT_PLUGIN_CONFIG.limits.resourceChars,
      },
      ports: {
        sessionGet: (input) => fake.sessionGet(input),
        permissionList: (input) => fake.permissionList(input),
        permissionGet: (input) => fake.permissionGet(input),
        permissionReply: (input) => fake.permissionReply(input),
        sessionContext: (input) => fake.sessionContext(input),
      },
      intentCache,
      jevEvaluate: async () => {
        counter.count += 1;
        return Object.freeze({ ok: true as const, value: makeJevAllow() });
      },
      audit: createAuditSink(() => {}),
      subscribeEvents: (signal) => {
        subscribeCalls.push(1);
        void signal;
        async function* empty(): AsyncIterable<unknown> {
          // End immediately to exercise reconnect + reconcile without hanging.
        }
        return empty();
      },
    });
    withStream.startEventLoop();
    withStream.startInterval();
    withStream.dispose();
    expect(withStream.isDisposed).toBe(true);
    expect(withStream.getStats()).toEqual({ knownSessions: 0, inFlight: 0, tombstones: 0 });
    const listsBefore = fake.listCalls.length;
    withStream.notifyEvent(makePermissionEvent("s1", "r1"));
    await withStream.reconcileAll();
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(counter.count).toBe(0);
    expect(fake.listCalls.length).toBe(listsBefore);
    expect(subscribeCalls.length).toBeGreaterThanOrEqual(1);
    coordinator.dispose();
    withStream.dispose();
  });
});

describe("plugin wiring", () => {
  it("exposes the stable package id and setup", async () => {
    const pluginModule = await import("../src/index.js");
    const plugin = pluginModule.default as unknown as { id: unknown; setup: unknown };
    expect(plugin.id).toBe("opencode-jev-permissions");
    expect(typeof plugin.setup).toBe("function");
    const pluginImpl = await import("../src/opencode/plugin.js");
    expect(pluginImpl.PLUGIN_ID).toBe("opencode-jev-permissions");
  });

  it("honors info, warn, and off production audit levels", async () => {
    const pluginImpl = await import("../src/opencode/plugin.js");
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const ordinary = { schemaVersion: 1, reason: "request_seen", outcome: "manual" };
      const warning = { schemaVersion: 1, reason: "stream_error", outcome: "skipped" };

      expect(pluginImpl.createPluginAudit("info").emit(ordinary)).toBe(true);
      expect(info).toHaveBeenCalledTimes(1);

      const warnAudit = pluginImpl.createPluginAudit("warn");
      expect(warnAudit.emit(ordinary)).toBe(true);
      expect(info).toHaveBeenCalledTimes(1);
      expect(warnAudit.emit(warning)).toBe(true);
      expect(warn).toHaveBeenCalledTimes(1);

      const offAudit = pluginImpl.createPluginAudit("off");
      expect(offAudit.emit(ordinary)).toBe(true);
      expect(info).toHaveBeenCalledTimes(1);
      expect(warn).toHaveBeenCalledTimes(1);

      const serialized = String(info.mock.calls[0]?.[0]);
      expect(serialized).toContain('"plugin":"opencode-jev-permissions"');
      expect(serialized).toContain('"reason":"request_seen"');
    } finally {
      info.mockRestore();
      warn.mockRestore();
    }
  });

  it("enters safe no-op for invalid options without subscribing or hooking", async () => {
    const pluginImpl = await import("../src/opencode/plugin.js");
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    let subscribed = false;
    let hooked = false;
    const fakeContext = {
      location: { directory: "/project" },
      options: { model: "not-jev", maxConcurrency: 999 },
      event: {
        subscribe: (_input: unknown) => {
          subscribed = true;
          async function* empty(): AsyncIterable<unknown> {}
          return empty();
        },
      },
      session: {
        hook: async (_name: string, _callback: unknown) => {
          hooked = true;
          return { dispose: async (): Promise<void> => {} };
        },
      },
      permission: {
        list: async (): Promise<unknown> => [],
        get: async (): Promise<unknown> => {
          throw makeNotFoundError();
        },
        reply: async (): Promise<void> => {},
      },
    } as unknown as Parameters<typeof pluginImpl.setup>[0];
    try {
      const cleanup = await pluginImpl.setup(fakeContext);
      expect(subscribed).toBe(false);
      expect(hooked).toBe(false);
      expect(typeof cleanup).toBe("function");
      expect(warning).toHaveBeenCalledTimes(1);
      await cleanup();
    } finally {
      warning.mockRestore();
    }
  });

  it("rejects unknown option keys and non-Jev models as invalid", async () => {
    const pluginImpl = await import("../src/opencode/plugin.js");
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    const base = {
      location: { directory: "/project" },
      event: {
        subscribe: () => {
          async function* empty(): AsyncIterable<unknown> {}
          return empty();
        },
      },
      session: {
        hook: async () => ({ dispose: async (): Promise<void> => {} }),
      },
      permission: {
        list: async (): Promise<unknown> => [],
        get: async (): Promise<unknown> => {
          throw makeNotFoundError();
        },
        reply: async (): Promise<void> => {},
      },
    };
    try {
      for (const options of [
        { disableGuardrails: true },
        { model: "gpt-4" },
        { thresholds: { allowConfidence: 0.5, elevatedAllowConfidence: 0.4 } },
      ]) {
        let subscribed = false;
        const context = {
          ...base,
          options,
          event: {
            subscribe: (_input: unknown) => {
              subscribed = true;
              async function* empty(): AsyncIterable<unknown> {}
              return empty();
            },
          },
        } as unknown as Parameters<typeof pluginImpl.setup>[0];
        const cleanup = await pluginImpl.setup(context);
        expect(subscribed).toBe(false);
        await cleanup();
      }
      expect(warning).toHaveBeenCalledTimes(3);
    } finally {
      warning.mockRestore();
    }
  });

  it("subscribes before reconciliation and cleans up prompt registration", async () => {
    const pluginImpl = await import("../src/opencode/plugin.js");
    const order: string[] = [];
    let disposed = false;
    const fakeContext = {
      location: { directory: "/project" },
      options: { pluginLogLevel: "off" },
      event: {
        subscribe: (_input: unknown) => {
          order.push("subscribe");
          async function* empty(): AsyncIterable<unknown> {}
          return empty();
        },
      },
      session: {
        get: async (): Promise<unknown> => {
          throw makeNotFoundError();
        },
        context: async (): Promise<unknown> => [],
        hook: async (_name: string, _callback: unknown) => {
          order.push("hook");
          return {
            dispose: async (): Promise<void> => {
              disposed = true;
            },
          };
        },
      },
      permission: {
        list: async (): Promise<unknown> => {
          order.push("list");
          return [];
        },
        get: async (): Promise<unknown> => {
          throw makeNotFoundError();
        },
        reply: async (): Promise<void> => {},
      },
    } as unknown as Parameters<typeof pluginImpl.setup>[0];
    const cleanup = await pluginImpl.setup(fakeContext);
    expect(order[0]).toBe("hook");
    expect(order).toContain("subscribe");
    await cleanup();
    expect(disposed).toBe(true);
  });
});
