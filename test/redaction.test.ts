import { describe, expect, it } from "vitest";

import type { PermissionFacts, RedactedPolicy } from "../src/domain.js";
import { buildJevRequest } from "../src/jev/questions.js";
import {
  buildRedactedContext,
  ContextBuilder,
} from "../src/opencode/context-builder.js";
import {
  projectPathDetailed,
  redactCommand,
  redactText,
  redactTextDetailed,
  redactUrl,
} from "../src/redaction/index.js";

const SENTINELS = {
  apiKey: "sk-live-SENTINEL-012345678901234567890123",
  bearer: "SENTINEL_BEARER_TOKEN_012345678901234567890",
  basic: "SENTINEL_BASIC_AUTH_012345678901234567890",
  cookie: "SENTINEL_COOKIE_VALUE_012345678901234567890",
  password: "SENTINEL_PASSWORD_012345678901234567890",
  signature: "SENTINEL_SIGNATURE_012345678901234567890",
  privateKey: "SENTINEL_PRIVATE_KEY_012345678901234567890",
  fragment: "SENTINEL_FRAGMENT_012345678901234567890",
  username: "alice-machine",
  internalHost: "db.internal.corp",
  homeRoot: "/home/alice-machine",
  highEntropy: "A9bC7dE2fG4hI6jK8lM1nO3pQ5rS7tU9vW",
} as const;

const POLICY: RedactedPolicy = {
  version: "test-v1",
  hardDenyCodes: [],
  unknown: "manual_review",
  maximumGrant: "once",
};

function expectNoSentinels(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const sentinel of Object.values(SENTINELS)) {
    expect(serialized).not.toContain(sentinel);
  }
}

function facts(overrides: Partial<PermissionFacts> & Record<string, unknown> = {}): PermissionFacts {
  return Object.assign(
    {
      key: { locationDirectory: "/workspace", sessionID: "session", requestID: "request" },
      location: { directory: "/workspace" },
      action: "shell",
      actionCategory: "shell",
      resources: [],
    },
    overrides,
  );
}

describe("pure text and command redaction", () => {
  it("removes API keys, authorization, cookies, and sensitive flags", () => {
    const input = [
      `curl --header 'Authorization: Bearer ${SENTINELS.bearer}'`,
      `--password=${SENTINELS.password}`,
      `Cookie: session=${SENTINELS.cookie}`,
      `api_key=${SENTINELS.apiKey}`,
    ].join(" ");
    const result = redactTextDetailed(input);

    expect(result.complete).toBe(true);
    expect(result.value).toContain("curl");
    expect(result.value).toContain("--header");
    expect(result.value).toContain("--password");
    expectNoSentinels(result);
  });

  it("redacts basic authorization and password/token flag values", () => {
    const result = redactTextDetailed(
      `curl --user name:password --token ${SENTINELS.bearer} -H 'Authorization: Basic ${SENTINELS.basic}'`,
    );

    expect(result.value).toContain("curl");
    expect(result.value).toContain("--user");
    expectNoSentinels(result);
  });

  it("removes complete and malformed private-key blocks", () => {
    const complete = redactTextDetailed(
      `-----BEGIN RSA PRIVATE KEY-----\n${SENTINELS.privateKey}\n-----END RSA PRIVATE KEY-----`,
    );
    const malformed = redactTextDetailed(`-----BEGIN OPENSSH PRIVATE KEY-----\n${SENTINELS.privateKey}`);

    expect(complete.complete).toBe(true);
    expect(complete.value).toContain("<redacted-private-key>");
    expect(malformed.complete).toBe(false);
    expect(malformed.value).not.toContain(SENTINELS.privateKey);
  });

  it("redacts environment dumps while retaining harmless variable names", () => {
    const result = redactTextDetailed(
      `env\nAPI_KEY=${SENTINELS.apiKey}\nNORMAL_SETTING=visible-value\nPASSWORD=${SENTINELS.password}`,
    );

    expect(result.value).toContain("API_KEY=");
    expect(result.value).toContain("NORMAL_SETTING=");
    expect(result.value).not.toContain("visible-value");
    expectNoSentinels(result);
  });

  it("redacts high-entropy literals but preserves ordinary command context", () => {
    const result = redactTextDetailed(
      `git status --short && echo ${SENTINELS.highEntropy} && npm test -- --runInBand`,
    );

    expect(result.value).toContain("git status --short");
    expect(result.value).toContain("npm test");
    expect(result.value).toContain("--runInBand");
    expect(result.value).not.toContain(SENTINELS.highEntropy);
  });

  it("caps text with deterministic head and tail markers", () => {
    const input = `${"a".repeat(80)}ACTION-TAIL`;
    const first = redactTextDetailed(input, { maxChars: 64 });
    const second = redactTextDetailed(input, { maxChars: 64 });

    expect(first.value).toBe(second.value);
    expect(first.truncated).toBe(true);
    expect(first.value).toContain("<truncated-head>");
    expect(first.value).toContain("<truncated-tail>");
    expect(first.value.length).toBeLessThanOrEqual(64);
  });

  it("does not treat a harmless command as a secret", () => {
    const command = redactCommand("git diff -- src/domain.ts && npm run typecheck");
    expect(command).toContain("git diff");
    expect(command).toContain("src/domain.ts");
    expect(command).toContain("npm run typecheck");
  });
});

describe("URL and path projection", () => {
  it("removes URL userinfo, sensitive query values, fragments, and internal hosts", () => {
    const url = redactUrl(
      `https://alice:${SENTINELS.basic}@${SENTINELS.internalHost}:8443/v1/action?X-Amz-Signature=${SENTINELS.signature}&mode=read#${SENTINELS.fragment}`,
    );

    expect(url).toContain("https://");
    expect(url).toContain("<internal-host>");
    expect(url).toContain("/v1/action");
    expect(url).toContain("mode=read");
    expect(url).toContain("<redacted-fragment>");
    expectNoSentinels(url);
  });

  it("preserves a public scheme, host, action path, and harmless query", () => {
    const url = redactUrl("https://example.com/v1/items?mode=read&format=json");
    expect(url).toContain("https://example.com");
    expect(url).toContain("/v1/items");
    expect(url).toContain("mode=read");
    expect(url).toContain("format=json");
  });

  it("projects all stable path categories without machine roots", () => {
    const cases = [
      [`${SENTINELS.homeRoot}/workspace/src/file.ts`, { projectRoot: `${SENTINELS.homeRoot}/workspace` }, "project"],
      [`${SENTINELS.homeRoot}/notes.txt`, { homeDirectory: SENTINELS.homeRoot }, "home"],
      ["/opt/vendor/data.json", {}, "external"],
      ["/usr/bin/node", {}, "system"],
      [`${SENTINELS.homeRoot}/.ssh/id_rsa`, { homeDirectory: SENTINELS.homeRoot }, "secret"],
      ["/etc/sudoers", {}, "protected"],
      ["../escape.txt", {}, "unknown"],
    ] as const;

    for (const [input, options, category] of cases) {
      const projection = projectPathDetailed(input, options);
      expect(projection.category).toBe(category);
      expectNoSentinels(projection);
      expect(projection.value).not.toContain(SENTINELS.homeRoot);
    }
  });

  it("redacts home paths embedded in arbitrary text", () => {
    const result = redactText(`read ${SENTINELS.homeRoot}/workspace/file.txt and continue`);
    expect(result).toContain("<home>");
    expect(result).toContain("file.txt");
    expectNoSentinels(result);
  });
});

describe("explicit context projection", () => {
  it("uses only named fields and omits unknown request structures", () => {
    const inputFacts = facts({
      action: "webfetch",
      actionCategory: "webfetch",
      tool: "fetch",
      resources: [
        { value: "https://example.com/v1/items?token=SENTINEL_QUERY_VALUE", kind: "url", scope: "external" },
        { value: `${SENTINELS.homeRoot}/workspace/file.txt`, kind: "path", scope: "project" },
      ],
      metadata: { apiKey: SENTINELS.apiKey, nested: { transcript: SENTINELS.bearer } },
      message: { text: SENTINELS.password },
      source: { messageID: "message", sourceID: "source" },
    });
    const context = buildRedactedContext(
      inputFacts,
      { text: `inspect the public item ${SENTINELS.highEntropy}`, redacted: false, truncated: false },
      POLICY,
      { projectRoot: `${SENTINELS.homeRoot}/workspace`, homeDirectory: SENTINELS.homeRoot },
    );
    const serialized = JSON.stringify(context);

    expect(context.action).toBe("webfetch");
    expect(context.resources.some((resource) => resource.display.includes("/v1/items"))).toBe(true);
    expect(serialized).not.toContain("metadata");
    expect(serialized).not.toContain("message");
    expect(Object.keys(context)).not.toContain("source");
    expect(serialized).not.toContain(SENTINELS.apiKey);
    expect(serialized).not.toContain(SENTINELS.bearer);
    expect(serialized).not.toContain(SENTINELS.password);
    expect(serialized).not.toContain(SENTINELS.highEntropy);
    expect(context.redactionComplete).toBe(true);
  });

  it("keeps harmless shell verbs and argument names while redacting command values", () => {
    const context = buildRedactedContext(
      facts({
        resources: [
          {
            value: `git status --short --token ${SENTINELS.bearer}`,
            kind: "command",
            scope: "project",
          },
        ],
      }),
      "check the repository status",
      POLICY,
    );

    expect(context.commands?.[0]).toContain("git status");
    expect(context.commands?.[0]).toContain("--short");
    expect(context.commands?.[0]).toContain("--token");
    expectNoSentinels(context);
  });

  it("makes missing intent deterministic and ineligible for automatic allow", () => {
    const context = buildRedactedContext(facts(), undefined, POLICY);
    expect(context.intent).toBeUndefined();
    expect(context.redactionComplete).toBe(true);
    expect(context.eligibleForAutoAllow).toBe(false);
  });

  it("fails closed for an unsafe intent projection", () => {
    const context = buildRedactedContext(
      facts(),
      `-----BEGIN RSA PRIVATE KEY-----\n${SENTINELS.privateKey}`,
      POLICY,
    );
    expect(context.intent).toBeUndefined();
    expect(context.redactionComplete).toBe(false);
    expect(context.eligibleForAutoAllow).toBe(false);
    expectNoSentinels(context);
  });

  it("marks unknown scope and oversize projections ineligible", () => {
    const context = buildRedactedContext(
      facts({
        action: "read",
        actionCategory: "read",
        resources: [{ value: "unclassified-resource", kind: "generic", scope: "unknown" }],
      }),
      "read the resource",
      POLICY,
      { limits: { resources: 1, resourceChars: 16, intentChars: 16, commandChars: 16 } },
    );

    expect(context.eligibleForAutoAllow).toBe(false);
    expect(context.truncation?.resource).toBe(true);
    expectNoSentinels(context);
  });

  it("bounds command, resource, and intent fields with explicit truncation flags", () => {
    const context = new ContextBuilder({
      limits: { commandChars: 32, intentChars: 32, resources: 1, resourceChars: 32 },
    }).build(
      facts({
        resources: [
          { value: "echo HEAD_ACTION", kind: "command", scope: "project" },
          { value: "echo SECOND_RESOURCE", kind: "generic", scope: "project" },
        ],
      }),
      `HEAD_INTENT${"x".repeat(80)}TAIL_INTENT`,
      POLICY,
    );

    expect(context.commands?.length).toBeLessThanOrEqual(1);
    expect(context.resources.length).toBeLessThanOrEqual(1);
    expect(context.truncation?.intent).toBe(true);
    expect(context.truncation?.resources).toBe(true);
    expect(context.eligibleForAutoAllow).toBe(false);
    expectNoSentinels(context);
  });

  it("produces a JSON-serializable structurally typed value", () => {
    const context = buildRedactedContext(facts(), "run a harmless check", POLICY);
    expect(() => JSON.stringify(context)).not.toThrow();
    expect(Object.keys(context)).not.toContain("metadata");
    expect(Object.keys(context)).not.toContain("message");
    expect(Object.keys(context)).not.toContain("source");
  });

  it("honors configured project roots instead of falling back to home", () => {
    const projectRoot = `${SENTINELS.homeRoot}/workspace`;
    const context = buildRedactedContext(
      facts({
        action: "read",
        actionCategory: "read",
        resources: [{ value: `${projectRoot}/src/file.ts`, kind: "path", scope: "project" }],
      }),
      "read the project file",
      POLICY,
      { projectRoot, homeDirectory: SENTINELS.homeRoot },
    );

    expect(context.resources[0]?.display).toBe("<project>/src/file.ts");
    expect(context.redactionComplete).toBe(true);
    expectNoSentinels(context);
  });

  it("fails closed on non-string, unknown-shape, and invalid policy inputs", () => {
    const malformed = buildRedactedContext(
      facts({
        resources: [
          { value: "", kind: "path", scope: "project" },
          { value: 42, kind: "generic", scope: "project" },
          { value: "ok", kind: "nope", scope: "project" },
          null,
        ] as unknown as PermissionFacts["resources"],
      }),
      `-----BEGIN RSA PRIVATE KEY-----\n${SENTINELS.privateKey}`,
      { version: "", hardDenyCodes: ["nope"], unknown: "manual_review", maximumGrant: "once" } as unknown as RedactedPolicy,
    );

    expect(malformed.resources).toEqual([]);
    expect(malformed.intent).toBeUndefined();
    expect(malformed.redactionComplete).toBe(false);
    expect(malformed.eligibleForAutoAllow).toBe(false);
    expectNoSentinels(malformed);
  });

  it("omits unknown resource shapes without leaking sentinel values", () => {
    const context = buildRedactedContext(
      facts({
        action: "read",
        actionCategory: "read",
        resources: [
          { value: `read ${SENTINELS.apiKey}`, kind: "unknown", scope: "unknown" },
        ],
      }),
      "read the resource",
      POLICY,
    );

    expect(context.eligibleForAutoAllow).toBe(false);
    expectNoSentinels(context);
  });
});

describe("Jev-state privacy", () => {
  it("outbound Jev state and questions contain no identifiers, raw paths, metadata, or secrets", () => {
    const context = buildRedactedContext(
      facts({
        action: "shell",
        actionCategory: "shell",
        tool: "shell-tool",
        resources: [
          {
            value: `curl --header 'Authorization: Bearer ${SENTINELS.bearer}' https://example.com/v1/items`,
            kind: "command",
            scope: "project",
          },
          { value: `${SENTINELS.homeRoot}/workspace/file.txt`, kind: "path", scope: "project" },
        ],
      }),
      `check the repository status with ${SENTINELS.apiKey}`,
      POLICY,
      { projectRoot: `${SENTINELS.homeRoot}/workspace`, homeDirectory: SENTINELS.homeRoot },
    );
    const request = buildJevRequest(context);
    const serialized = JSON.stringify(request);

    expectNoSentinels(request);
    expect(serialized).not.toContain("sessionID");
    expect(serialized).not.toContain("messageID");
    expect(serialized).not.toContain("metadata");
    expect(serialized).not.toContain("transcript");
    expect(serialized).toContain("intent_alignment");
    expect(serialized).toContain("risk_class");
    expect(serialized).toContain("policy_decision");
  });

  it("smuggled session and message identifiers never reach Jev JSON", () => {
    const context = buildRedactedContext(facts(), "run a harmless check", POLICY);
    const polluted = {
      ...context,
      sessionID: "session-JEV-SENTINEL-001",
      messageID: "message-JEV-SENTINEL-002",
      rawPath: `${SENTINELS.homeRoot}/secret`,
      metadata: { token: SENTINELS.apiKey },
      transcript: SENTINELS.bearer,
    } as unknown as typeof context;
    const request = buildJevRequest(polluted);

    expectNoSentinels(request);
    const serialized = JSON.stringify(request);
    expect(serialized).not.toContain("session-JEV-SENTINEL-001");
    expect(serialized).not.toContain("message-JEV-SENTINEL-002");
    expect(serialized).not.toContain("sessionID");
    expect(serialized).not.toContain("messageID");
  });
});
