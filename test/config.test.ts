import { describe, expect, it } from "vitest";

import {
  DEFAULT_PLUGIN_CONFIG,
  PLUGIN_LOG_LEVELS,
  type ParsePluginOptionsResult,
  parsePluginOptions,
} from "../src/config.js";

function expectInvalid(input: unknown): void {
  const result = parsePluginOptions(input);
  expect(result).toEqual({
    ok: false,
    error: { code: "config_invalid", message: "Invalid plugin options" },
  });
}

function expectValid(input: unknown): void {
  const result: ParsePluginOptionsResult = parsePluginOptions(input);
  expect(result.ok).toBe(true);
}

const EXPECTED_DEFAULTS = {
  model: "jev-latest",
  timeoutMs: 8000,
  maxRetries: 1,
  maxConcurrency: 4,
  maxQueueSize: 256,
  reconcileIntervalMs: 30000,
  thresholds: {
    allowConfidence: 0.8,
    allowProbability: 0.85,
    elevatedAllowConfidence: 0.9,
    denyConfidence: 0.85,
    denyProbability: 0.8,
    auxiliaryConfidence: 0.8,
  },
  limits: {
    commandChars: 4096,
    intentChars: 2000,
    resources: 16,
    resourceChars: 512,
  },
  pluginLogLevel: "info",
} as const;

describe("parsePluginOptions", () => {
  it("returns the documented defaults for omitted options", () => {
    expect(parsePluginOptions(undefined)).toEqual({ ok: true, value: EXPECTED_DEFAULTS });
    expect(parsePluginOptions({})).toEqual({ ok: true, value: EXPECTED_DEFAULTS });
    expect(DEFAULT_PLUGIN_CONFIG).toEqual(EXPECTED_DEFAULTS);
  });

  it("accepts a complete valid configuration", () => {
    const input = {
      model: "jev-custom-v2",
      timeoutMs: 100,
      maxRetries: 0,
      maxConcurrency: 1,
      maxQueueSize: 1,
      reconcileIntervalMs: 5000,
      thresholds: {
        allowConfidence: 0,
        allowProbability: 0,
        elevatedAllowConfidence: 0,
        denyConfidence: 1,
        denyProbability: 1,
        auxiliaryConfidence: 1,
      },
      limits: {
        commandChars: 256,
        intentChars: 128,
        resources: 1,
        resourceChars: 64,
      },
      pluginLogLevel: "off",
    } as const;

    const result = parsePluginOptions(input);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toEqual(input);
  });

  it.each([
    ["timeoutMs", 100, 30000],
    ["maxRetries", 0, 2],
    ["maxConcurrency", 1, 16],
    ["maxQueueSize", 1, 2048],
    ["reconcileIntervalMs", 5000, 300000],
  ] as const)("accepts the inclusive %s bounds", (key, minimum, maximum) => {
    expectValid({ [key]: minimum });
    expectValid({ [key]: maximum });
  });

  it.each([
    ["commandChars", 256, 16384],
    ["intentChars", 128, 8192],
    ["resources", 1, 64],
    ["resourceChars", 64, 4096],
  ] as const)("accepts the inclusive limits.%s bounds", (key, minimum, maximum) => {
    expectValid({ limits: { [key]: minimum } });
    expectValid({ limits: { [key]: maximum } });
  });

  it("accepts probability endpoints and requires the elevated threshold ordering", () => {
    expectValid({
      thresholds: {
        allowConfidence: 0,
        allowProbability: 1,
        elevatedAllowConfidence: 0,
        denyConfidence: 0,
        denyProbability: 1,
        auxiliaryConfidence: 0,
      },
    });
    expectValid({
      thresholds: {
        allowConfidence: 1,
        elevatedAllowConfidence: 1,
      },
    });
    expectInvalid({
      thresholds: {
        allowConfidence: 0.8,
        elevatedAllowConfidence: 0.79,
      },
    });
  });

  it("rejects unknown keys at every object level", () => {
    expectInvalid({ extra: true });
    expectInvalid({ thresholds: { extra: 0.5 } });
    expectInvalid({ limits: { extra: 1 } });
  });

  it("rejects non-object option values", () => {
    expectInvalid(null);
    expectInvalid([]);
    expectInvalid("options");
    expectInvalid(1);
  });

  it("rejects models outside the hosted Jev namespace", () => {
    for (const model of [
      "",
      "jev-",
      "JEV-latest",
      "gpt-4",
      " jev-latest",
      "jev latest",
      "jev-latest\n",
    ]) {
      expectInvalid({ model });
    }
    expectInvalid({ model: 42 });
  });

  it("accepts every supported log level and rejects invalid enum values", () => {
    for (const pluginLogLevel of ["info", "warn", "off"]) {
      expectValid({ pluginLogLevel });
    }
    for (const pluginLogLevel of ["debug", "error", "INFO", ""]) {
      expectInvalid({ pluginLogLevel });
    }
    expectInvalid({ pluginLogLevel: null });
  });

  it("does not allow mutation of the public log-level export to widen validation", () => {
    const exportedLevels = PLUGIN_LOG_LEVELS as unknown as string[];
    const originalLength = exportedLevels.length;

    try {
      exportedLevels.push("debug");
      expectInvalid({ pluginLogLevel: "debug" });
    } finally {
      exportedLevels.length = originalLength;
    }
  });

  it.each([
    ["timeoutMs", 99],
    ["timeoutMs", 30001],
    ["timeoutMs", 100.5],
    ["maxRetries", -1],
    ["maxRetries", 3],
    ["maxRetries", 0.5],
    ["maxConcurrency", 0],
    ["maxConcurrency", 17],
    ["maxQueueSize", 0],
    ["maxQueueSize", 2049],
    ["reconcileIntervalMs", 4999],
    ["reconcileIntervalMs", 300001],
  ] as const)("rejects out-of-range %s", (key, value) => {
    expectInvalid({ [key]: value });
  });

  it.each([
    ["commandChars", 255],
    ["commandChars", 16385],
    ["intentChars", 127],
    ["intentChars", 8193],
    ["resources", 0],
    ["resources", 65],
    ["resourceChars", 63],
    ["resourceChars", 4097],
  ] as const)("rejects out-of-range limits.%s", (key, value) => {
    expectInvalid({ limits: { [key]: value } });
  });

  it.each([
    "allowConfidence",
    "allowProbability",
    "elevatedAllowConfidence",
    "denyConfidence",
    "denyProbability",
    "auxiliaryConfidence",
  ] as const)("rejects non-finite and non-probability %s", (key) => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0.01, 1.01]) {
      expectInvalid({ thresholds: { [key]: value } });
    }
  });

  it.each([
    "timeoutMs",
    "maxRetries",
    "maxConcurrency",
    "maxQueueSize",
    "reconcileIntervalMs",
  ] as const)("rejects non-finite root numeric option %s", (key) => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expectInvalid({ [key]: value });
    }
  });

  it.each(["commandChars", "intentChars", "resources", "resourceChars"] as const)(
    "rejects non-finite limits.%s",
    (key) => {
      for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        expectInvalid({ limits: { [key]: value } });
      }
    },
  );

  it("rejects wrong types for numeric and nested options", () => {
    expectInvalid({ timeoutMs: "8000" });
    expectInvalid({ maxRetries: null });
    expectInvalid({ thresholds: { allowConfidence: null } });
    expectInvalid({ limits: { resources: "16" } });
  });

  it("rejects explicitly undefined nested values instead of silently defaulting", () => {
    expectInvalid({ thresholds: { allowConfidence: undefined } });
    expectInvalid({ limits: { commandChars: undefined } });
  });

  it("does not mutate input and returns a frozen normalized value", () => {
    const input = {
      timeoutMs: 9000,
      thresholds: { allowConfidence: 0.87 },
      limits: { resources: 20 },
    };
    const before = structuredClone(input);
    const result = parsePluginOptions(input);

    expect(input).toEqual(before);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.isFrozen(result.value)).toBe(true);
      expect(Object.isFrozen(result.value.thresholds)).toBe(true);
      expect(Object.isFrozen(result.value.limits)).toBe(true);
    }
  });

  it("returns a closed sanitized error without input interpolation", () => {
    const sentinel = "secret-value-that-must-not-appear";
    const result = parsePluginOptions({ model: sentinel, unexpected: sentinel });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("config_invalid");
      expect(result.error.message).toBe("Invalid plugin options");
      expect(JSON.stringify(result.error)).not.toContain(sentinel);
    }
  });
});

describe("test network isolation", () => {
  it("removes the TypeSafe credential and fails fetch immediately", () => {
    expect(process.env.TYPESAFE_API_KEY).toBeUndefined();
    expect(() => globalThis.fetch("https://api.typesafe.ai/v1/systemone")).toThrow(
      "Network access is disabled in tests",
    );
  });
});
