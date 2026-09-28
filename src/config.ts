export const PLUGIN_LOG_LEVELS = ["info", "warn", "off"] as const;
export type PluginLogLevel = (typeof PLUGIN_LOG_LEVELS)[number];

// Keep validation independent from the public export: `as const` is a
// compile-time guarantee, not a runtime immutability guarantee.
const PLUGIN_LOG_LEVELS_RUNTIME: readonly string[] = Object.freeze([...PLUGIN_LOG_LEVELS]);

export interface PluginConfigThresholds {
  readonly allowConfidence: number;
  readonly allowProbability: number;
  readonly elevatedAllowConfidence: number;
  readonly denyConfidence: number;
  readonly denyProbability: number;
  readonly auxiliaryConfidence: number;
}

export interface PluginConfigLimits {
  readonly commandChars: number;
  readonly intentChars: number;
  readonly resources: number;
  readonly resourceChars: number;
}

export interface PluginConfig {
  readonly model: string;
  readonly timeoutMs: number;
  readonly maxRetries: number;
  readonly maxConcurrency: number;
  readonly maxQueueSize: number;
  readonly reconcileIntervalMs: number;
  readonly thresholds: PluginConfigThresholds;
  readonly limits: PluginConfigLimits;
  readonly pluginLogLevel: PluginLogLevel;
}

export interface PluginConfigError {
  readonly code: "config_invalid";
  readonly message: "Invalid plugin options";
}

export type ParsePluginOptionsResult =
  | Readonly<{ ok: true; value: PluginConfig }>
  | Readonly<{ ok: false; error: PluginConfigError }>;

const ROOT_KEYS = [
  "model",
  "timeoutMs",
  "maxRetries",
  "maxConcurrency",
  "maxQueueSize",
  "reconcileIntervalMs",
  "thresholds",
  "limits",
  "pluginLogLevel",
] as const;

const THRESHOLD_KEYS = [
  "allowConfidence",
  "allowProbability",
  "elevatedAllowConfidence",
  "denyConfidence",
  "denyProbability",
  "auxiliaryConfidence",
] as const;

const LIMIT_KEYS = ["commandChars", "intentChars", "resources", "resourceChars"] as const;

const DEFAULTS = {
  model: "jev-latest",
  timeoutMs: 8000,
  maxRetries: 1,
  maxConcurrency: 4,
  maxQueueSize: 256,
  reconcileIntervalMs: 30000,
  thresholds: {
    // Jev's calibrated confidence and selected-label probability are separate
    // signals.  Requiring near-certainty from both made routine, strongly
    // supported operations fall through to manual review in normal hosted
    // responses.  These defaults preserve a meaningful confidence floor while
    // allowing Jev to handle clear routine decisions as intended.
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
} as const satisfies PluginConfig;

function freezeConfig(config: PluginConfig): PluginConfig {
  return Object.freeze({
    ...config,
    thresholds: Object.freeze({ ...config.thresholds }),
    limits: Object.freeze({ ...config.limits }),
  });
}

export const DEFAULT_PLUGIN_CONFIG: PluginConfig = freezeConfig(DEFAULTS);

function invalid(): ParsePluginOptionsResult {
  return Object.freeze({
    ok: false,
    error: Object.freeze({
      code: "config_invalid",
      message: "Invalid plugin options",
    }),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Reflect.ownKeys(value).every(
    (key) => typeof key === "string" && allowed.includes(key),
  );
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return isFiniteNumber(value) && Number.isInteger(value) && value >= minimum && value <= maximum;
}

function isProbability(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 0 && value <= 1;
}

function isJevModel(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim() === value &&
    /^jev-[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
  );
}

function isPluginLogLevel(value: unknown): value is PluginLogLevel {
  return typeof value === "string" && PLUGIN_LOG_LEVELS_RUNTIME.includes(value);
}

function readThresholds(value: unknown): PluginConfigThresholds | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, THRESHOLD_KEYS)) return undefined;

  const allowConfidence = hasOwn(value, "allowConfidence")
    ? value.allowConfidence
    : DEFAULTS.thresholds.allowConfidence;
  const allowProbability = hasOwn(value, "allowProbability")
    ? value.allowProbability
    : DEFAULTS.thresholds.allowProbability;
  const elevatedAllowConfidence = hasOwn(value, "elevatedAllowConfidence")
    ? value.elevatedAllowConfidence
    : DEFAULTS.thresholds.elevatedAllowConfidence;
  const denyConfidence = hasOwn(value, "denyConfidence")
    ? value.denyConfidence
    : DEFAULTS.thresholds.denyConfidence;
  const denyProbability = hasOwn(value, "denyProbability")
    ? value.denyProbability
    : DEFAULTS.thresholds.denyProbability;
  const auxiliaryConfidence = hasOwn(value, "auxiliaryConfidence")
    ? value.auxiliaryConfidence
    : DEFAULTS.thresholds.auxiliaryConfidence;

  if (
    !isProbability(allowConfidence) ||
    !isProbability(allowProbability) ||
    !isProbability(elevatedAllowConfidence) ||
    !isProbability(denyConfidence) ||
    !isProbability(denyProbability) ||
    !isProbability(auxiliaryConfidence) ||
    elevatedAllowConfidence < allowConfidence
  ) {
    return undefined;
  }

  return {
    allowConfidence,
    allowProbability,
    elevatedAllowConfidence,
    denyConfidence,
    denyProbability,
    auxiliaryConfidence,
  };
}

function readLimits(value: unknown): PluginConfigLimits | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, LIMIT_KEYS)) return undefined;

  const commandChars = hasOwn(value, "commandChars")
    ? value.commandChars
    : DEFAULTS.limits.commandChars;
  const intentChars = hasOwn(value, "intentChars")
    ? value.intentChars
    : DEFAULTS.limits.intentChars;
  const resources = hasOwn(value, "resources")
    ? value.resources
    : DEFAULTS.limits.resources;
  const resourceChars = hasOwn(value, "resourceChars")
    ? value.resourceChars
    : DEFAULTS.limits.resourceChars;

  if (
    !isIntegerInRange(commandChars, 256, 16384) ||
    !isIntegerInRange(intentChars, 128, 8192) ||
    !isIntegerInRange(resources, 1, 64) ||
    !isIntegerInRange(resourceChars, 64, 4096)
  ) {
    return undefined;
  }

  return { commandChars, intentChars, resources, resourceChars };
}

/**
 * Parse untrusted OpenCode plugin options without reading the environment,
 * performing I/O, or interpolating input into an error.
 */
export function parsePluginOptions(input: unknown): ParsePluginOptionsResult {
  try {
    return parsePluginOptionsUnsafe(input);
  } catch {
    return invalid();
  }
}

function parsePluginOptionsUnsafe(input: unknown): ParsePluginOptionsResult {
  if (input === undefined) {
    return {
      ok: true,
      value: freezeConfig({
        ...DEFAULTS,
        thresholds: { ...DEFAULTS.thresholds },
        limits: { ...DEFAULTS.limits },
      }),
    };
  }

  if (!isRecord(input) || !hasOnlyKeys(input, ROOT_KEYS)) return invalid();

  const model = hasOwn(input, "model") ? input.model : DEFAULTS.model;
  const timeoutMs = hasOwn(input, "timeoutMs") ? input.timeoutMs : DEFAULTS.timeoutMs;
  const maxRetries = hasOwn(input, "maxRetries") ? input.maxRetries : DEFAULTS.maxRetries;
  const maxConcurrency = hasOwn(input, "maxConcurrency")
    ? input.maxConcurrency
    : DEFAULTS.maxConcurrency;
  const maxQueueSize = hasOwn(input, "maxQueueSize")
    ? input.maxQueueSize
    : DEFAULTS.maxQueueSize;
  const reconcileIntervalMs = hasOwn(input, "reconcileIntervalMs")
    ? input.reconcileIntervalMs
    : DEFAULTS.reconcileIntervalMs;
  const pluginLogLevel = hasOwn(input, "pluginLogLevel")
    ? input.pluginLogLevel
    : DEFAULTS.pluginLogLevel;

  if (hasOwn(input, "model") && !isJevModel(model)) return invalid();
  if (hasOwn(input, "timeoutMs") && !isIntegerInRange(timeoutMs, 100, 30000)) return invalid();
  if (hasOwn(input, "maxRetries") && !isIntegerInRange(maxRetries, 0, 2)) return invalid();
  if (hasOwn(input, "maxConcurrency") && !isIntegerInRange(maxConcurrency, 1, 16)) {
    return invalid();
  }
  if (hasOwn(input, "maxQueueSize") && !isIntegerInRange(maxQueueSize, 1, 2048)) {
    return invalid();
  }
  if (
    hasOwn(input, "reconcileIntervalMs") &&
    !isIntegerInRange(reconcileIntervalMs, 5000, 300000)
  ) {
    return invalid();
  }
  if (hasOwn(input, "pluginLogLevel") && !isPluginLogLevel(pluginLogLevel)) return invalid();

  const thresholds = hasOwn(input, "thresholds")
    ? readThresholds(input.thresholds)
    : { ...DEFAULTS.thresholds };
  if (thresholds === undefined) return invalid();

  const limits = hasOwn(input, "limits") ? readLimits(input.limits) : { ...DEFAULTS.limits };
  if (limits === undefined) return invalid();

  const config: PluginConfig = {
    model: model as string,
    timeoutMs: timeoutMs as number,
    maxRetries: maxRetries as number,
    maxConcurrency: maxConcurrency as number,
    maxQueueSize: maxQueueSize as number,
    reconcileIntervalMs: reconcileIntervalMs as number,
    thresholds,
    limits,
    pluginLogLevel: pluginLogLevel as PluginLogLevel,
  };

  return { ok: true, value: freezeConfig(config) };
}
