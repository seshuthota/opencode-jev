/**
 * Bounded local relevant-intent storage and deterministic fallback selection.
 *
 * The cache owns no transcript and no raw prompt. A prompt is redacted before
 * it is admitted, and the only stored value is a frozen bounded fragment plus
 * local revision/timing/flag metadata.
 */

import type { LocalIntentCandidate, PermissionSourceCorrelation } from "../domain.js";
import { redactIntentDetailed, type TextRedactionResult } from "../redaction/index.js";

export interface IntentCacheEntry extends LocalIntentCandidate {
  readonly text: string;
  readonly revision: number;
  readonly timestamp: number;
  readonly redacted: true;
  readonly redactionComplete: true;
}

export interface IntentUpdateResult {
  readonly admitted: boolean;
  readonly revision?: number;
  readonly timestamp?: number;
  readonly truncated: boolean;
  readonly redactionComplete: boolean;
}

export interface IntentCacheOptions {
  readonly maxEntries?: number;
  readonly ttlMs?: number;
  readonly maxChars?: number;
  /** Injectable clock; production callers may use Date.now. */
  readonly now?: () => number;
}

export interface IntentSelection {
  readonly text: string;
  readonly redacted: true;
  readonly truncated: boolean;
  readonly redactionComplete: true;
  readonly source: "correlated" | "latest";
}

const DEFAULT_MAX_ENTRIES = 64;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_CHARS = 2000;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
}

function normalizedOptions(options: IntentCacheOptions): Required<Omit<IntentCacheOptions, "now">> & {
  readonly now: () => number;
} {
  const maxEntries = isBoundedInteger(options.maxEntries, 1, 1024)
    ? options.maxEntries
    : DEFAULT_MAX_ENTRIES;
  const ttlMs = isBoundedInteger(options.ttlMs, 1, 24 * 60 * 60 * 1000)
    ? options.ttlMs
    : DEFAULT_TTL_MS;
  const maxChars = isBoundedInteger(options.maxChars, 16, 100_000)
    ? options.maxChars
    : DEFAULT_MAX_CHARS;
  const now = typeof options.now === "function" ? options.now : Date.now;
  return { maxEntries, ttlMs, maxChars, now };
}

function safeTimestamp(now: () => number): number {
  try {
    const value = now();
    return typeof value === "number" && Number.isFinite(value) ? value : 0;
  } catch {
    return 0;
  }
}

function isExpired(entry: IntentCacheEntry, now: number, ttlMs: number): boolean {
  return now >= entry.timestamp && now - entry.timestamp >= ttlMs;
}

function freezeEntry(entry: IntentCacheEntry): IntentCacheEntry {
  return Object.freeze({ ...entry });
}

function makeUpdateResult(
  projection: TextRedactionResult,
  entry: IntentCacheEntry | undefined,
): IntentUpdateResult {
  if (entry === undefined) {
    return Object.freeze({
      admitted: false,
      truncated: projection.truncated,
      redactionComplete: projection.complete,
    });
  }
  return Object.freeze({
    admitted: true,
    revision: entry.revision,
    timestamp: entry.timestamp,
    truncated: entry.truncated,
    redactionComplete: true,
  });
}

/** A bounded, replacement-only cache of redacted user intent. */
export class RelevantIntentCache {
  private readonly entries = new Map<string, IntentCacheEntry>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly maxChars: number;
  private readonly now: () => number;
  private revision = 0;

  public constructor(options: IntentCacheOptions = {}) {
    const normalized = normalizedOptions(options);
    this.maxEntries = normalized.maxEntries;
    this.ttlMs = normalized.ttlMs;
    this.maxChars = normalized.maxChars;
    this.now = normalized.now;
  }

  /** Admit one prompt, replacing (never concatenating) that session's value. */
  public update(sessionID: string, prompt: unknown): IntentUpdateResult {
    if (typeof sessionID !== "string" || sessionID.length === 0 || sessionID.length > 512) {
      return Object.freeze({ admitted: false, truncated: false, redactionComplete: false });
    }
    const projection = redactIntentDetailed(prompt, { maxChars: this.maxChars });
    if (!projection.complete || projection.value.length === 0 || projection.value === "<redacted-omitted>") {
      return makeUpdateResult(projection, undefined);
    }
    this.cleanup();
    this.revision = this.revision >= Number.MAX_SAFE_INTEGER ? 1 : this.revision + 1;
    const entry = freezeEntry({
      text: projection.value,
      revision: this.revision,
      timestamp: safeTimestamp(this.now),
      redacted: true,
      truncated: projection.truncated,
      redactionComplete: true,
    });
    this.entries.delete(sessionID);
    this.entries.set(sessionID, entry);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (typeof oldest !== "string") break;
      this.entries.delete(oldest);
    }
    return makeUpdateResult(projection, entry);
  }

  public get(sessionID: string): IntentCacheEntry | undefined {
    if (typeof sessionID !== "string") return undefined;
    const entry = this.entries.get(sessionID);
    if (entry === undefined) return undefined;
    if (isExpired(entry, safeTimestamp(this.now), this.ttlMs)) {
      this.entries.delete(sessionID);
      return undefined;
    }
    return entry;
  }

  public has(sessionID: string): boolean {
    return this.get(sessionID) !== undefined;
  }

  public delete(sessionID: string): boolean {
    return typeof sessionID === "string" && this.entries.delete(sessionID);
  }

  public cleanup(now = safeTimestamp(this.now)): number {
    let removed = 0;
    for (const [sessionID, entry] of this.entries) {
      if (isExpired(entry, now, this.ttlMs)) {
        this.entries.delete(sessionID);
        removed += 1;
      }
    }
    return removed;
  }

  public clear(): void {
    this.entries.clear();
  }

  public get size(): number {
    this.cleanup();
    return this.entries.size;
  }

  public snapshot(): readonly IntentCacheEntry[] {
    this.cleanup();
    return Object.freeze([...this.entries.values()].map(freezeEntry));
  }
}

export const IntentCache = RelevantIntentCache;
export type IntentCache = RelevantIntentCache;

function readMessageText(message: Record<string, unknown>): string | undefined {
  if (typeof message.text === "string" && message.text.trim().length > 0) return message.text;
  if (typeof message.content === "string" && message.content.trim().length > 0) return message.content;
  const content = message.content;
  if (Array.isArray(content)) {
    const parts: string[] = [];
    for (const part of content.slice(0, 32)) {
      if (!isRecord(part) || part.type !== "text" || typeof part.text !== "string") continue;
      if (part.text.length === 0) continue;
      parts.push(part.text);
    }
    if (parts.length > 0) return parts.join("\n");
  }
  if (Array.isArray(message.parts)) {
    const parts: string[] = [];
    for (const part of message.parts.slice(0, 32)) {
      if (!isRecord(part) || part.type !== "text" || typeof part.text !== "string") continue;
      if (part.text.length === 0) continue;
      parts.push(part.text);
    }
    if (parts.length > 0) return parts.join("\n");
  }
  return undefined;
}

function messageRole(message: Record<string, unknown>): string | undefined {
  return typeof message.role === "string" ? message.role.toLowerCase() : undefined;
}

function messageID(message: Record<string, unknown>): string | undefined {
  if (typeof message.id === "string") return message.id;
  if (typeof message.messageID === "string") return message.messageID;
  return undefined;
}

function messageSourceID(message: Record<string, unknown>): string | undefined {
  if (typeof message.sourceID === "string") return message.sourceID;
  if (typeof message.sourceMessageID === "string") return message.sourceMessageID;
  if (isRecord(message.source) && typeof message.source.messageID === "string") return message.source.messageID;
  return undefined;
}

function sourceValues(
  source: PermissionSourceCorrelation | undefined,
): Readonly<{ messageID?: string; sourceID?: string }> {
  if (!isRecord(source)) return {};
  if (typeof source.messageID !== "string" || typeof source.sourceID !== "string") return {};
  return { messageID: source.messageID, sourceID: source.sourceID };
}

function messageMatchesSource(
  message: Record<string, unknown>,
  source: Readonly<{ messageID?: string; sourceID?: string }>,
): boolean {
  const id = messageID(message);
  const sourceID = messageSourceID(message);
  return (
    (source.messageID !== undefined && id === source.messageID) ||
    (source.sourceID !== undefined && (sourceID === source.sourceID || id === source.sourceID))
  );
}

function contextMessages(input: unknown): readonly Record<string, unknown>[] {
  const candidate = Array.isArray(input)
    ? input
    : isRecord(input) && Array.isArray(input.messages)
      ? input.messages
      : [];
  const messages: Record<string, unknown>[] = [];
  for (const value of candidate.slice(0, 10_000)) {
    if (isRecord(value)) messages.push(value);
  }
  return messages;
}

/**
 * Select at most one user message from a local context. The context itself is
 * never returned or retained by this function.
 */
export function selectRelevantIntent(
  context: unknown,
  source?: PermissionSourceCorrelation,
  options: { readonly maxChars?: number } = {},
): IntentSelection | undefined {
  const maxChars = isRecord(options) && isBoundedInteger(options.maxChars, 16, 100_000)
    ? options.maxChars
    : DEFAULT_MAX_CHARS;
  const messages = contextMessages(context);
  const correlation = sourceValues(source);
  let selected: Record<string, unknown> | undefined;
  let selectionSource: "correlated" | "latest" = "latest";

  if (correlation.messageID !== undefined || correlation.sourceID !== undefined) {
    const sourceIndex = messages.findIndex((message) => messageMatchesSource(message, correlation));
    if (sourceIndex < 0) return undefined;
    const exact = messages[sourceIndex];
    if (exact !== undefined && messageRole(exact) === "user") {
      selected = exact;
    } else {
      for (let index = sourceIndex - 1; index >= 0; index -= 1) {
        const candidate = messages[index];
        if (candidate !== undefined && messageRole(candidate) === "user") {
          selected = candidate;
          break;
        }
      }
    }
    selectionSource = "correlated";
  } else {
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const candidate = messages[index];
      if (candidate !== undefined && messageRole(candidate) === "user") {
        selected = candidate;
        break;
      }
    }
  }

  if (selected === undefined) return undefined;
  const rawText = readMessageText(selected);
  if (rawText === undefined) return undefined;
  const projection = redactIntentDetailed(rawText, { maxChars });
  if (!projection.complete || projection.value.length === 0 || projection.value === "<redacted-omitted>") {
    return undefined;
  }
  return Object.freeze({
    text: projection.value,
    redacted: true,
    truncated: projection.truncated,
    redactionComplete: true,
    source: selectionSource,
  });
}

export const selectRelevantUserIntent = selectRelevantIntent;

/** Stateless helper useful to adapters that already own a cache instance. */
export function fallbackIntent(
  context: unknown,
  source?: PermissionSourceCorrelation,
  options: { readonly maxChars?: number } = {},
): IntentSelection | undefined {
  return selectRelevantIntent(context, source, options);
}
