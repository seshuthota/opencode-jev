/**
 * OpenCode contract narrowing (Slice 5).
 *
 * This module owns every OpenCode type assertion for the adapter. All other
 * Slice 5 modules must use these helpers instead of casting OpenCode shapes.
 * Functions never throw, never log raw values, and return only closed reason
 * codes or freshly copied validated values.
 */

export interface PermissionIdentity {
  readonly sessionID: string;
  readonly requestID: string;
}

export interface PermissionSourceIdentity {
  readonly messageID: string;
  readonly sourceID: string;
}

export interface NormalizedPermissionRequest {
  readonly sessionID: string;
  readonly requestID: string;
  readonly action: string;
  readonly resources: readonly string[];
  readonly source?: PermissionSourceIdentity;
}

export type RequestValidationResult =
  | Readonly<{ ok: true; value: NormalizedPermissionRequest }>
  | Readonly<{ ok: false; reason: "malformed_request" }>;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as object | null;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

/** Non-empty, bounded identifier without control characters. */
export function isValidID(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 512) return false;
  if (value.trim().length === 0) return false;
  if (value.includes("\u0000")) return false;
  return true;
}

/** Non-empty bounded action string. */
export function isValidAction(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 256) return false;
  if (value.trim().length === 0) return false;
  if (value.includes("\u0000")) return false;
  return true;
}

/** Bounded single resource string. */
export function isValidResource(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 100_000) return false;
  if (value.includes("\u0000")) return false;
  return true;
}

function isValidDirectory(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 4096) return false;
  if (value.trim().length === 0) return false;
  if (value.includes("\u0000")) return false;
  return true;
}

/**
 * Normalize a location directory for equality checks.
 *
 * Replaces Windows separators and strips trailing slashes (except root).
 * Pure string work; no filesystem access.
 */
export function normalizeLocationDirectory(directory: string): string {
  try {
    const slashed = directory.replaceAll("\\", "/");
    if (slashed.length > 1) {
      let end = slashed.length;
      while (end > 1 && slashed.charCodeAt(end - 1) === 47) end -= 1;
      return slashed.slice(0, end);
    }
    return slashed;
  } catch {
    return directory;
  }
}

/** True when two directories normalize to the same value. */
export function locationsEqual(left: string, right: string): boolean {
  try {
    return normalizeLocationDirectory(left) === normalizeLocationDirectory(right);
  } catch {
    return false;
  }
}

/** Canonical in-process key for one location/session/request. */
export function canonicalRequestKey(
  locationDirectory: string,
  sessionID: string,
  requestID: string,
): string {
  return `${normalizeLocationDirectory(locationDirectory)}|${sessionID}|${requestID}`;
}

/**
 * Extract only sessionID/requestID from a public `permission.asked` event.
 *
 * Installed shape carries the request at `data` with `data.id` as the
 * request ID and `data.sessionID` as the session ID. Any other variant or
 * malformed payload returns undefined.
 */
export function extractPermissionAsked(event: unknown): PermissionIdentity | undefined {
  try {
    if (!isRecord(event)) return undefined;
    if (event.type !== "permission.asked") return undefined;
    const data = event.data;
    if (!isRecord(data)) return undefined;
    const sessionID = data.sessionID;
    const requestID = data.id;
    if (!isValidID(sessionID) || !isValidID(requestID)) return undefined;
    return Object.freeze({ sessionID, requestID });
  } catch {
    return undefined;
  }
}

function extractSource(request: Record<string, unknown>): PermissionSourceIdentity | undefined {
  try {
    const source = request.source;
    if (!isRecord(source)) return undefined;
    if (source.type !== "tool") return undefined;
    const messageID = source.messageID;
    const sourceID = source.id;
    if (!isValidID(messageID) || !isValidID(sourceID)) return undefined;
    return Object.freeze({ messageID, sourceID });
  } catch {
    return undefined;
  }
}

/**
 * Validate an authoritative permission request envelope.
 *
 * Accepts only named fields (id/sessionID/action/resources plus optional
 * tool source). Arbitrary metadata/message/source structures are ignored,
 * never copied. Returns a frozen copy or a sanitized failure reason.
 */
export function validatePermissionRequest(request: unknown): RequestValidationResult {
  try {
    if (!isRecord(request)) return Object.freeze({ ok: false as const, reason: "malformed_request" as const });
    const id = request.id;
    const sessionID = request.sessionID;
    const action = request.action;
    const resources = request.resources;
    if (!isValidID(id) || !isValidID(sessionID) || !isValidAction(action)) {
      return Object.freeze({ ok: false as const, reason: "malformed_request" as const });
    }
    if (!Array.isArray(resources)) {
      return Object.freeze({ ok: false as const, reason: "malformed_request" as const });
    }
    const copied: string[] = [];
    for (const entry of resources) {
      if (!isValidResource(entry)) {
        return Object.freeze({ ok: false as const, reason: "malformed_request" as const });
      }
      copied.push(entry);
    }
    const source = extractSource(request);
    return Object.freeze({
      ok: true as const,
      value: Object.freeze({
        sessionID,
        requestID: id,
        action,
        resources: Object.freeze(copied),
        ...(source === undefined ? {} : { source }),
      }),
    });
  } catch {
    return Object.freeze({ ok: false as const, reason: "malformed_request" as const });
  }
}

/**
 * Extract a normalized session location directory.
 *
 * Reads only `session.location.directory`. Returns the normalized directory
 * or undefined when absent/malformed.
 */
export function extractSessionDirectory(session: unknown): string | undefined {
  try {
    if (!isRecord(session)) return undefined;
    const location = session.location;
    if (!isRecord(location)) return undefined;
    const directory = location.directory;
    if (!isValidDirectory(directory)) return undefined;
    return normalizeLocationDirectory(directory);
  } catch {
    return undefined;
  }
}

/** Extract a session ID from a prompt-hook input. */
export function extractPromptSession(input: unknown): string | undefined {
  try {
    if (!isRecord(input)) return undefined;
    const sessionID = input.sessionID;
    if (!isValidID(sessionID)) return undefined;
    return sessionID;
  } catch {
    return undefined;
  }
}

/**
 * Extract prompt text from a prompt-hook input.
 *
 * Reads only `input.prompt.text` (or a plain-string prompt in fakes).
 * Returns the raw text for the caller to redact; never logs it.
 */
export function extractPromptText(input: unknown): string | undefined {
  try {
    if (!isRecord(input)) return undefined;
    const prompt = input.prompt;
    if (typeof prompt === "string") {
      if (prompt.length === 0 || prompt.length > 100_000) return undefined;
      return prompt;
    }
    if (!isRecord(prompt)) return undefined;
    const text = prompt.text;
    if (typeof text !== "string") return undefined;
    if (text.length === 0 || text.length > 100_000) return undefined;
    return text;
  } catch {
    return undefined;
  }
}
