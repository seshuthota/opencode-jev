/**
 * Session-scoped permission port (Slice 5).
 *
 * Wraps only verified public Promise methods: session lookup, per-known-
 * session permission list, authoritative request get, pre-reply get, and
 * bounded same-decision reply recovery. Never throws; maps failures to
 * closed sanitized outcomes. No raw values in errors or logs.
 */

import {
  extractSessionDirectory,
  locationsEqual,
  validatePermissionRequest,
  type NormalizedPermissionRequest,
} from "./contract.js";
import { sanitizeErrorCategory } from "../observability/errors.js";

export type ReplyDecision = "once" | "reject";

export interface SessionGetPort {
  (input: Readonly<{ sessionID: string }>): Promise<unknown>;
}

export interface PermissionListPort {
  (input: Readonly<{ sessionID: string }>): Promise<unknown>;
}

export interface PermissionGetPort {
  (input: Readonly<{ sessionID: string; requestID: string }>): Promise<unknown>;
}

export interface PermissionReplyPort {
  (input: Readonly<{ sessionID: string; requestID: string; decision: ReplyDecision }>): Promise<void>;
}

export interface SessionContextPort {
  (input: Readonly<{ sessionID: string }>): Promise<unknown>;
}

export interface PermissionPorts {
  readonly sessionGet: SessionGetPort;
  readonly permissionList: PermissionListPort;
  readonly permissionGet: PermissionGetPort;
  readonly permissionReply: PermissionReplyPort;
  readonly sessionContext?: SessionContextPort;
}

export type SessionDirectoryResult =
  | Readonly<{ status: "in_scope"; directory: string }>
  | Readonly<{ status: "out_of_scope"; directory: string }>
  | Readonly<{ status: "external" }>
  | Readonly<{ status: "transport" }>;

export type AuthoritativeResult =
  | Readonly<{ status: "pending"; request: NormalizedPermissionRequest }>
  | Readonly<{ status: "external" }>
  | Readonly<{ status: "malformed" }>
  | Readonly<{ status: "transport" }>;

export type ReplyResult =
  | Readonly<{ status: "replied" }>
  | Readonly<{ status: "external" }>
  | Readonly<{ status: "pending" }>;

function isNotFound(error: unknown): boolean {
  try {
    return sanitizeErrorCategory(error) === "opencode_not_found";
  } catch {
    return false;
  }
}

/**
 * Verify session ownership against this instance's location.
 *
 * Returns in_scope only when the authoritative session location normalizes
 * equal to the instance directory. Not-found maps to external; any other
 * failure maps to transport (leave pending, no reply).
 */
export async function getSessionDirectory(
  ports: Pick<PermissionPorts, "sessionGet">,
  sessionID: string,
  locationDirectory: string,
): Promise<SessionDirectoryResult> {
  try {
    const session = await ports.sessionGet({ sessionID });
    const directory = extractSessionDirectory(session);
    if (directory === undefined) {
      return Object.freeze({ status: "transport" as const });
    }
    if (locationsEqual(directory, locationDirectory)) {
      return Object.freeze({ status: "in_scope" as const, directory });
    }
    return Object.freeze({ status: "out_of_scope" as const, directory });
  } catch (error) {
    if (isNotFound(error)) return Object.freeze({ status: "external" as const });
    return Object.freeze({ status: "transport" as const });
  }
}

/**
 * List pending requests for one known session.
 *
 * Returns only validated requests. Not-found and transport failures return
 * an empty list (leave pending, no throw, no private fallback).
 */
export async function listPendingRequests(
  ports: Pick<PermissionPorts, "permissionList">,
  sessionID: string,
): Promise<readonly NormalizedPermissionRequest[]> {
  try {
    const listed = await ports.permissionList({ sessionID });
    if (!Array.isArray(listed)) return Object.freeze([]);
    const validated: NormalizedPermissionRequest[] = [];
    for (const entry of listed) {
      const result = validatePermissionRequest(entry);
      if (result.ok === true) validated.push(result.value);
    }
    return Object.freeze(validated);
  } catch (error) {
    if (isNotFound(error)) return Object.freeze([]);
    return Object.freeze([]);
  }
}

/**
 * Fetch the authoritative pending request.
 *
 * Missing/not-found is externally resolved (no reply). Validation failure
 * is malformed (manual). Other failures are transport (leave pending).
 */
export async function getAuthoritativeRequest(
  ports: Pick<PermissionPorts, "permissionGet">,
  sessionID: string,
  requestID: string,
): Promise<AuthoritativeResult> {
  try {
    const raw = await ports.permissionGet({ sessionID, requestID });
    const validated = validatePermissionRequest(raw);
    if (validated.ok !== true) return Object.freeze({ status: "malformed" as const });
    // Defensive identity check: the authoritative record must match the key.
    if (validated.value.sessionID !== sessionID || validated.value.requestID !== requestID) {
      return Object.freeze({ status: "malformed" as const });
    }
    return Object.freeze({ status: "pending" as const, request: validated.value });
  } catch (error) {
    if (isNotFound(error)) return Object.freeze({ status: "external" as const });
    return Object.freeze({ status: "transport" as const });
  }
}

/** Current-request pre-reply check: a fresh get wins over a late decision. */
export async function preReplyCheck(
  ports: Pick<PermissionPorts, "permissionGet">,
  sessionID: string,
  requestID: string,
): Promise<AuthoritativeResult> {
  return getAuthoritativeRequest(ports, sessionID, requestID);
}

/**
 * Bounded same-decision reply recovery.
 *
 * - Success marks replied.
 * - Known not-found/404 marks externally resolved.
 * - Any other failure performs one fresh get; when still pending, retries
 *   the identical decision at most once. A second failure leaves pending.
 * Never recomputes a different decision because of transport errors.
 */
export async function replyWithRecovery(
  ports: Pick<PermissionPorts, "permissionGet" | "permissionReply">,
  sessionID: string,
  requestID: string,
  decision: ReplyDecision,
): Promise<ReplyResult> {
  try {
    await ports.permissionReply({ sessionID, requestID, decision });
    return Object.freeze({ status: "replied" as const });
  } catch (error) {
    if (isNotFound(error)) return Object.freeze({ status: "external" as const });
  }
  // Ambiguous transport failure: one fresh get, then at most one same-decision retry.
  let fresh: AuthoritativeResult;
  try {
    fresh = await getAuthoritativeRequest(ports, sessionID, requestID);
  } catch {
    return Object.freeze({ status: "pending" as const });
  }
  if (fresh.status !== "pending") {
    if (fresh.status === "external") return Object.freeze({ status: "external" as const });
    return Object.freeze({ status: "pending" as const });
  }
  try {
    await ports.permissionReply({ sessionID, requestID, decision });
    return Object.freeze({ status: "replied" as const });
  } catch (retryError) {
    if (isNotFound(retryError)) return Object.freeze({ status: "external" as const });
    return Object.freeze({ status: "pending" as const });
  }
}

/**
 * Fetch raw session context for local fallback intent selection.
 *
 * Returns the unknown payload for the caller to select one redacted user
 * fragment from; never throws and never logs content.
 */
export async function fetchSessionContext(
  ports: Pick<PermissionPorts, "sessionContext">,
  sessionID: string,
): Promise<unknown> {
  try {
    const fetcher = ports.sessionContext;
    if (fetcher === undefined) return undefined;
    return await fetcher({ sessionID });
  } catch {
    return undefined;
  }
}
