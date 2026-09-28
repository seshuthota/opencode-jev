/** Closed error taxonomy for Jev and adapter boundaries. */

import type { ErrorReason } from "../domain.js";

export const ERROR_REASONS: readonly ErrorReason[] = Object.freeze([
  "config_invalid",
  "missing_api_key",
  "api_authentication",
  "api_rate_limited",
  "api_server",
  "api_transport",
  "api_timeout",
  "api_aborted",
  "api_malformed_response",
  "opencode_transport",
  "opencode_not_found",
  "opencode_invalid_response",
  "unknown",
]);

const ERROR_REASON_SET: ReadonlySet<string> = new Set(ERROR_REASONS);

export interface SanitizedError {
  readonly category: ErrorReason;
  readonly status?: number;
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  try {
    Object.getPrototypeOf(value);
    return true;
  } catch {
    return false;
  }
}

function readString(value: unknown, key: string): string | undefined {
  if (!isObjectLike(value)) return undefined;
  try {
    const candidate = value[key];
    return typeof candidate === "string" ? candidate : undefined;
  } catch {
    return undefined;
  }
}

function readNumber(value: unknown, key: string): number | undefined {
  if (!isObjectLike(value)) return undefined;
  try {
    const candidate = value[key];
    return typeof candidate === "number" && Number.isFinite(candidate) ? candidate : undefined;
  } catch {
    return undefined;
  }
}

function readStatus(error: unknown): number | undefined {
  const direct = readNumber(error, "status");
  if (direct !== undefined) return Number.isInteger(direct) ? direct : undefined;
  const statusCode = readNumber(error, "statusCode");
  if (statusCode !== undefined && Number.isInteger(statusCode)) return statusCode;
  if (isObjectLike(error)) {
    try {
      const response = error.response;
      const nested = readNumber(response, "status");
      if (nested !== undefined && Number.isInteger(nested)) return nested;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function hasErrorName(error: unknown, expected: string): boolean {
  return readString(error, "name")?.toLowerCase() === expected;
}

function errorCodeIs(error: unknown, codes: readonly string[]): boolean {
  const code = readString(error, "code")?.toLowerCase();
  return code !== undefined && codes.includes(code);
}

function categoryForStatus(status: number): ErrorReason {
  if (status === 401 || status === 403) return "api_authentication";
  if (status === 404) return "opencode_not_found";
  if (status === 408 || status === 504) return "api_timeout";
  if (status === 429) return "api_rate_limited";
  if (status >= 500 && status <= 599) return "api_server";
  if (status >= 400 && status <= 499) return "api_malformed_response";
  return "unknown";
}

export function isErrorReason(value: unknown): value is ErrorReason {
  return typeof value === "string" && ERROR_REASON_SET.has(value);
}

/**
 * Map an arbitrary exception to a closed category without reading or
 * returning its message, stack, body, headers, or request data.
 *
 * Only `name`, `code`, and numeric `status`/`statusCode`/`response.status`
 * are inspected. SDK `TypeSafeError` without a status is treated as a
 * missing-key construction failure because explicit client options are
 * always valid; callers validate model/timeout/retries before construction.
 */
export function sanitizeErrorCategory(error: unknown): ErrorReason {
  if (error === null || error === undefined) return "unknown";
  if (typeof error === "string") {
    const lower = error.toLowerCase();
    if (lower.includes("abort")) return "api_aborted";
    if (lower.includes("timeout")) return "api_timeout";
    if (lower.includes("rate")) return "api_rate_limited";
    return "unknown";
  }
  if (
    hasErrorName(error, "apiuseraborterror") ||
    hasErrorName(error, "aborterror") ||
    errorCodeIs(error, ["aborted", "abort_error"])
  ) {
    return "api_aborted";
  }
  if (
    hasErrorName(error, "apitimeouterror") ||
    hasErrorName(error, "timeouterror") ||
    errorCodeIs(error, ["etimedout", "timeout"])
  ) {
    return "api_timeout";
  }
  if (hasErrorName(error, "apiconnectionerror")) {
    return "api_transport";
  }
  const status = readStatus(error);
  if (status !== undefined) return categoryForStatus(status);
  if (
    hasErrorName(error, "authenticationerror") ||
    hasErrorName(error, "permissiondeniederror")
  ) {
    return "api_authentication";
  }
  if (hasErrorName(error, "ratelimiterror")) {
    return "api_rate_limited";
  }
  if (hasErrorName(error, "internalservererror")) {
    return "api_server";
  }
  if (
    hasErrorName(error, "badrequesterror") ||
    hasErrorName(error, "unprocessableentityerror")
  ) {
    return "api_malformed_response";
  }
  if (hasErrorName(error, "notfounderror")) {
    return "opencode_not_found";
  }
  if (hasErrorName(error, "typesafeerror")) {
    return "missing_api_key";
  }
  if (errorCodeIs(error, ["not_found", "opencode_not_found"])) return "opencode_not_found";
  if (errorCodeIs(error, ["invalid_response", "opencode_invalid_response"])) {
    return "opencode_invalid_response";
  }
  if (errorCodeIs(error, ["enotfound", "econnreset", "econnrefused", "etimedout", "socketerror"])) {
    return "api_transport";
  }
  if (hasErrorName(error, "syntaxerror") || errorCodeIs(error, ["invalid_json", "malformed_response"])) {
    return "api_malformed_response";
  }
  return "unknown";
}

export function sanitizeHttpError(error: unknown): SanitizedError {
  const category = sanitizeErrorCategory(error);
  const status = readStatus(error);
  if (status === undefined || !Number.isInteger(status) || status < 100 || status > 599) {
    return Object.freeze({ category });
  }
  return Object.freeze({ category, status });
}

export const toSanitizedError = sanitizeHttpError;
export const safeErrorCategory = sanitizeErrorCategory;
