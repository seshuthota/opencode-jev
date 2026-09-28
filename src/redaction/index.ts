/** Public, provider-neutral redaction boundary for Slice 1. */

import type { RedactedResource, ResourceKind, ResourceScope } from "../domain.js";
import {
  projectPathDetailed,
  type PathRedactionOptions,
} from "./paths.js";
import {
  redactCommandDetailed,
  redactIntentDetailed,
  redactTextDetailed,
  redactUrlDetailed,
  type TextRedactionOptions,
  type TextRedactionResult,
} from "./text.js";

export * from "./paths.js";
export * from "./text.js";

export interface ResourceRedactionOptions extends TextRedactionOptions {
  readonly pathOptions?: PathRedactionOptions;
  readonly maxChars?: number;
}

export interface ResourceRedactionResult {
  /** Omitted when a safe resource projection cannot be established. */
  readonly resource?: RedactedResource;
  readonly complete: boolean;
  readonly truncated: boolean;
}

/**
 * Project one normalized resource. No arbitrary resource object is inspected
 * or copied; callers must pass the already-classified kind and value.
 */
export function redactResourceDetailed(
  value: unknown,
  kind: ResourceKind,
  scope: ResourceScope,
  options: ResourceRedactionOptions = {},
): ResourceRedactionResult {
  const maxChars = options.maxChars ?? 512;
  if (typeof value !== "string" || value.length === 0) {
    return { complete: false, truncated: false };
  }

  let projection: TextRedactionResult;
  if (kind === "url") {
    projection = redactUrlDetailed(value, { ...options, maxChars });
  } else if (kind === "path") {
    const pathProjection = projectPathDetailed(value, {
      ...options.pathOptions,
      maxChars,
    });
    const pathText = redactTextDetailed(pathProjection.value, {
      ...options,
      maxChars,
    });
    projection = Object.freeze({
      ...pathText,
      complete: pathProjection.complete && pathText.complete,
      truncated: pathProjection.truncated || pathText.truncated,
      redactionComplete: pathProjection.complete && pathText.complete,
    });
  } else if (kind === "command") {
    projection = redactCommandDetailed(value, { ...options, maxChars });
  } else if (kind === "query") {
    projection = redactTextDetailed(value, { ...options, maxChars });
  } else {
    projection = redactTextDetailed(value, { ...options, maxChars });
  }

  const safeDisplay = projection.complete ? projection.value : "<resource-omitted>";
  // A bounded head/tail projection is still safe and is retained with its
  // truncation flag. An incomplete (rather than merely truncated) projection
  // is omitted entirely.
  const resource: RedactedResource | undefined = projection.complete
    ? Object.freeze({ kind, scope, display: safeDisplay })
    : undefined;
  return Object.freeze({
    ...(resource === undefined ? {} : { resource }),
    complete: projection.complete,
    truncated: projection.truncated,
  });
}

export function redactResource(
  value: unknown,
  kind: ResourceKind,
  scope: ResourceScope,
  options: ResourceRedactionOptions = {},
): RedactedResource | undefined {
  return redactResourceDetailed(value, kind, scope, options).resource;
}

export function redactIntent(
  input: unknown,
  options: TextRedactionOptions = {},
): string {
  return redactIntentDetailed(input, options).value;
}

export function redactCommand(
  input: unknown,
  options: TextRedactionOptions = {},
): string {
  return redactCommandDetailed(input, options).value;
}

export function redactText(
  input: unknown,
  options: TextRedactionOptions = {},
): string {
  return redactTextDetailed(input, options).value;
}

export function redactUrl(
  input: unknown,
  options: TextRedactionOptions = {},
): string {
  return redactUrlDetailed(input, options).value;
}
