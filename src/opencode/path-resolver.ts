/**
 * Production filesystem path resolution for the permission adapter.
 *
 * Guardrail policy remains provider-neutral and receives this narrow resolver
 * as a port. Existing paths are resolved through the filesystem so symlinks
 * cannot disguise an external, protected, or secret target. For a path that
 * does not exist yet, the nearest existing ancestor is resolved and the
 * missing suffix is appended without touching the filesystem.
 */

import { realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";

import type { PathResolver } from "../guardrails/path-policy.js";

const MAX_ANCESTOR_STEPS = 1024;

function isMissingPathError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = Reflect.get(error, "code");
  return code === "ENOENT";
}

/**
 * Resolve a path without requiring its final components to exist.
 *
 * Permission resources are expected to be absolute after the guardrail layer
 * joins project-relative values to the project root. Any malformed,
 * inaccessible, or otherwise unresolvable value returns undefined, which
 * makes the request ineligible for automatic approval.
 */
export function canonicalizeNearestExisting(input: string): string | undefined {
  try {
    if (typeof input !== "string" || input.length === 0 || input.includes("\u0000")) {
      return undefined;
    }
    if (!isAbsolute(input)) return undefined;

    const normalized = resolve(input);
    let cursor = normalized;
    const missingSuffix: string[] = [];

    for (let step = 0; step < MAX_ANCESTOR_STEPS; step += 1) {
      try {
        const existing = realpathSync.native(cursor);
        return missingSuffix.length === 0
          ? existing
          : resolve(existing, ...missingSuffix.reverse());
      } catch (error) {
        if (!isMissingPathError(error)) return undefined;
        const parent = dirname(cursor);
        if (parent === cursor) return undefined;
        const segment = basename(cursor);
        if (segment.length === 0) return undefined;
        missingSuffix.push(segment);
        cursor = parent;
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export const FILESYSTEM_PATH_RESOLVER: PathResolver = Object.freeze({
  canonicalize: canonicalizeNearestExisting,
});
