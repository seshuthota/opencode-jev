/**
 * Deterministic guardrail orchestration.
 *
 * Pure decision logic with no I/O. Canonicalization is injected through the
 * narrow PathResolver port. Shell text is tokenized without execution.
 * Exfiltration requires source/sink correlation across the compound resource
 * set. Stable codes only; matched values never enter signals.
 */

import type {
  ActionCategory,
  GuardrailSignalCode,
  HardDenySignalCode,
  LocalResource,
  PermissionFacts,
  ParseStatus,
  GuardrailAssessment,
} from "../domain.js";
import { assessPathResource, type PathResolver } from "./path-policy.js";
import { assessShellCommand } from "./shell-policy.js";
import {
  GUARDRAIL_POLICY_VERSION,
  dedupeAndSortSignals,
  hardDenyCodesFor,
  parseStatusForSignals,
} from "./signals.js";

export { GUARDRAIL_POLICY_VERSION };
export type { PathResolver };

export type EvaluateGuardrailsPolicy = Readonly<{
  version?: unknown;
}> &
  Readonly<Record<string, unknown>>;

const RESOURCE_KINDS: ReadonlySet<string> = new Set([
  "path",
  "url",
  "command",
  "query",
  "generic",
  "unknown",
]);

const RESOURCE_SCOPES: ReadonlySet<string> = new Set([
  "project",
  "external",
  "home",
  "system",
  "secret",
  "protected",
  "unknown",
]);

const ACTION_CATEGORIES: ReadonlySet<string> = new Set([
  "read",
  "edit",
  "glob",
  "grep",
  "shell",
  "subagent",
  "skill",
  "question",
  "webfetch",
  "websearch",
  "external_directory",
  "execute",
  "plugin",
  "mcp",
  "other",
  "unknown",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function readProjectRoot(facts: Record<string, unknown>): string {
  const location = facts.location;
  if (isRecord(location) && typeof location.directory === "string" && location.directory.length > 0) {
    return location.directory;
  }
  const key = facts.key;
  if (isRecord(key) && typeof key.locationDirectory === "string" && key.locationDirectory.length > 0) {
    return key.locationDirectory;
  }
  return "";
}

function readActionCategory(facts: Record<string, unknown>): ActionCategory | string {
  const candidate = facts.actionCategory;
  if (typeof candidate === "string" && ACTION_CATEGORIES.has(candidate)) return candidate;
  return "unknown";
}

function hasControlChars(value: string): boolean {
  if (value.includes("\u0000")) return true;
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)) return true;
  return false;
}

interface UrlFinding {
  readonly signals: readonly GuardrailSignalCode[];
  readonly hasSecretSource: boolean;
  readonly hasNetworkSink: boolean;
}

function assessUrlValue(value: string): UrlFinding {
  if (value.length === 0 || value.length > 1_000_000 || hasControlChars(value)) {
    return { signals: Object.freeze(["unparseable_syntax"]), hasSecretSource: false, hasNetworkSink: false };
  }
  if (!value.includes("://")) {
    return {
      signals: Object.freeze(["ambiguous_resource", "unknown_scope"]),
      hasSecretSource: false,
      hasNetworkSink: false,
    };
  }
  const lower = value.toLowerCase();
  let hasSecretSource = false;
  let hasNetworkSink = false;
  if (
    lower.startsWith("https://") ||
    lower.startsWith("http://") ||
    lower.startsWith("ftp://")
  ) {
    hasNetworkSink = true;
  }
  const beforeFragment = lower.split("#").at(0) ?? lower;
  const hasUserinfo = /:\/\/[^/]*@/u.test(beforeFragment);
  const hasSensitiveQuery =
    beforeFragment.includes("token=") ||
    beforeFragment.includes("signature=") ||
    beforeFragment.includes("password=") ||
    beforeFragment.includes("passwd=") ||
    beforeFragment.includes("secret=") ||
    beforeFragment.includes("api_key=") ||
    beforeFragment.includes("apikey=") ||
    beforeFragment.includes("auth=") ||
    beforeFragment.includes("cookie") ||
    beforeFragment.includes("bearer");
  if (hasUserinfo || hasSensitiveQuery) {
    hasSecretSource = true;
    return {
      signals: Object.freeze(["secret_access"]),
      hasSecretSource,
      hasNetworkSink,
    };
  }
  return {
    signals: Object.freeze([]),
    hasSecretSource,
    hasNetworkSink,
  };
}

function frozenAssessment(
  signals: readonly GuardrailSignalCode[],
  parseStatus: ParseStatus,
  hardDeny: boolean,
  hardDenyCodes: readonly HardDenySignalCode[],
  eligibleForAutoAllow: boolean,
): GuardrailAssessment {
  const frozenSignals = Object.freeze([...signals]);
  const frozenHardDenyCodes = Object.freeze([...hardDenyCodes]);
  return Object.freeze({
    signals: frozenSignals,
    parseStatus,
    hardDeny,
    policyVersion: GUARDRAIL_POLICY_VERSION,
    hardDenyCodes: frozenHardDenyCodes,
    eligibleForAutoAllow,
  });
}

function manualAssessment(signals: readonly GuardrailSignalCode[]): GuardrailAssessment {
  const deduped = dedupeAndSortSignals(signals);
  const parseStatus = parseStatusForSignals(deduped);
  const hardDenyCodes = hardDenyCodesFor(deduped);
  const hardDeny = hardDenyCodes.length > 0;
  const eligibleForAutoAllow = !hardDeny && parseStatus === "parsed" && deduped.length === 0;
  return frozenAssessment(deduped, parseStatus, hardDeny, hardDenyCodes, eligibleForAutoAllow);
}

/**
 * Evaluate mandatory local policy for one observed permission request.
 *
 * The policy input is versioned and cannot disable guardrails: unknown fields
 * such as `enabled` or `disabled` are ignored and the canonical version is
 * always reported. A later Jev allow cannot change the returned `hardDeny`.
 */
export function evaluateGuardrails(
  facts: unknown,
  _policy?: unknown,
  resolver?: PathResolver,
): GuardrailAssessment {
  void _policy;
  if (!isRecord(facts)) {
    return manualAssessment(["ambiguous_resource", "unknown_scope"]);
  }
  const resourcesUnknown = facts.resources;
  if (!Array.isArray(resourcesUnknown)) {
    return manualAssessment(["ambiguous_resource", "unknown_scope"]);
  }

  const projectRoot = readProjectRoot(facts);
  const actionCategory = readActionCategory(facts);

  const collected: GuardrailSignalCode[] = [];
  let hasSecretSource = false;
  let hasNetworkSink = false;
  let oversize = false;

  if (actionCategory === "unknown") {
    collected.push("unknown_scope", "ambiguous_resource");
  }

  if (resourcesUnknown.length > 64) oversize = true;

  const resources = resourcesUnknown.slice(0, 10_000);
  for (const candidate of resources) {
    if (!isRecord(candidate)) {
      collected.push("ambiguous_resource", "unknown_scope");
      continue;
    }
    const value = candidate.value;
    const kind = candidate.kind;
    const scope = candidate.scope;
    if (typeof value !== "string" || value.length === 0) {
      collected.push("unparseable_syntax", "ambiguous_resource");
      continue;
    }
    if (value.length > 100_000) oversize = true;
    if (typeof kind !== "string" || !RESOURCE_KINDS.has(kind)) {
      collected.push("ambiguous_resource", "unknown_scope");
      continue;
    }
    if (typeof scope !== "string" || !RESOURCE_SCOPES.has(scope)) {
      collected.push("ambiguous_resource", "unknown_scope");
      continue;
    }
    if (hasControlChars(value) && kind !== "command") {
      collected.push("unparseable_syntax", "ambiguous_resource");
      continue;
    }

    if (kind === "path") {
      const finding = assessPathResource(value, {
        boundaries: { projectRoot },
        ...(resolver === undefined ? {} : { resolver }),
        actionCategory,
      });
      for (const signal of finding.signals) collected.push(signal);
      if (finding.scope === "secret" || finding.signals.includes("secret_access")) {
        hasSecretSource = true;
      }
      continue;
    }

    if (kind === "command") {
      const finding = assessShellCommand(value);
      for (const signal of finding.signals) collected.push(signal);
      if (finding.hasSecretSource) hasSecretSource = true;
      if (finding.hasNetworkSink) hasNetworkSink = true;
      continue;
    }

    if (kind === "url") {
      const finding = assessUrlValue(value);
      for (const signal of finding.signals) collected.push(signal);
      if (finding.hasSecretSource) hasSecretSource = true;
      if (finding.hasNetworkSink) hasNetworkSink = true;
      continue;
    }

    if (kind === "query") {
      if (value.length > 100_000) oversize = true;
      continue;
    }

    collected.push("ambiguous_resource", "unknown_scope");
    const shellFinding = assessShellCommand(value);
    for (const signal of shellFinding.signals) {
      if (signal === "unparseable_syntax") continue;
      collected.push(signal);
    }
    if (shellFinding.hasSecretSource) hasSecretSource = true;
    if (shellFinding.hasNetworkSink) hasNetworkSink = true;
    if (projectRoot.length > 0) {
      const pathFinding = assessPathResource(value, {
        boundaries: { projectRoot },
        ...(resolver === undefined ? {} : { resolver }),
        actionCategory,
      });
      for (const signal of pathFinding.signals) {
        if (signal === "unresolved_path" || signal === "unknown_scope") continue;
        collected.push(signal);
      }
      if (pathFinding.scope === "secret") hasSecretSource = true;
    }
  }

  if (resourcesUnknown.length === 0) {
    collected.push("ambiguous_resource", "unknown_scope");
  }

  if (hasSecretSource && hasNetworkSink) {
    collected.push("obvious_exfiltration");
  }

  if (oversize) collected.push("oversize");

  const deduped = dedupeAndSortSignals(collected);
  const parseStatus = parseStatusForSignals(deduped);
  const hardDenyCodes = hardDenyCodesFor(deduped);
  const hardDeny = hardDenyCodes.length > 0;
  const eligibleForAutoAllow = !hardDeny && parseStatus === "parsed" && deduped.length === 0;

  return frozenAssessment(deduped, parseStatus, hardDeny, hardDenyCodes, eligibleForAutoAllow);
}

/** True when the assessment requires an immutable reject. */
export function isHardDenied(assessment: GuardrailAssessment): boolean {
  return assessment.hardDeny;
}

/** True when guardrails permit a later stage to consider automatic allow. */
export function isAutoAllowEligible(assessment: GuardrailAssessment): boolean {
  return assessment.eligibleForAutoAllow;
}

export type { LocalResource, PermissionFacts };
