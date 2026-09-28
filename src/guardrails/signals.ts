/**
 * Stable, value-free guardrail signal codes and versioned policy identity.
 *
 * This module is pure decision logic with no I/O. Signal codes never contain
 * matched secret, command, or path values.
 */

import type {
  GuardrailSignalCode,
  HardDenySignalCode,
  ParseStatus,
} from "../domain.js";

/** Versioned local policy identity. Guardrails cannot be disabled. */
export const GUARDRAIL_POLICY_VERSION = "guardrails-v1" as const;

/** Hard-deny codes that force an immutable reject. */
export const HARD_DENY_SIGNAL_CODES: readonly HardDenySignalCode[] = Object.freeze([
  "secret_access",
  "destructive_operation",
  "privilege_change",
  "security_boundary_change",
  "obvious_exfiltration",
]);

/** Uncertainty codes that block automatic allow without forcing reject. */
export const UNCERTAINTY_SIGNAL_CODES: readonly GuardrailSignalCode[] = Object.freeze([
  "unparseable_syntax",
  "unknown_scope",
  "unresolved_path",
  "ambiguous_resource",
]);

/** Canonical deterministic ordering for every stable signal code. */
export const ALL_SIGNAL_CODES: readonly GuardrailSignalCode[] = Object.freeze([
  "secret_access",
  "destructive_operation",
  "privilege_change",
  "security_boundary_change",
  "obvious_exfiltration",
  "unparseable_syntax",
  "unknown_scope",
  "unresolved_path",
  "ambiguous_resource",
  "oversize",
  "redaction_incomplete",
  "missing_intent",
  "intent_ambiguous",
  "risk_unclear",
  "high_risk",
  "low_confidence",
  "invalid_answer",
  "queue_overflow",
  "api_unavailable",
]);

const HARD_DENY_SET: ReadonlySet<string> = new Set(HARD_DENY_SIGNAL_CODES);
const UNCERTAINTY_SET: ReadonlySet<string> = new Set(UNCERTAINTY_SIGNAL_CODES);
const ALL_SET: ReadonlySet<string> = new Set(ALL_SIGNAL_CODES);

function signalOrderIndex(code: GuardrailSignalCode): number {
  const index = ALL_SIGNAL_CODES.indexOf(code);
  return index < 0 ? ALL_SIGNAL_CODES.length : index;
}

/** True for the five non-bypassable hard-deny codes. */
export function isHardDenySignal(code: GuardrailSignalCode): code is HardDenySignalCode {
  return HARD_DENY_SET.has(code);
}

/** True for uncertainty codes that block auto-allow without forcing reject. */
export function isUncertaintySignal(code: GuardrailSignalCode): boolean {
  return UNCERTAINTY_SET.has(code);
}

/** True for any stable guardrail signal code. */
export function isKnownSignalCode(value: string): value is GuardrailSignalCode {
  return ALL_SET.has(value);
}

/** Deduplicate and deterministically order signal codes. */
export function dedupeAndSortSignals(codes: readonly GuardrailSignalCode[]): readonly GuardrailSignalCode[] {
  const seen = new Set<GuardrailSignalCode>();
  for (const code of codes) {
    if (isKnownSignalCode(code)) seen.add(code);
  }
  const sorted = [...seen].sort((left, right) => signalOrderIndex(left) - signalOrderIndex(right));
  return Object.freeze(sorted);
}

/** Extract only the hard-deny subset in deterministic order. */
export function hardDenyCodesFor(signals: readonly GuardrailSignalCode[]): readonly HardDenySignalCode[] {
  const filtered: HardDenySignalCode[] = [];
  for (const code of dedupeAndSortSignals(signals)) {
    if (isHardDenySignal(code)) filtered.push(code);
  }
  return Object.freeze(filtered);
}

/** Derive a deterministic parse status from a signal set. */
export function parseStatusForSignals(signals: readonly GuardrailSignalCode[]): ParseStatus {
  if (signals.includes("unparseable_syntax")) return "unparseable";
  if (
    signals.includes("unknown_scope") ||
    signals.includes("unresolved_path") ||
    signals.includes("ambiguous_resource")
  ) {
    return "unknown_scope";
  }
  return "parsed";
}
