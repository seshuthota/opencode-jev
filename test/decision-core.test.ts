import { describe, expect, it } from "vitest";

import type {
  AutomaticReply,
  CoreDecision,
  GuardrailAssessment,
  GuardrailSignalCode,
  IntentAlignment,
  JevEvaluation,
  PolicyDecisionLabel,
  RiskClass,
} from "../src/domain.js";
import type { PluginConfigThresholds } from "../src/config.js";
import { decide, mapAutomaticReply } from "../src/decision/core.js";

type IsAssignable<From, To> = [From] extends [To] ? true : false;
type Assert<T extends true> = T;
/** Compile-time lock: `always` is not an automatic reply. */
export type AlwaysIsNotAutomaticReply = Assert<
  IsAssignable<"always", AutomaticReply> extends false ? true : false
>;

const THRESHOLDS: PluginConfigThresholds = Object.freeze({
  allowConfidence: 0.98,
  allowProbability: 0.95,
  elevatedAllowConfidence: 0.99,
  denyConfidence: 0.95,
  denyProbability: 0.9,
  auxiliaryConfidence: 0.9,
});

const SENTINEL = "DECISION_SENTINEL_SECRET_012345678901234567890";

function probsFor(
  labels: readonly string[],
  selected: string,
  selectedProb: number,
): Record<string, number> {
  const others = labels.filter((label) => label !== selected);
  const each = others.length === 0 ? 0 : (1 - selectedProb) / others.length;
  const probs: Record<string, number> = {};
  for (const label of labels) {
    probs[label] = label === selected ? selectedProb : each;
  }
  return probs;
}

function choiceFor<Label extends string>(
  choice: Label,
  labels: readonly Label[],
  confidence: number,
  selectedProb: number,
): Record<string, unknown> {
  return {
    type: "choice",
    choice,
    confidence,
    probabilities: probsFor(labels as readonly string[], choice, selectedProb),
  };
}

function guardrailsFor(
  overrides: Partial<GuardrailAssessment> = {},
): GuardrailAssessment {
  const signals = overrides.signals ?? [];
  const hardDenyCodes = overrides.hardDenyCodes ?? [];
  return Object.freeze({
    parseStatus: "parsed",
    hardDeny: false,
    policyVersion: "guardrails-v1",
    eligibleForAutoAllow: true,
    ...overrides,
    signals: Object.freeze([...signals]),
    hardDenyCodes: Object.freeze([...hardDenyCodes]),
  }) as GuardrailAssessment;
}

function jevFor(opts: {
  intentChoice?: IntentAlignment;
  intentConf?: number;
  intentProb?: number;
  riskChoice?: RiskClass;
  riskConf?: number;
  riskProb?: number;
  finalChoice?: PolicyDecisionLabel;
  finalConf?: number;
  finalProb?: number;
  modelVersion?: string;
} = {}): JevEvaluation {
  const intentChoice = opts.intentChoice ?? "supported";
  const intentConf = opts.intentConf ?? 0.95;
  const intentProb = opts.intentProb ?? 0.95;
  const riskChoice = opts.riskChoice ?? "routine";
  const riskConf = opts.riskConf ?? 0.95;
  const riskProb = opts.riskProb ?? 0.95;
  const finalChoice = opts.finalChoice ?? "allow_once";
  const finalConf = opts.finalConf ?? 0.99;
  const finalProb = opts.finalProb ?? 0.96;
  const modelVersion = opts.modelVersion ?? "jev-test-v1";
  const intentLabels: readonly IntentAlignment[] = ["supported", "contradicted", "unclear"];
  const riskLabels: readonly RiskClass[] = ["routine", "elevated", "high", "unclear"];
  const finalLabels: readonly PolicyDecisionLabel[] = ["allow_once", "deny", "manual_review"];
  return Object.freeze({
    auxiliary: Object.freeze({
      intent_alignment: Object.freeze(
        choiceFor(intentChoice, intentLabels, intentConf, intentProb),
      ),
      risk_class: Object.freeze(choiceFor(riskChoice, riskLabels, riskConf, riskProb)),
    }),
    final: Object.freeze(choiceFor(finalChoice, finalLabels, finalConf, finalProb)),
    modelVersion,
    usage: Object.freeze({ inputTokens: 12, outputTokens: 4 }),
  }) as unknown as JevEvaluation;
}

function expectFrozenDecision(decision: CoreDecision): void {
  expect(Object.isFrozen(decision)).toBe(true);
}

function expectNoSentinel(value: unknown): void {
  const serialized = JSON.stringify(value) ?? "";
  expect(serialized).not.toContain(SENTINEL);
}

describe("routine allow and reply mapping", () => {
  it("routine allow maps to once", () => {
    const decision = decide(guardrailsFor(), jevFor(), THRESHOLDS);
    expect(decision).toEqual({ kind: "ALLOW_ONCE", reason: "allow_once", confidence: "high" });
    expectFrozenDecision(decision);
    expect(mapAutomaticReply(decision)).toBe("once");
    expectNoSentinel(decision);
  });

  it("is pure synchronous with no promise", () => {
    const decision = decide(guardrailsFor(), jevFor(), THRESHOLDS);
    expect(decision).not.toBeInstanceOf(Promise);
    expect(typeof decision.kind).toBe("string");
    const reply = mapAutomaticReply(decision);
    expect(reply).not.toBeInstanceOf(Promise);
  });
});

describe("exact threshold boundaries and just-below cases", () => {
  it("allow confidence exactly at floor allows; just below is manual", () => {
    const atFloor = decide(
      guardrailsFor(),
      jevFor({ finalConf: 0.98, finalProb: 0.96 }),
      THRESHOLDS,
    );
    expect(atFloor.kind).toBe("ALLOW_ONCE");
    expect(atFloor.reason).toBe("allow_once");

    const below = decide(
      guardrailsFor(),
      jevFor({ finalConf: 0.979, finalProb: 0.96 }),
      THRESHOLDS,
    );
    expect(below.kind).toBe("MANUAL_PENDING");
    expect(below.reason).toBe("low_confidence");
    expect(mapAutomaticReply(below)).toBeUndefined();
  });

  it("allow probability exactly at floor allows; just below is manual", () => {
    const atFloor = decide(
      guardrailsFor(),
      jevFor({ finalConf: 0.99, finalProb: 0.95 }),
      THRESHOLDS,
    );
    expect(atFloor.kind).toBe("ALLOW_ONCE");

    const below = decide(
      guardrailsFor(),
      jevFor({ finalConf: 0.99, finalProb: 0.949 }),
      THRESHOLDS,
    );
    expect(below.kind).toBe("MANUAL_PENDING");
    expect(below.reason).toBe("low_confidence");
  });

  it("elevated allow requires stricter confidence; boundary and just-below", () => {
    const elevatedAt = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "elevated", finalConf: 0.99, finalProb: 0.96 }),
      THRESHOLDS,
    );
    expect(elevatedAt.kind).toBe("ALLOW_ONCE");

    const elevatedBelow = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "elevated", finalConf: 0.989, finalProb: 0.96 }),
      THRESHOLDS,
    );
    expect(elevatedBelow.kind).toBe("MANUAL_PENDING");
    expect(elevatedBelow.reason).toBe("low_confidence");

    // Same 0.989 confidence would allow for routine risk.
    const routineSame = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "routine", finalConf: 0.989, finalProb: 0.96 }),
      THRESHOLDS,
    );
    expect(routineSame.kind).toBe("ALLOW_ONCE");
  });

  it("deny confidence and probability boundaries", () => {
    const denyAt = decide(
      guardrailsFor(),
      jevFor({ finalChoice: "deny", finalConf: 0.95, finalProb: 0.9 }),
      THRESHOLDS,
    );
    expect(denyAt).toEqual({ kind: "REJECT", reason: "confident_deny", confidence: "high" });
    expect(mapAutomaticReply(denyAt)).toBe("reject");

    const denyConfBelow = decide(
      guardrailsFor(),
      jevFor({ finalChoice: "deny", finalConf: 0.949, finalProb: 0.9 }),
      THRESHOLDS,
    );
    expect(denyConfBelow.kind).toBe("MANUAL_PENDING");
    expect(denyConfBelow.reason).toBe("low_confidence");
    expect(mapAutomaticReply(denyConfBelow)).toBeUndefined();

    const denyProbBelow = decide(
      guardrailsFor(),
      jevFor({ finalChoice: "deny", finalConf: 0.96, finalProb: 0.899 }),
      THRESHOLDS,
    );
    expect(denyProbBelow.kind).toBe("MANUAL_PENDING");
    expect(denyProbBelow.reason).toBe("low_confidence");
  });

  it("auxiliary floor boundaries for intent and risk", () => {
    const intentAt = decide(
      guardrailsFor(),
      jevFor({ intentConf: 0.9, intentProb: 0.9 }),
      THRESHOLDS,
    );
    expect(intentAt.kind).toBe("ALLOW_ONCE");

    const intentConfBelow = decide(
      guardrailsFor(),
      jevFor({ intentConf: 0.899, intentProb: 0.95 }),
      THRESHOLDS,
    );
    expect(intentConfBelow.kind).toBe("MANUAL_PENDING");
    expect(intentConfBelow.reason).toBe("low_confidence");

    const intentProbBelow = decide(
      guardrailsFor(),
      jevFor({ intentConf: 0.95, intentProb: 0.899 }),
      THRESHOLDS,
    );
    expect(intentProbBelow.kind).toBe("MANUAL_PENDING");
    expect(intentProbBelow.reason).toBe("low_confidence");

    const riskConfBelow = decide(
      guardrailsFor(),
      jevFor({ riskConf: 0.899, riskProb: 0.95 }),
      THRESHOLDS,
    );
    expect(riskConfBelow.kind).toBe("MANUAL_PENDING");
    expect(riskConfBelow.reason).toBe("low_confidence");

    const riskProbBelow = decide(
      guardrailsFor(),
      jevFor({ riskConf: 0.95, riskProb: 0.899 }),
      THRESHOLDS,
    );
    expect(riskProbBelow.kind).toBe("MANUAL_PENDING");
    expect(riskProbBelow.reason).toBe("low_confidence");
  });
});

describe("hard-deny, high-risk, and deny cases", () => {
  it("hard-deny rejects immediately and maps to reject", () => {
    const guardrails = guardrailsFor({
      signals: ["secret_access"],
      hardDeny: true,
      hardDenyCodes: ["secret_access"],
      eligibleForAutoAllow: false,
    });
    const decision = decide(guardrails, jevFor(), THRESHOLDS);
    expect(decision).toEqual({ kind: "REJECT", reason: "hard_deny", confidence: "high" });
    expect(mapAutomaticReply(decision)).toBe("reject");
  });

  it("Jev allow cannot override local hard-deny", () => {
    const guardrails = guardrailsFor({
      signals: ["destructive_operation"],
      hardDeny: true,
      hardDenyCodes: ["destructive_operation"],
      eligibleForAutoAllow: false,
    });
    const jev = jevFor({ finalChoice: "allow_once", finalConf: 0.99, finalProb: 0.99 });
    const decision = decide(guardrails, jev, THRESHOLDS);
    expect(decision.kind).toBe("REJECT");
    expect(decision.reason).toBe("hard_deny");
    expect(mapAutomaticReply(decision)).toBe("reject");
  });

  it("hard-deny remains reject even with invalid Jev and thresholds", () => {
    const guardrails = guardrailsFor({
      signals: ["privilege_change"],
      hardDeny: true,
      hardDenyCodes: ["privilege_change"],
      eligibleForAutoAllow: false,
    });
    const invalidJev = null;
    const invalidThresholds = { allowConfidence: 2 };
    const decision = decide(guardrails, invalidJev, invalidThresholds);
    expect(decision.kind).toBe("REJECT");
    expect(decision.reason).toBe("hard_deny");
  });

  it("confident deny rejects; high-risk and unclear risk stay manual", () => {
    const deny = decide(
      guardrailsFor(),
      jevFor({ finalChoice: "deny", finalConf: 0.97, finalProb: 0.93 }),
      THRESHOLDS,
    );
    expect(deny.kind).toBe("REJECT");
    expect(deny.reason).toBe("confident_deny");

    const highRisk = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "high", finalConf: 0.99, finalProb: 0.99 }),
      THRESHOLDS,
    );
    expect(highRisk.kind).toBe("MANUAL_PENDING");
    expect(highRisk.reason).toBe("risk_high");
    expect(mapAutomaticReply(highRisk)).toBeUndefined();

    const unclearRisk = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "unclear", finalConf: 0.99, finalProb: 0.99 }),
      THRESHOLDS,
    );
    expect(unclearRisk.kind).toBe("MANUAL_PENDING");
    expect(unclearRisk.reason).toBe("risk_unclear");
  });

  it("stricter elevated allow succeeds with high confidence", () => {
    const decision = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "elevated", finalConf: 0.995, finalProb: 0.97 }),
      THRESHOLDS,
    );
    expect(decision.kind).toBe("ALLOW_ONCE");
    expect(mapAutomaticReply(decision)).toBe("once");
  });
});

describe("low confidence, manual_review, disagreement, missing intent", () => {
  it("low final confidence for allow is manual", () => {
    const decision = decide(
      guardrailsFor(),
      jevFor({ finalConf: 0.5, finalProb: 0.5 }),
      THRESHOLDS,
    );
    expect(decision.kind).toBe("MANUAL_PENDING");
    expect(decision.reason).toBe("low_confidence");
    expect(mapAutomaticReply(decision)).toBeUndefined();
  });

  it("manual_review is manual at any confidence, even very high", () => {
    for (const confidence of [0.2, 0.9, 0.99]) {
      const decision = decide(
        guardrailsFor(),
        jevFor({ finalChoice: "manual_review", finalConf: confidence, finalProb: 0.9 }),
        THRESHOLDS,
      );
      expect(decision.kind).toBe("MANUAL_PENDING");
      expect(decision.reason).toBe("manual_review");
      expect(mapAutomaticReply(decision)).toBeUndefined();
    }
  });

  it("disagreement between final allow and auxiliaries stays manual", () => {
    const intentDisagree = decide(
      guardrailsFor(),
      jevFor({ intentChoice: "contradicted", finalChoice: "allow_once" }),
      THRESHOLDS,
    );
    expect(intentDisagree.kind).toBe("MANUAL_PENDING");
    expect(intentDisagree.reason).toBe("intent_ambiguous");

    const intentUnclear = decide(
      guardrailsFor(),
      jevFor({ intentChoice: "unclear", finalChoice: "allow_once" }),
      THRESHOLDS,
    );
    expect(intentUnclear.kind).toBe("MANUAL_PENDING");
    expect(intentUnclear.reason).toBe("intent_ambiguous");

    const riskDisagree = decide(
      guardrailsFor(),
      jevFor({ riskChoice: "high", finalChoice: "allow_once" }),
      THRESHOLDS,
    );
    expect(riskDisagree.kind).toBe("MANUAL_PENDING");
    expect(riskDisagree.reason).toBe("risk_high");
  });

  it("missing intent signal blocks auto-allow", () => {
    const guardrails = guardrailsFor({
      signals: ["missing_intent"],
      parseStatus: "parsed",
      hardDeny: false,
      hardDenyCodes: [],
      eligibleForAutoAllow: false,
    });
    const decision = decide(guardrails, jevFor(), THRESHOLDS);
    expect(decision.kind).toBe("MANUAL_PENDING");
    expect(decision.reason).toBe("missing_intent");
    expect(mapAutomaticReply(decision)).toBeUndefined();
  });

  it("deny below thresholds is manual low_confidence", () => {
    const decision = decide(
      guardrailsFor(),
      jevFor({ finalChoice: "deny", finalConf: 0.6, finalProb: 0.6 }),
      THRESHOLDS,
    );
    expect(decision.kind).toBe("MANUAL_PENDING");
    expect(decision.reason).toBe("low_confidence");
  });
});

describe("malformed distributions, unknown model, validation failures", () => {
  it("malformed probability sums are manual malformed_jev_answer", () => {
    const badSums: Array<Record<string, number>> = [
      { supported: 0.3, contradicted: 0.1, unclear: 0.1 },
      { supported: 0.7, contradicted: 0.5, unclear: 0.3 },
    ];
    for (const probabilities of badSums) {
      const jev = {
        auxiliary: {
          intent_alignment: {
            type: "choice",
            choice: "supported",
            confidence: 0.99,
            probabilities,
          },
          risk_class: {
            type: "choice",
            choice: "routine",
            confidence: 0.95,
            probabilities: probsFor(
              ["routine", "elevated", "high", "unclear"],
              "routine",
              0.95,
            ),
          },
        },
        final: {
          type: "choice",
          choice: "allow_once",
          confidence: 0.99,
          probabilities: probsFor(["allow_once", "deny", "manual_review"], "allow_once", 0.96),
        },
        modelVersion: "jev-test-v1",
        usage: { inputTokens: 1, outputTokens: 1 },
      };
      const decision = decide(guardrailsFor(), jev, THRESHOLDS);
      expect(decision.kind).toBe("MANUAL_PENDING");
      expect(decision.reason).toBe("malformed_jev_answer");
    }
  });

  it("missing, extra, out-of-range, NaN, and non-choice answers are manual", () => {
    const base = jevFor();
    const cases: unknown[] = [
      // Missing probabilities label.
      {
        ...base,
        auxiliary: {
          ...base.auxiliary,
          intent_alignment: {
            type: "choice",
            choice: "supported",
            confidence: 0.99,
            probabilities: { supported: 1 },
          },
        },
      },
      // Extra label.
      {
        ...base,
        auxiliary: {
          ...base.auxiliary,
          intent_alignment: {
            type: "choice",
            choice: "supported",
            confidence: 0.99,
            probabilities: {
              supported: 0.9,
              contradicted: 0.05,
              unclear: 0.04,
              extra: 0.01,
            },
          },
        },
      },
      // Out-of-range probability.
      {
        ...base,
        final: {
          type: "choice",
          choice: "allow_once",
          confidence: 0.99,
          probabilities: { allow_once: 1.5, deny: -0.25, manual_review: -0.25 },
        },
      },
      // NaN confidence.
      {
        ...base,
        final: {
          type: "choice",
          choice: "allow_once",
          confidence: Number.NaN,
          probabilities: probsFor(["allow_once", "deny", "manual_review"], "allow_once", 0.96),
        },
      },
      // Non-choice type.
      {
        ...base,
        auxiliary: {
          ...base.auxiliary,
          risk_class: {
            type: "text",
            choice: "routine",
            confidence: 0.95,
            probabilities: probsFor(
              ["routine", "elevated", "high", "unclear"],
              "routine",
              0.95,
            ),
          },
        },
      },
      // Unknown final label.
      {
        ...base,
        final: {
          type: "choice",
          choice: "approve",
          confidence: 0.99,
          probabilities: { approve: 0.9, deny: 0.05, manual_review: 0.05 },
        },
      },
    ];
    for (const malformed of cases) {
      const decision = decide(guardrailsFor(), malformed, THRESHOLDS);
      expect(decision.kind).toBe("MANUAL_PENDING");
      expect(decision.reason).toBe("malformed_jev_answer");
      expect(mapAutomaticReply(decision)).toBeUndefined();
    }
  });

  it("unknown model identity is manual", () => {
    for (const modelVersion of [
      "",
      "unknown",
      "bad model!",
      "jev latest",
      "x".repeat(129),
      "jev-test-v1 with spaces",
    ]) {
      const decision = decide(guardrailsFor(), jevFor({ modelVersion }), THRESHOLDS);
      expect(decision.kind).toBe("MANUAL_PENDING");
      expect(decision.reason).toBe("malformed_jev_answer");
      expectNoSentinel(decision);
    }
  });

  it("validation failures are manual unless hard-deny", () => {
    expect(decide(null, jevFor(), THRESHOLDS).kind).toBe("MANUAL_PENDING");
    expect(decide(guardrailsFor(), null, THRESHOLDS).reason).toBe("malformed_jev_answer");
    expect(decide(guardrailsFor(), jevFor(), null).reason).toBe("malformed_request");
    expect(
      decide(guardrailsFor(), jevFor(), { ...THRESHOLDS, elevatedAllowConfidence: 0.5 }).reason,
    ).toBe("malformed_request");
    expect(decide(undefined, undefined, undefined).kind).toBe("MANUAL_PENDING");

    const malformedGuardrails = { signals: ["not_a_signal"], hardDeny: false };
    const manual = decide(malformedGuardrails, jevFor(), THRESHOLDS);
    expect(manual.kind).toBe("MANUAL_PENDING");
    expect(manual.reason).toBe("malformed_request");
  });

  it("unknown final label shape is manual", () => {
    const jev = jevFor();
    const polluted = {
      ...jev,
      final: { type: "choice", choice: "ALLOW_ONCE", confidence: 0.99, probabilities: {} },
    };
    const decision = decide(guardrailsFor(), polluted, THRESHOLDS);
    expect(decision.kind).toBe("MANUAL_PENDING");
    expect(decision.reason).toBe("malformed_jev_answer");
  });
});

describe("uncertain parser and risk signals block auto-allow", () => {
  const blocking: Array<{ signal: GuardrailSignalCode; reason: string }> = [
    { signal: "unparseable_syntax", reason: "malformed_request" },
    { signal: "unknown_scope", reason: "malformed_request" },
    { signal: "unresolved_path", reason: "malformed_request" },
    { signal: "ambiguous_resource", reason: "malformed_request" },
    { signal: "oversize", reason: "malformed_request" },
    { signal: "redaction_incomplete", reason: "malformed_request" },
    { signal: "missing_intent", reason: "missing_intent" },
    { signal: "intent_ambiguous", reason: "intent_ambiguous" },
    { signal: "risk_unclear", reason: "risk_unclear" },
    { signal: "high_risk", reason: "risk_high" },
    { signal: "low_confidence", reason: "low_confidence" },
    { signal: "invalid_answer", reason: "malformed_jev_answer" },
    { signal: "queue_overflow", reason: "queue_overflow" },
    { signal: "api_unavailable", reason: "malformed_request" },
  ];

  it.each(blocking)("$signal blocks allow even when eligible flag is true", ({
    signal,
    reason,
  }) => {
    // eligibleForAutoAllow true is ignored; signals win.
    const guardrails = guardrailsFor({
      signals: [signal],
      parseStatus: "parsed",
      hardDeny: false,
      hardDenyCodes: [],
      eligibleForAutoAllow: true,
    });
    const decision = decide(guardrails, jevFor(), THRESHOLDS);
    expect(decision.kind).toBe("MANUAL_PENDING");
    expect(decision.reason).toBe(reason);
    expect(mapAutomaticReply(decision)).toBeUndefined();
  });

  it("non-parsed status blocks allow", () => {
    for (const parseStatus of ["unparseable", "unknown_scope"] as const) {
      const guardrails = guardrailsFor({
        signals: [],
        parseStatus,
        hardDeny: false,
        hardDenyCodes: [],
        eligibleForAutoAllow: true,
      });
      const decision = decide(guardrails, jevFor(), THRESHOLDS);
      expect(decision.kind).toBe("MANUAL_PENDING");
      expect(decision.reason).toBe("malformed_request");
    }
  });

  it("deny still rejects with uncertain signals when thresholds met", () => {
    const guardrails = guardrailsFor({
      signals: ["unparseable_syntax"],
      parseStatus: "unparseable",
      hardDeny: false,
      hardDenyCodes: [],
      eligibleForAutoAllow: false,
    });
    const decision = decide(
      guardrails,
      jevFor({ finalChoice: "deny", finalConf: 0.97, finalProb: 0.93 }),
      THRESHOLDS,
    );
    expect(decision.kind).toBe("REJECT");
    expect(decision.reason).toBe("confident_deny");
  });
});

describe("reply mapping is closed and never always", () => {
  it("only ALLOW_ONCE maps to once and only REJECT maps to reject", () => {
    const allow: CoreDecision = Object.freeze({
      kind: "ALLOW_ONCE",
      reason: "allow_once",
      confidence: "high",
    });
    const hardReject: CoreDecision = Object.freeze({
      kind: "REJECT",
      reason: "hard_deny",
      confidence: "high",
    });
    const confidentReject: CoreDecision = Object.freeze({
      kind: "REJECT",
      reason: "confident_deny",
      confidence: "high",
    });
    expect(mapAutomaticReply(allow)).toBe("once");
    expect(mapAutomaticReply(hardReject)).toBe("reject");
    expect(mapAutomaticReply(confidentReject)).toBe("reject");
  });

  it("low and medium manuals emit no reply", () => {
    const low: CoreDecision = Object.freeze({
      kind: "MANUAL_PENDING",
      reason: "low_confidence",
      confidence: "low",
    });
    const medium: CoreDecision = Object.freeze({
      kind: "MANUAL_PENDING",
      reason: "manual_review",
      confidence: "medium",
    });
    const highManual: CoreDecision = Object.freeze({
      kind: "MANUAL_PENDING",
      reason: "risk_high",
      confidence: "high",
    });
    expect(mapAutomaticReply(low)).toBeUndefined();
    expect(mapAutomaticReply(medium)).toBeUndefined();
    expect(mapAutomaticReply(highManual)).toBeUndefined();
  });

  it("exhaustive mapping never produces always", () => {
    const kinds = ["ALLOW_ONCE", "REJECT", "MANUAL_PENDING"] as const;
    for (const kind of kinds) {
      const reason =
        kind === "ALLOW_ONCE" ? "allow_once" : kind === "REJECT" ? "hard_deny" : "unknown";
      const decision = Object.freeze({ kind, reason, confidence: "high" });
      const reply = mapAutomaticReply(decision);
      expect(reply).not.toBe("always");
      if (kind === "ALLOW_ONCE") expect(reply).toBe("once");
      else if (kind === "REJECT") expect(reply).toBe("reject");
      else expect(reply).toBeUndefined();
    }
    // Runtime exhaustive check: no branch can construct "always".
    const replies = new Set<string>();
    for (const kind of kinds) {
      const decision = Object.freeze({
        kind,
        reason: kind === "ALLOW_ONCE" ? "allow_once" : kind === "REJECT" ? "hard_deny" : "low_confidence",
        confidence: "low",
      });
      const reply = mapAutomaticReply(decision);
      if (reply !== undefined) replies.add(reply);
    }
    expect([...replies].sort()).toEqual(["once", "reject"]);
  });

  it("malformed decisions emit no reply and never always", () => {
    for (const malformed of [
      null,
      undefined,
      {},
      { kind: "ALLOW_ONCE" },
      { kind: "REJECT", reason: "hard_deny" },
      { kind: "ALLOW_ONCE", reason: "allow_once", confidence: "ultra" },
      { kind: "ALLOW_ONCE", reason: "hard_deny", confidence: "high" },
      { kind: "REJECT", reason: "allow_once", confidence: "high" },
      { kind: "MANUAL_PENDING", reason: "allow_once", confidence: "low" },
      { kind: "always", reason: "allow_once", confidence: "high" },
      "once",
      "always",
      42,
    ]) {
      expect(mapAutomaticReply(malformed)).toBeUndefined();
      expect(mapAutomaticReply(malformed)).not.toBe("always");
    }
  });

  it("decide outputs are frozen and sanitized", () => {
    const decision = decide(guardrailsFor(), jevFor(), THRESHOLDS);
    expect(Object.isFrozen(decision)).toBe(true);
    expectNoSentinel(decision);
    expect(Object.keys(decision).sort()).toEqual(["confidence", "kind", "reason"]);
  });
});
