/**
 * Local, provider-neutral domain contracts.
 *
 * These types deliberately contain no OpenCode or TypeSafe SDK types. Later
 * adapters may translate their public contracts into these closed shapes.
 */

/** The only replies this plugin may ever send automatically. */
export type AutomaticReply = "once" | "reject";

/** Internal name used by the permission adapter. */
export type InternalPermissionReply = AutomaticReply;

/** A canonical, in-process identity for one location and permission request. */
export type PermissionKey = Readonly<{
  locationDirectory: string;
  sessionID: string;
  requestID: string;
}>;

/** The loaded location identity used while validating ownership. */
export interface LocationIdentity {
  readonly directory: string;
  readonly projectID?: string;
}

/** OpenCode actions are extensible strings, rather than a closed allowlist. */
export type PermissionAction = string;

export type ActionCategory =
  | "read"
  | "edit"
  | "glob"
  | "grep"
  | "shell"
  | "subagent"
  | "skill"
  | "question"
  | "webfetch"
  | "websearch"
  | "external_directory"
  | "execute"
  | "plugin"
  | "mcp"
  | "other"
  | "unknown";

export type ResourceKind = "path" | "url" | "command" | "query" | "generic" | "unknown";

export type ResourceScope =
  | "project"
  | "external"
  | "home"
  | "system"
  | "secret"
  | "protected"
  | "unknown";

/** A raw resource value remains local until it is classified and redacted. */
export interface LocalResource {
  readonly value: string;
  readonly kind: ResourceKind;
  readonly scope: ResourceScope;
}

export interface PermissionSourceCorrelation {
  readonly messageID: string;
  readonly sourceID: string;
}

/** A bounded local intent candidate; it is not yet an outbound payload. */
export interface LocalIntentCandidate {
  readonly text: string;
  readonly redacted: boolean;
  readonly truncated: boolean;
  /** Local cache metadata; these fields are never copied to the outbound state. */
  readonly revision?: number;
  readonly timestamp?: number;
  readonly redactionComplete?: boolean;
}

export interface PermissionFacts {
  readonly key: PermissionKey;
  readonly location: LocationIdentity;
  readonly action: PermissionAction;
  readonly actionCategory: ActionCategory;
  readonly resources: readonly LocalResource[];
  readonly tool?: string;
  readonly source?: PermissionSourceCorrelation;
  readonly intent?: LocalIntentCandidate;
  /** Optional deterministic codes supplied by a later local assessment. */
  readonly signals?: readonly GuardrailSignalCode[];
}

export type RedactedResource = Readonly<{
  kind: ResourceKind;
  scope: ResourceScope;
  display: string;
}>;

export type ResourceKindCounts = Readonly<Record<ResourceKind, number>>;
export type ResourceScopeCounts = Readonly<Record<ResourceScope, number>>;

/** Bounded, value-free counts used by the outbound projection. */
export interface RedactionSummary {
  readonly total: number;
  readonly included: number;
  readonly omitted: number;
  readonly kindCounts: ResourceKindCounts;
  readonly scopeCounts: ResourceScopeCounts;
}

export interface RedactionTruncation {
  readonly commands: boolean;
  readonly intent: boolean;
  readonly resources: boolean;
  readonly resource: boolean;
}

/** Stable, value-free guardrail signal codes. */
export type GuardrailSignalCode =
  | "secret_access"
  | "destructive_operation"
  | "privilege_change"
  | "security_boundary_change"
  | "obvious_exfiltration"
  | "unparseable_syntax"
  | "unknown_scope"
  | "unresolved_path"
  | "ambiguous_resource"
  | "oversize"
  | "redaction_incomplete"
  | "missing_intent"
  | "intent_ambiguous"
  | "risk_unclear"
  | "high_risk"
  | "low_confidence"
  | "invalid_answer"
  | "queue_overflow"
  | "api_unavailable";

export type HardDenySignalCode = Extract<
  GuardrailSignalCode,
  | "secret_access"
  | "destructive_operation"
  | "privilege_change"
  | "security_boundary_change"
  | "obvious_exfiltration"
>;

export type ParseStatus = "parsed" | "unparseable" | "unknown_scope";

export interface GuardrailPolicy {
  readonly version: string;
}

export interface GuardrailAssessment {
  readonly signals: readonly GuardrailSignalCode[];
  readonly parseStatus: ParseStatus;
  readonly hardDeny: boolean;
  readonly policyVersion: string;
  readonly hardDenyCodes: readonly HardDenySignalCode[];
  readonly eligibleForAutoAllow: boolean;
}

export type IntentAlignment = "supported" | "contradicted" | "unclear";
export type RiskClass = "routine" | "elevated" | "high" | "unclear";
export type PolicyDecisionLabel = "allow_once" | "deny" | "manual_review";
export type JevChoiceLabel = IntentAlignment | RiskClass | PolicyDecisionLabel;

export interface JevChoiceAnswer<Label extends JevChoiceLabel> {
  readonly type: "choice";
  readonly choice: Label;
  readonly confidence: number;
  readonly probabilities: Readonly<Record<Label, number>>;
}

export interface JevTokenUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
}

export interface JevEvaluation {
  readonly auxiliary: Readonly<{
    intent_alignment: JevChoiceAnswer<IntentAlignment>;
    risk_class: JevChoiceAnswer<RiskClass>;
  }>;
  readonly final: JevChoiceAnswer<PolicyDecisionLabel>;
  readonly modelVersion: string;
  readonly usage: JevTokenUsage;
}

export type RedactedPolicy = Readonly<{
  version: string;
  hardDenyCodes: readonly HardDenySignalCode[];
  unknown: "manual_review";
  maximumGrant: "once";
}>;

/** The only shape permitted to cross the outbound Jev boundary. */
export interface RedactedContext {
  readonly action: PermissionAction;
  readonly actionCategory: ActionCategory;
  readonly tool?: string;
  readonly commands?: readonly string[];
  readonly resources: readonly RedactedResource[];
  readonly signals: readonly GuardrailSignalCode[];
  readonly intent?: string;
  readonly policy: RedactedPolicy;
  readonly summary?: RedactionSummary;
  readonly truncation?: RedactionTruncation;
  readonly redactionComplete: boolean;
  /** False when privacy/uncertainty makes an automatic grant unsafe. */
  readonly eligibleForAutoAllow?: boolean;
}

export type ConfidenceBucket = "low" | "medium" | "high";

export type CoreDecisionKind = "ALLOW_ONCE" | "REJECT" | "MANUAL_PENDING";

export type CoreDecisionReason =
  | "allow_once"
  | "hard_deny"
  | "confident_deny"
  | ManualReason;

export interface CoreDecision {
  readonly kind: CoreDecisionKind;
  readonly reason: CoreDecisionReason;
  readonly confidence: ConfidenceBucket;
}

/** Closed reasons for leaving a request for manual review. */
export type ManualReason =
  | "out_of_scope"
  | "already_resolved_external"
  | "malformed_request"
  | "missing_intent"
  | "intent_ambiguous"
  | "risk_unclear"
  | "risk_high"
  | "low_confidence"
  | "malformed_jev_answer"
  | "manual_review"
  | "missing_api_key"
  | "api_failure"
  | "timeout"
  | "queue_overflow"
  | "event_stream_error"
  | "plugin_cleanup"
  | "unknown";

/** Closed, sanitized error categories; raw exception text never enters this union. */
export type ErrorReason =
  | "config_invalid"
  | "missing_api_key"
  | "api_authentication"
  | "api_rate_limited"
  | "api_server"
  | "api_transport"
  | "api_timeout"
  | "api_aborted"
  | "api_malformed_response"
  | "opencode_transport"
  | "opencode_not_found"
  | "opencode_invalid_response"
  | "unknown";

/** Closed audit reason codes; arbitrary strings are not accepted. */
export type AuditReason =
  | "config_invalid"
  | "request_seen"
  | "request_out_of_scope"
  | "request_external"
  | "request_manual"
  | "request_allow_once"
  | "request_reject"
  | "jev_started"
  | "jev_completed"
  | "jev_failed"
  | "reply_attempted"
  | "reply_succeeded"
  | "reply_failed"
  | "stream_started"
  | "stream_error"
  | "cleanup";

export type AuditOutcome = "once" | "reject" | "manual" | "external" | "skipped";

/** Sanitized, closed metadata variants accepted by the audit boundary. */
export type AuditMetadata =
  | Readonly<{
      type: "request";
      action: ActionCategory;
      resourceCount: number;
      kindCounts: ResourceKindCounts;
      scopeCounts: ResourceScopeCounts;
      signals: readonly GuardrailSignalCode[];
      flags: Readonly<{
        redactionComplete: boolean;
        intentAvailable: boolean;
        truncated: boolean;
        parseStatus: ParseStatus;
      }>;
    }>
  | Readonly<{
      type: "jev";
      modelVersion: string;
      label: PolicyDecisionLabel;
      confidence: ConfidenceBucket;
      probability: ConfidenceBucket;
      inputTokens?: number;
      outputTokens?: number;
    }>
  | Readonly<{
      type: "error";
      category: ErrorReason;
      status?: number;
    }>
  | Readonly<{
      type: "lifecycle";
      event: "stream_started" | "stream_error" | "cleanup";
    }>;

export interface AuditEvent {
  readonly schemaVersion: 1;
  readonly reason: AuditReason;
  readonly outcome: AuditOutcome;
  readonly error?: ErrorReason;
  readonly metadata?: AuditMetadata;
}
