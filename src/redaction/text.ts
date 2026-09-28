/**
 * Pure text, credential, and URL redaction.
 *
 * All regular expressions in this module are fixed by the implementation. No
 * caller-provided expression is compiled or evaluated. The input is inspected
 * only while a projection is being built; the returned value contains no raw
 * value when a safe projection cannot be established.
 */

import {
  isHighEntropyLiteral,
  projectPathDetailed,
  type PathRedactionOptions,
} from "./paths.js";

export const REDACTED_SECRET_TOKEN = "<redacted-secret>" as const;
export const REDACTED_AUTHORIZATION_TOKEN = "<redacted-authorization>" as const;
export const REDACTED_COOKIE_TOKEN = "<redacted-cookie>" as const;
export const REDACTED_FLAG_TOKEN = "<redacted-flag-value>" as const;
export const REDACTED_ENV_TOKEN = "<redacted-env-value>" as const;
export const REDACTED_QUERY_TOKEN = "<redacted-query-value>" as const;
export const REDACTED_USERINFO_TOKEN = "<redacted-userinfo>" as const;
export const REDACTED_FRAGMENT_TOKEN = "<redacted-fragment>" as const;
export const REDACTED_URL_TOKEN = "<redacted-url>" as const;
export const INTERNAL_HOST_TOKEN = "<internal-host>" as const;
export const REDACTED_HOST_TOKEN = "<redacted-host>" as const;
export const OMITTED_TEXT_TOKEN = "<redacted-omitted>" as const;
export const PRIVATE_KEY_TOKEN = "<redacted-private-key>" as const;

const SAFE_PLACEHOLDERS: readonly string[] = Object.freeze([
  REDACTED_SECRET_TOKEN,
  REDACTED_AUTHORIZATION_TOKEN,
  REDACTED_COOKIE_TOKEN,
  REDACTED_FLAG_TOKEN,
  REDACTED_ENV_TOKEN,
  REDACTED_QUERY_TOKEN,
  REDACTED_USERINFO_TOKEN,
  REDACTED_FRAGMENT_TOKEN,
  REDACTED_URL_TOKEN,
  INTERNAL_HOST_TOKEN,
  REDACTED_HOST_TOKEN,
  OMITTED_TEXT_TOKEN,
  PRIVATE_KEY_TOKEN,
  "<project>",
  "<home>",
  "<external>",
  "<system>",
  "<secret>",
  "<protected>",
  "<unknown-path>",
  "<redacted-segment>",
  "<truncated-head>",
  "<truncated-tail>",
  "<head>",
  "<tail>",
]);

const SENSITIVE_NAME = /(?:api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth(?:orization)?|cookie|password|passwd|passphrase|secret|client[-_]?secret|private[-_]?key|session[-_]?token|access[-_]?key|signature|signed|credential|jwt|bearer|token|key)/i;
const SENSITIVE_QUERY_NAME = new Set([
  "access_token",
  "accesstoken",
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "client_secret",
  "clientsecret",
  "code",
  "cookie",
  "credential",
  "id_token",
  "key",
  "passwd",
  "password",
  "private_key",
  "refresh_token",
  "secret",
  "session",
  "sig",
  "signature",
  "token",
  "x_amz_algorithm",
  "x_amz_credential",
  "x_amz_security_token",
  "x_amz_signature",
  "x_amz_expires",
  "awsaccesskeyid",
  "x_amz_date",
  "x_goog_algorithm",
  "x_goog_credential",
  "x_goog_signature",
]);

const URL_PATTERN = /\b(?:https?|ftp):\/\/[^\s<>"'`]*(?:(?:<redacted-[^>]+>|<internal-host>)[^\s<>"'`]*)*/giu;
const ABSOLUTE_PATH_PATTERN = /(?:[A-Za-z]:[\\/]|\/)[^\s<>"'`|?#]+/gu;
const PLAIN_INTERNAL_HOST_PATTERN = /\b(?:localhost|(?:[A-Za-z0-9-]+\.)+(?:internal|local|lan|corp|intranet)|127(?:\.\d{1,3}){3})\b/giu;
const HIGH_ENTROPY_TOKEN_PATTERN = /(^|[^A-Za-z0-9_])([A-Za-z0-9+/_=-]{20,})(?=$|[^A-Za-z0-9_])/gu;
const HEX_LITERAL_PATTERN = /(^|[^A-Fa-f0-9])([A-Fa-f0-9]{24,})(?=$|[^A-Fa-f0-9])/gu;
const SECRET_WORD_LITERAL_PATTERN = /(^|[^\w-])([^\s"'`<>]{0,32}(?:secret|token|password|passwd|apikey|api_key|private[_-]?key)[^\s"'`<>]{0,32})(?=$|[^\w-])/giu;
const SECRET_CONTAINING_TOKEN_PATTERN = /(^|[^\w-])([^\s"'`<>]*(?:secret|token|password|passwd|apikey|api_key|private[_-]?key)[^\s"'`<>]*)(?=$|[^\w-])/giu;

export type TextRedactionFinding =
  | "private_key"
  | "authorization"
  | "cookie"
  | "sensitive_flag"
  | "api_key"
  | "sensitive_assignment"
  | "environment_dump"
  | "url"
  | "internal_host"
  | "path"
  | "high_entropy"
  | "truncated"
  | "unsafe_remainder";

export interface TextRedactionOptions {
  readonly maxChars?: number;
  readonly pathOptions?: PathRedactionOptions;
  /** Disable only when the caller has already handled an environment dump. */
  readonly redactEnvironmentDump?: boolean;
}

const MAX_TRANSIENT_TEXT_CHARS = 1_000_000;

export interface TextRedactionResult {
  /** Safe projected text. Never the original input on an unsafe projection. */
  readonly value: string;
  /** Alias for callers that use text terminology. */
  readonly text: string;
  readonly complete: boolean;
  readonly truncated: boolean;
  readonly redacted: boolean;
  readonly findings: readonly TextRedactionFinding[];
  readonly redactionComplete: boolean;
}

interface RedactionState {
  changed: boolean;
  complete: boolean;
  findings: Set<TextRedactionFinding>;
}

function newState(): RedactionState {
  return { changed: false, complete: true, findings: new Set<TextRedactionFinding>() };
}

function mark(state: RedactionState, finding: TextRedactionFinding): void {
  state.changed = true;
  state.findings.add(finding);
}

function validMaxChars(value: number | undefined): { readonly max: number; readonly valid: boolean } {
  if (value === undefined) return { max: Number.MAX_SAFE_INTEGER, valid: true };
  return {
    max: Number.isInteger(value) && value >= 16 ? value : 512,
    valid: Number.isInteger(value) && value >= 16,
  };
}

function isPlaceholder(value: string): boolean {
  return (
    SAFE_PLACEHOLDERS.some((placeholder) => value === placeholder || value.includes(placeholder)) ||
    /(?:redacted|truncated|internal-host|unknown-path|resources-omitted|commands-omitted)/iu.test(value)
  );
}

function withoutSafePlaceholders(value: string): string {
  let result = value;
  for (const placeholder of SAFE_PLACEHOLDERS) {
    result = result.replaceAll(placeholder, " ");
  }
  return result;
}

function capText(
  value: string,
  maxChars: number,
): Readonly<{ value: string; truncated: boolean }> {
  if (value.length <= maxChars) return { value, truncated: false };
  const head = "<truncated-head>";
  const tail = "<truncated-tail>";
  if (maxChars < head.length + tail.length) {
    const compactHead = "<head>";
    const compactTail = "<tail>";
    if (maxChars <= compactHead.length + compactTail.length) {
      return { value: compactHead.slice(0, maxChars), truncated: true };
    }
    const available = maxChars - compactHead.length - compactTail.length;
    const headLength = Math.ceil(available / 2);
    const tailLength = available - headLength;
    return {
      value: `${compactHead}${value.slice(0, headLength)}${compactTail}${value.slice(value.length - tailLength)}`,
      truncated: true,
    };
  }
  const available = maxChars - head.length - tail.length;
  const headLength = Math.ceil(available / 2);
  const tailLength = available - headLength;
  return {
    value: `${head}${value.slice(0, headLength)}${tail}${value.slice(value.length - tailLength)}`,
    truncated: true,
  };
}

function replacePrivateKeys(value: string, state: RedactionState): string {
  const completeBlock = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/giu;
  const malformedBlock = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*/giu;
  let result = value.replace(completeBlock, () => {
    mark(state, "private_key");
    return PRIVATE_KEY_TOKEN;
  });
  result = result.replace(malformedBlock, () => {
    mark(state, "private_key");
    state.complete = false;
    return PRIVATE_KEY_TOKEN;
  });
  return result;
}

function replaceAuthorization(value: string, state: RedactionState): string {
  let result = value.replace(
    /(\b(?:authorization|proxy-authorization)\s*[:=]\s*)(?:bearer|basic)(?:\s+|:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/giu,
    (_match, prefix: string) => {
      mark(state, "authorization");
      return `${prefix}${REDACTED_AUTHORIZATION_TOKEN}`;
    },
  );
  result = result.replace(
    /(\b(?:bearer|basic)(?:\s+|:\s*))(?:"[^"\r\n]*"|'[^'\r\n]*'|[A-Za-z0-9._~+/=-]{8,})/giu,
    (_match, prefix: string) => {
      mark(state, "authorization");
      return `${prefix}${REDACTED_AUTHORIZATION_TOKEN}`;
    },
  );
  return result;
}

function replaceCookies(value: string, state: RedactionState): string {
  return value.replace(
    /(\b(?:set-cookie|cookie)\s*:\s*)[^\r\n]+/giu,
    (_match, prefix: string) => {
      mark(state, "cookie");
      return `${prefix}${REDACTED_COOKIE_TOKEN}`;
    },
  );
}

function replaceSensitiveFlags(value: string, state: RedactionState): string {
  return value.replace(
    /((?:^|\s)--?(?:password|passwd|passphrase|token|secret|api[-_]?key|cookie|auth|authorization|credential|private[-_]?key))(\s*=\s*|\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+)/giu,
    (_match, flag: string, separator: string) => {
      mark(state, "sensitive_flag");
      return `${flag}${separator}${REDACTED_FLAG_TOKEN}`;
    },
  );
}

function replaceUserInfoFlags(value: string, state: RedactionState): string {
  return value.replace(
    /((?:^|\s)(?:--user|-u))(\s*=\s*|\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+)/giu,
    (_match, flag: string, separator: string) => {
      mark(state, "authorization");
      return `${flag}${separator}${REDACTED_AUTHORIZATION_TOKEN}`;
    },
  );
}

function replaceKeyValueSecrets(value: string, state: RedactionState): string {
  let result = value.replace(
    /(["'])([A-Za-z_][A-Za-z0-9_.-]*)\1\s*:\s*(["'])(?:\\.|(?!\3)[\s\S])*\3/giu,
    (_match, quote: string, name: string) => {
      if (!isSensitiveAssignmentName(name)) return _match;
      mark(state, "sensitive_assignment");
      return `${quote}${name}${quote}:${quote}${REDACTED_SECRET_TOKEN}${quote}`;
    },
  );
  result = result.replace(
    /(^|[\s;,{])([A-Za-z_][A-Za-z0-9_.-]*)(\s*:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)/gmu,
    (match, prefix: string, name: string, separator: string) => {
      if (!isSensitiveAssignmentName(name)) return match;
      mark(state, "sensitive_assignment");
      return `${prefix}${name}${separator}${REDACTED_SECRET_TOKEN}`;
    },
  );
  result = result.replace(
    /([?&])([A-Za-z_][A-Za-z0-9_.-]*)=([^&#\s]*)/gu,
    (match, prefix: string, name: string) => {
      if (!isSensitiveAssignmentName(name) && !queryNameIsSensitive(name)) return match;
      mark(state, "sensitive_assignment");
      return `${prefix}${name}=${REDACTED_QUERY_TOKEN}`;
    },
  );
  return result;
}

function isSensitiveAssignmentName(name: string): boolean {
  return SENSITIVE_NAME.test(name);
}

function replaceSensitiveAssignments(value: string, state: RedactionState): string {
  return value.replace(
    /(^|[\s;])([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)/gmu,
    (match, prefix: string, name: string, separator: string) => {
      if (!isSensitiveAssignmentName(name)) return match;
      const existingValue = match.slice(prefix.length + name.length + separator.length);
      if (isPlaceholder(existingValue)) return match;
      mark(state, "sensitive_assignment");
      return `${prefix}${name}${separator}${REDACTED_SECRET_TOKEN}`;
    },
  );
}

function looksLikeEnvironmentDump(value: string): boolean {
  const lines = value.split(/\r?\n/u);
  const assignmentLines = lines.filter((line) => /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*=/u.test(line)).length;
  const hasDumpCommand = /(?:^|[;&|]\s*)(?:env|printenv|export)\b/iu.test(value);
  return assignmentLines >= 2 || (hasDumpCommand && assignmentLines >= 1);
}

function redactEnvironmentDumpValue(value: string, state: RedactionState): string {
  if (!looksLikeEnvironmentDump(value)) return value;
  const lines = value.split(/(\r?\n)/u);
  let changed = false;
  const projected = lines.map((line) => {
    const match = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/u.exec(line);
    if (match === null) return line;
    changed = true;
    return `${match[1] ?? ""}${match[2] ?? ""}${match[3] ?? ""}${REDACTED_ENV_TOKEN}`;
  });
  if (changed) mark(state, "environment_dump");
  return projected.join("");
}

/** Redact all values in an environment-style dump while preserving names. */
export function redactEnvironmentDump(input: unknown): string {
  const state = newState();
  if (typeof input !== "string") return OMITTED_TEXT_TOKEN;
  return redactEnvironmentDumpValue(input, state);
}

function replaceKnownCredentialLiterals(value: string, state: RedactionState): string {
  const patterns: readonly RegExp[] = [
    /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b/giu,
    /\bgh[pousr]_[A-Za-z0-9_]{16,}\b/giu,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/giu,
    /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
    /\bAIza[A-Za-z0-9_-]{20,}\b/gu,
    /\bya29\.[A-Za-z0-9._-]{20,}\b/giu,
    /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/giu,
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  ];
  let result = value;
  for (const pattern of patterns) {
    result = result.replace(pattern, () => {
      mark(state, "api_key");
      return REDACTED_SECRET_TOKEN;
    });
  }
  return result;
}

function isLikelyHexSecret(value: string): boolean {
  if (!/^[A-Fa-f0-9]{24,}$/u.test(value)) return false;
  const hasDigit = /[0-9]/u.test(value);
  const hasUpper = /[A-F]/u.test(value);
  const hasLower = /[a-f]/u.test(value);
  const unique = new Set(value).size;
  return (hasDigit || hasUpper) && unique >= 8 && (hasLower || hasDigit || hasUpper);
}

function replaceHighEntropyLiterals(value: string, state: RedactionState): string {
  let result = value.replace(HIGH_ENTROPY_TOKEN_PATTERN, (match, prefix: string, token: string) => {
    if (token.includes("<") || isPlaceholder(token) || isHighEntropyLiteral(token) === false) return match;
    mark(state, "high_entropy");
    return `${prefix}${REDACTED_SECRET_TOKEN}`;
  });
  result = result.replace(HEX_LITERAL_PATTERN, (match, prefix: string, token: string) => {
    if (isPlaceholder(token) || !isLikelyHexSecret(token)) return match;
    mark(state, "high_entropy");
    return `${prefix}${REDACTED_SECRET_TOKEN}`;
  });
  result = result.replace(SECRET_WORD_LITERAL_PATTERN, (match, prefix: string, token: string) => {
    if (isPlaceholder(token) || token.length < 10 || token.startsWith("-") || token.includes("=")) return match;
    mark(state, "high_entropy");
    return `${prefix}${REDACTED_SECRET_TOKEN}`;
  });
  result = result.replace(SECRET_CONTAINING_TOKEN_PATTERN, (match, prefix: string, token: string) => {
    if (
      isPlaceholder(token) ||
      token.length < 12 ||
      token.startsWith("-") ||
      token.includes("=")
    ) {
      return match;
    }
    mark(state, "high_entropy");
    return `${prefix}${REDACTED_SECRET_TOKEN}`;
  });
  return result;
}

function hostIsInternal(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "localhost" || lower.endsWith(".localhost")) return true;
  if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
  if (/^(?:fc|fd|fe8|fe9|fea|feb)[0-9a-f:]+$/u.test(lower)) return true;
  if (/^127(?:\.\d{1,3}){3}$/.test(lower)) return true;
  if (/^10(?:\.\d{1,3}){3}$/.test(lower)) return true;
  if (/^192\.168(?:\.\d{1,3}){2}$/.test(lower)) return true;
  if (/^172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}$/.test(lower)) return true;
  const labels = lower.split(".");
  return (
    lower.endsWith(".internal") ||
    lower.endsWith(".local") ||
    lower.endsWith(".lan") ||
    lower.endsWith(".corp") ||
    lower.endsWith(".intranet") ||
    lower === "internal" ||
    labels.some((label) => /^(?:internal|intranet|corp|private|localhost)(?:[-_]?\d*)?$/u.test(label))
  );
}

function queryNameIsSensitive(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[-_.]/g, "_");
  return SENSITIVE_QUERY_NAME.has(normalized) || SENSITIVE_QUERY_NAME.has(normalized.replaceAll("_", ""));
}

function projectedQueryName(name: string): Readonly<{ value: string; complete: boolean }> {
  if (
    name.length > 0 &&
    name.length <= 64 &&
    /^[A-Za-z0-9._~-]+$/u.test(name) &&
    !isHighEntropyLiteral(name) &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(name)
  ) {
    return { value: name, complete: true };
  }
  return { value: REDACTED_QUERY_TOKEN, complete: false };
}

function cleanUrlBoundary(value: string): Readonly<{ url: string; suffix: string }> {
  const match = /[.,;:!?)}\]]+$/u.exec(value);
  if (match === null) return { url: value, suffix: "" };
  return { url: value.slice(0, value.length - match[0].length), suffix: match[0] };
}

function redactUrlPath(pathname: string, options: TextRedactionOptions): Readonly<{ value: string; complete: boolean }> {
  if (pathname.length === 0) return { value: "", complete: true };
  const projection = projectPathDetailed(pathname, {
    ...options.pathOptions,
    maxChars: options.pathOptions?.maxChars ?? 256,
  });
  return { value: projection.value, complete: projection.complete };
}

function redactUrlValue(
  input: unknown,
  options: TextRedactionOptions = {},
): Readonly<{ value: string; complete: boolean; changed: boolean }> {
  const state = newState();
  if (typeof input !== "string" || input.length === 0) {
    return { value: REDACTED_URL_TOKEN, complete: false, changed: true };
  }
  if (
    input.includes(REDACTED_USERINFO_TOKEN) ||
    input.includes(INTERNAL_HOST_TOKEN) ||
    input.includes(REDACTED_QUERY_TOKEN) ||
    input.includes(REDACTED_FRAGMENT_TOKEN) &&
    !containsSensitiveLiteral(input)
  ) {
    return { value: input, complete: true, changed: false };
  }
  const { url, suffix } = cleanUrlBoundary(input);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    mark(state, "url");
    state.complete = false;
    return { value: `${REDACTED_URL_TOKEN}${suffix}`, complete: false, changed: true };
  }

  let result = parsed.protocol;
  result += "//";
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    result += `${REDACTED_USERINFO_TOKEN}@`;
    mark(state, "url");
  }
  const hostname = parsed.hostname.toLowerCase();
  if (hostIsInternal(hostname)) {
    result += INTERNAL_HOST_TOKEN;
    mark(state, "internal_host");
  } else if (hostname.split(".").some((label) => isHighEntropyLiteral(label))) {
    result += REDACTED_HOST_TOKEN;
    mark(state, "url");
  } else {
    result += hostname;
  }
  if (!hostIsInternal(hostname) && parsed.port.length > 0) result += `:${parsed.port}`;

  const pathResult = redactUrlPath(parsed.pathname, options);
  if (parsed.pathname.startsWith("/") && pathResult.value.startsWith("<external>/")) {
    result += `/${pathResult.value.slice("<external>/".length)}`;
  } else {
    result += pathResult.value;
  }
  if (!pathResult.complete) state.complete = false;

  const queryParts: string[] = [];
  for (const [name, value] of parsed.searchParams) {
    const nameProjection = projectedQueryName(name);
    if (!nameProjection.complete) state.complete = false;
    const safeName = nameProjection.value;
    const sensitive = queryNameIsSensitive(name);
    const valueProjection: TextRedactionResult = sensitive
      ? Object.freeze({
          value: REDACTED_QUERY_TOKEN,
          text: REDACTED_QUERY_TOKEN,
          complete: true,
          truncated: false,
          redacted: true,
          findings: Object.freeze([] as const),
          redactionComplete: true,
        })
      : redactTextDetailed(value, {
          ...options,
          maxChars: 256,
          redactEnvironmentDump: false,
        });
    if (valueProjection.truncated || !valueProjection.complete) state.complete = false;
    if (valueProjection.truncated) mark(state, "truncated");
    queryParts.push(`${encodeURIComponent(safeName)}=${valueProjection.value}`);
  }
  if (queryParts.length > 0) result += `?${queryParts.join("&")}`;

  // Fragments are never needed for permission judgment and can carry tokens.
  if (parsed.hash.length > 0) {
    result += `#${REDACTED_FRAGMENT_TOKEN}`;
    mark(state, "url");
  }
  if (input !== result + suffix) mark(state, "url");
  return { value: `${result}${suffix}`, complete: state.complete, changed: state.changed };
}

/** Project a URL while retaining only a safe host/path and query shape. */
export function redactUrlDetailed(
  input: unknown,
  options: TextRedactionOptions = {},
): TextRedactionResult {
  const direct = redactUrlValue(input, options);
  const max = validMaxChars(options.maxChars);
  const postProjection = redactTextDetailed(direct.value, {
    ...options,
    maxChars: max.max,
  });
  const capped = capText(postProjection.value, max.max);
  const findings = new Set<TextRedactionFinding>(postProjection.findings);
  if (direct.changed) findings.add("url");
  if (capped.truncated) findings.add("truncated");
  const complete = direct.complete && postProjection.complete && max.valid;
  return Object.freeze({
    value: capped.value,
    text: capped.value,
    complete,
    truncated: capped.truncated || postProjection.truncated,
    redacted: direct.changed || postProjection.redacted,
    findings: Object.freeze([...findings]),
    redactionComplete: complete,
  });
}

export function redactUrl(input: unknown, options: TextRedactionOptions = {}): string {
  return redactUrlDetailed(input, options).value;
}

function replaceUrls(value: string, options: TextRedactionOptions, state: RedactionState): string {
  return value.replace(URL_PATTERN, (match) => {
    const candidate = match;
    const projection = redactUrlValue(candidate, options);
    if (!projection.complete) state.complete = false;
    if (projection.changed) mark(state, "url");
    if (projection.value !== candidate) state.changed = true;
    return projection.value;
  });
}

function replacePlainInternalHosts(value: string, state: RedactionState): string {
  return value.replace(PLAIN_INTERNAL_HOST_PATTERN, () => {
    mark(state, "internal_host");
    return INTERNAL_HOST_TOKEN;
  });
}

function replaceAbsolutePaths(
  value: string,
  options: TextRedactionOptions,
  state: RedactionState,
): string {
  return value.replace(ABSOLUTE_PATH_PATTERN, (match, offset: number) => {
    const before = value.slice(0, offset);
    const lastWhitespace = Math.max(before.lastIndexOf(" "), before.lastIndexOf("\n"), before.lastIndexOf("\t"));
    const prefix = before.slice(lastWhitespace + 1);
    // Do not reinterpret the path component of a URL after URL projection.
    if (prefix.includes("://") || /[A-Za-z0-9>]$/.test(prefix)) return match;
    const projection = projectPathDetailed(match, {
      ...options.pathOptions,
      maxChars: options.pathOptions?.maxChars ?? 512,
    });
    if (!projection.complete) state.complete = false;
    if (projection.value !== match) {
      mark(state, "path");
      state.changed = true;
    }
    return projection.value;
  });
}

function looksLikeRawAbsolutePath(value: string): boolean {
  return /(?:^|[\s"'=])(?:\/home\/[^/\s]+\/|\/Users\/[^/\s]+\/|[A-Za-z]:\/Users\/[^/\s]+\/)/u.test(
    withoutSafePlaceholders(value),
  );
}

function matchesFresh(expression: RegExp, value: string): boolean {
  expression.lastIndex = 0;
  const result = expression.test(value);
  expression.lastIndex = 0;
  return result;
}

function containsUnsafeSensitiveAssignment(value: string): boolean {
  const patterns: readonly Readonly<{ expression: RegExp; valueIndex: number }>[] = [
    {
      expression: /(^|[\s;{])([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;}]+)/gmu,
      valueIndex: 4,
    },
    {
      expression: /(^|[\s;{])([A-Za-z_][A-Za-z0-9_.-]*)(\s*:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)/gmu,
      valueIndex: 5,
    },
    {
      expression: /([?&])([A-Za-z_][A-Za-z0-9_.-]*)=([^&#\s]*)/gu,
      valueIndex: 3,
    },
  ];
  for (const { expression, valueIndex } of patterns) {
    for (const match of value.matchAll(expression)) {
      const name = match[2];
      const assignedValue = match[valueIndex];
      if (
        name !== undefined &&
        assignedValue !== undefined &&
        (SENSITIVE_NAME.test(name) || queryNameIsSensitive(name)) &&
        !isPlaceholder(assignedValue) &&
        !assignedValue.startsWith("<")
      ) {
        return true;
      }
    }
  }
  return false;
}

function containsSensitiveLiteral(value: string): boolean {
  const scrubbed = withoutSafePlaceholders(value);
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/iu.test(scrubbed)) return true;
  if (/\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+(?!<)[^\s,;]+/iu.test(scrubbed)) {
    return true;
  }
  if (/\b(?:bearer|basic)\s+(?!<)[A-Za-z0-9._~+/=-]{8,}/iu.test(scrubbed)) {
    return true;
  }
  if (/\b(?:set-cookie|cookie)\s*:\s*(?!<|\s*$)\S/iu.test(scrubbed)) {
    return true;
  }
  if (containsUnsafeSensitiveAssignment(value)) {
    return true;
  }
  for (const match of value.matchAll(SECRET_CONTAINING_TOKEN_PATTERN)) {
    const token = match[2];
    if (token !== undefined && token.length >= 12 && !isPlaceholder(token) && !token.startsWith("-") && !token.includes("=")) {
      return true;
    }
  }
  if (/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}\b/iu.test(scrubbed)) {
    return true;
  }
  if (/\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}\b/iu.test(scrubbed)) {
    return true;
  }
  if (/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u.test(scrubbed)) {
    return true;
  }
  HIGH_ENTROPY_TOKEN_PATTERN.lastIndex = 0;
  for (const match of withoutSafePlaceholders(scrubbed).matchAll(HIGH_ENTROPY_TOKEN_PATTERN)) {
    const token = match[2];
    if (token !== undefined && isHighEntropyLiteral(token)) {
      return true;
    }
  }
  HIGH_ENTROPY_TOKEN_PATTERN.lastIndex = 0;
  if (looksLikeRawAbsolutePath(scrubbed)) {
    return true;
  }
  if (matchesFresh(PLAIN_INTERNAL_HOST_PATTERN, scrubbed)) {
    return true;
  }
  return false;
}

function runSensitivePass(value: string, options: TextRedactionOptions, state: RedactionState): string {
  let result = value;
  result = replacePrivateKeys(result, state);
  result = replaceUrls(result, options, state);
  result = redactEnvironmentDumpValue(result, state);
  result = replaceAuthorization(result, state);
  result = replaceCookies(result, state);
  result = replaceSensitiveFlags(result, state);
  result = replaceUserInfoFlags(result, state);
  result = replaceKeyValueSecrets(result, state);
  result = replaceSensitiveAssignments(result, state);
  result = replaceKnownCredentialLiterals(result, state);
  result = replacePlainInternalHosts(result, state);
  result = replaceAbsolutePaths(result, options, state);
  result = replaceHighEntropyLiterals(result, state);
  return result;
}

/**
 * Redact arbitrary text and return only a safe projection plus bounded flags.
 */
export function redactTextDetailed(
  input: unknown,
  options: TextRedactionOptions = {},
): TextRedactionResult {
  const state = newState();
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    input.length > MAX_TRANSIENT_TEXT_CHARS
  ) {
    return Object.freeze({
      value: OMITTED_TEXT_TOKEN,
      text: OMITTED_TEXT_TOKEN,
      complete: false,
      truncated: false,
      redacted: true,
      findings: Object.freeze(["unsafe_remainder"] as const),
      redactionComplete: false,
    });
  }

  const max = validMaxChars(options.maxChars);
  if (!max.valid) state.complete = false;
  let result = runSensitivePass(input, options, state);
  // A second independent pass catches literals exposed by overlapping rules.
  result = runSensitivePass(result, options, state);
  if (containsSensitiveLiteral(result)) {
    state.complete = false;
    mark(state, "unsafe_remainder");
    result = OMITTED_TEXT_TOKEN;
  }
  const capped = capText(result, max.max);
  let wasTruncated = false;
  if (capped.truncated) {
    wasTruncated = true;
    state.changed = true;
    mark(state, "truncated");
  }
  const complete = state.complete && max.valid;
  const value = capped.value || OMITTED_TEXT_TOKEN;
  return Object.freeze({
    value,
    text: value,
    complete,
    truncated: wasTruncated,
    redacted: state.changed,
    findings: Object.freeze([...state.findings]),
    redactionComplete: complete,
  });
}

/** String convenience wrapper around {@link redactTextDetailed}. */
export function redactText(input: unknown, options: TextRedactionOptions = {}): string {
  return redactTextDetailed(input, options).value;
}

/** Redact one shell command without attempting to parse or execute it. */
export function redactCommandDetailed(
  input: unknown,
  options: TextRedactionOptions = {},
): TextRedactionResult {
  return redactTextDetailed(input, {
    ...options,
    redactEnvironmentDump: true,
  });
}

export function redactCommand(input: unknown, options: TextRedactionOptions = {}): string {
  return redactCommandDetailed(input, options).value;
}

/** Redact one user-intent fragment. */
export function redactIntentDetailed(
  input: unknown,
  options: TextRedactionOptions = {},
): TextRedactionResult {
  return redactTextDetailed(input, {
    ...options,
    redactEnvironmentDump: true,
  });
}

export function redactIntent(input: unknown, options: TextRedactionOptions = {}): string {
  return redactIntentDetailed(input, options).value;
}
