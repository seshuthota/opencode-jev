/**
 * Pure path classification and projection.
 *
 * This module intentionally does not use `fs`, `path`, or any other I/O. It
 * only compares strings supplied by the caller with explicit, local boundary
 * roots and replaces machine-specific portions before returning a projection.
 */

import type { ResourceScope } from "../domain.js";

export const PROJECT_PATH_TOKEN = "<project>" as const;
export const HOME_PATH_TOKEN = "<home>" as const;
export const EXTERNAL_PATH_TOKEN = "<external>" as const;
export const SYSTEM_PATH_TOKEN = "<system>" as const;
export const SECRET_PATH_TOKEN = "<secret>" as const;
export const PROTECTED_PATH_TOKEN = "<protected>" as const;
export const UNKNOWN_PATH_TOKEN = "<unknown-path>" as const;

export const TRUNCATED_HEAD_MARKER = "<truncated-head>" as const;
export const TRUNCATED_TAIL_MARKER = "<truncated-tail>" as const;
export const REDACTED_SEGMENT_TOKEN = "<redacted-segment>" as const;
export const REDACTED_USER_TOKEN = "<redacted-user>" as const;

const DEFAULT_MAX_PATH_CHARS = 512;
const DEFAULT_SYSTEM_ROOTS: readonly string[] = Object.freeze([
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/lib",
  "/lib32",
  "/lib64",
  "/proc",
  "/root",
  "/sbin",
  "/sys",
  "/usr",
  "/var/lib",
  "/var/spool",
]);

export interface PathRedactionOptions {
  /** The loaded project root, used only transiently while projecting. */
  readonly projectRoot?: string;
  /** The local user's home root, used only transiently while projecting. */
  readonly homeDirectory?: string;
  /** Additional stable system roots. */
  readonly systemRoots?: readonly string[];
  /** Maximum projected path length. */
  readonly maxChars?: number;
}

export interface PathProjection {
  /** Safe display form. This never contains the configured absolute root. */
  readonly value: string;
  /** Alias useful to callers that use text terminology. */
  readonly text: string;
  readonly category: ResourceScope;
  readonly scope: ResourceScope;
  readonly complete: boolean;
  readonly truncated: boolean;
  readonly sensitive: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function normalizeSlashes(value: string): string {
  return value.replaceAll("\\", "/");
}

function stripTrailingSlashes(value: string): string {
  let result = value;
  while (result.length > 1 && result.endsWith("/")) result = result.slice(0, -1);
  return result;
}

function isAbsolutePath(value: string): boolean {
  return value.startsWith("/") || /^[A-Za-z]:\//.test(value);
}

function isWindowsDrivePath(value: string): boolean {
  return /^[A-Za-z]:\//.test(value);
}

function rootKey(value: string): string {
  const normalized = stripTrailingSlashes(normalizeSlashes(value));
  return isWindowsDrivePath(normalized) ? normalized.toLowerCase() : normalized;
}

function pathKey(value: string): string {
  const normalized = normalizeSlashes(value);
  return isWindowsDrivePath(normalized) ? normalized.toLowerCase() : normalized;
}

function isWithin(candidate: string, root: string): boolean {
  const candidateKey = pathKey(candidate);
  const rootKeyValue = pathKey(stripTrailingSlashes(root));
  return candidateKey === rootKeyValue || candidateKey.startsWith(`${rootKeyValue}/`);
}

function relativeToRoot(candidate: string, root: string): string {
  const normalizedCandidate = stripTrailingSlashes(normalizeSlashes(candidate));
  const normalizedRoot = stripTrailingSlashes(normalizeSlashes(root));
  if (pathKey(normalizedCandidate) === pathKey(normalizedRoot)) return "";
  return normalizedCandidate.slice(normalizedRoot.length).replace(/^\/+/, "");
}

function segmentsOf(value: string): readonly string[] {
  return normalizeSlashes(value)
    .split("/")
    .filter((segment) => segment.length > 0);
}

function inferredHomeRoot(value: string): string | undefined {
  const normalized = normalizeSlashes(value);
  const posix = /^(?:\/home\/[^/]+|\/Users\/[^/]+|\/var\/root)(?:\/|$)/.exec(normalized);
  if (posix?.[0] !== undefined) {
    const withoutTrailing = posix[0].replace(/\/+$/, "");
    return withoutTrailing.length > 0 ? withoutTrailing : undefined;
  }
  const windows = /^([A-Za-z]:\/Users\/[^/]+)(?:\/|$)/.exec(normalized);
  return windows?.[1];
}

function looksLikeSecretPath(value: string): boolean {
  const lower = value.toLowerCase();
  const segments = segmentsOf(lower);
  const basename = segments.at(-1) ?? "";

  if (
    basename === ".env" ||
    ((basename.startsWith(".env.")) && ![".env.example", ".env.sample", ".env.template"].includes(basename))
  ) {
    return true;
  }
  if (
    basename === ".npmrc" ||
    basename === ".pypirc" ||
    basename === "credentials" ||
    basename === "credentials.json" ||
    basename === "secrets" ||
    basename === "secrets.json" ||
    basename === "secrets.yaml" ||
    basename === "secrets.yml" ||
    basename === "id_rsa" ||
    basename === "id_dsa" ||
    basename === "id_ecdsa" ||
    basename === "id_ed25519" ||
    basename === "authorized_keys" ||
    basename === "shadow" ||
    basename === "passwd"
  ) {
    return true;
  }
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/.test(basename)) return true;
  if (/(?:^|[._-])(?:secret|secrets|token|tokens|password|passwd|private[_-]?key|credential|credentials)(?:$|[._-])/.test(basename)) {
    return true;
  }
  if (segments.some((segment) => ["credentials", "secrets", "private keys", "keychain"].includes(segment))) {
    return true;
  }
  return false;
}

function looksLikeProtectedPath(value: string): boolean {
  const lower = value.toLowerCase();
  const segments = segmentsOf(lower);
  return (
    segments.includes(".git") ||
    segments.includes(".opencode") ||
    segments.includes("hooks") ||
    lower.includes("/etc/sudo") ||
    lower.includes("/etc/security") ||
    lower.includes("/etc/pam") ||
    lower.includes("security-boundary") ||
    lower.includes("policy") ||
    lower.includes("permissions")
  );
}

function isValidRoot(root: string | undefined): root is string {
  return typeof root === "string" && isAbsolutePath(normalizeSlashes(root));
}

function uniqueRoots(
  projectRoot: string | undefined,
  homeDirectory: string | undefined,
  systemRoots: readonly string[] | undefined,
): readonly string[] {
  const candidates = [
    ...(isValidRoot(projectRoot) ? [projectRoot] : []),
    ...(isValidRoot(homeDirectory) ? [homeDirectory] : []),
    ...(systemRoots ?? []),
    ...DEFAULT_SYSTEM_ROOTS,
  ];
  const result: string[] = [];
  for (const candidate of candidates) {
    if (!isValidRoot(candidate)) continue;
    const normalized = stripTrailingSlashes(normalizeSlashes(candidate));
    if (!result.some((existing) => rootKey(existing) === rootKey(normalized))) result.push(normalized);
  }
  return result;
}

function safeMaxChars(value: number | undefined): { readonly max: number; readonly valid: boolean } {
  if (value === undefined) return { max: DEFAULT_MAX_PATH_CHARS, valid: true };
  return {
    max: Number.isInteger(value) && value >= TRUNCATED_HEAD_MARKER.length + TRUNCATED_TAIL_MARKER.length + 2
      ? value
      : DEFAULT_MAX_PATH_CHARS,
    valid: Number.isInteger(value) && value >= TRUNCATED_HEAD_MARKER.length + TRUNCATED_TAIL_MARKER.length + 2,
  };
}

/** Deterministically retain both ends of an overlong projection. */
export function truncateWithMarkers(
  value: string,
  maxChars: number,
): Readonly<{ value: string; truncated: boolean }> {
  if (value.length <= maxChars) return { value, truncated: false };
  if (maxChars <= 0) return { value: "", truncated: true };

  const markerLength = TRUNCATED_HEAD_MARKER.length + TRUNCATED_TAIL_MARKER.length;
  if (maxChars < markerLength) {
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

  const available = maxChars - markerLength;
  const headLength = Math.ceil(available / 2);
  const tailLength = available - headLength;
  return {
    value: `${TRUNCATED_HEAD_MARKER}${value.slice(0, headLength)}${TRUNCATED_TAIL_MARKER}${value.slice(value.length - tailLength)}`,
    truncated: true,
  };
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** A conservative lexical check used for opaque path segments. */
export function isHighEntropyLiteral(value: string): boolean {
  const candidate = value.replace(/^[<("']+|[>)"',]+$/g, "");
  if (candidate.length < 20 || candidate.includes(" ") || candidate.includes("<")) return false;
  if (/^[A-Fa-f0-9]{24,}$/.test(candidate)) return true;
  const hasLower = /[a-z]/.test(candidate);
  const hasUpper = /[A-Z]/.test(candidate);
  const hasDigit = /[0-9]/.test(candidate);
  const symbolCount = (candidate.match(/[^A-Za-z0-9]/g) ?? []).length;
  const classes = Number(hasLower) + Number(hasUpper) + Number(hasDigit) + Number(symbolCount > 0);
  if (classes < 3) return false;
  const uniqueRatio = new Set(candidate).size / candidate.length;
  return uniqueRatio >= 0.42 && shannonEntropy(candidate) >= 3.15;
}

function safeSegment(segment: string): Readonly<{ value: string; complete: boolean }> {
  if (segment.length === 0) return { value: "", complete: true };
  if (isHighEntropyLiteral(segment)) {
    return { value: REDACTED_SEGMENT_TOKEN, complete: true };
  }
  if (/[\u0000-\u001f\u007f]/.test(segment)) {
    return { value: REDACTED_SEGMENT_TOKEN, complete: false };
  }
  return { value: segment, complete: true };
}

function relativeForMatch(
  value: string,
  root: string | undefined,
  matches: boolean,
): string {
  return root !== undefined && matches ? relativeToRoot(value, root) : value.replace(/^\/+/, "");
}

function projectSuffix(suffix: string): Readonly<{ value: string; complete: boolean }> {
  const segments = segmentsOf(suffix);
  const projected: string[] = [];
  let complete = true;
  let redactNextSegment = false;
  for (const segment of segments) {
    if (redactNextSegment) {
      projected.push(REDACTED_USER_TOKEN);
      redactNextSegment = false;
      continue;
    }
    const lower = segment.toLowerCase();
    if (lower === "user" || lower === "users") {
      projected.push(segment);
      redactNextSegment = true;
      continue;
    }
    const result = safeSegment(segment);
    projected.push(result.value);
    complete = complete && result.complete;
  }
  return { value: projected.join("/"), complete };
}

function makeProjection(
  display: string,
  category: ResourceScope,
  complete: boolean,
  sensitive: boolean,
  maxChars: number,
): PathProjection {
  const capped = truncateWithMarkers(display, maxChars);
  const value = capped.value || UNKNOWN_PATH_TOKEN;
  return Object.freeze({
    value,
    text: value,
    category,
    scope: category,
    complete,
    truncated: capped.truncated,
    sensitive,
  });
}

function invalidPath(maxChars: number): PathProjection {
  return makeProjection(UNKNOWN_PATH_TOKEN, "unknown", false, false, maxChars);
}

/**
 * Project one path-like value without reading the filesystem.
 */
export function projectPathDetailed(
  input: unknown,
  options: PathRedactionOptions = {},
): PathProjection {
  const max = safeMaxChars(options.maxChars);
  if (typeof input !== "string" || input.length === 0 || input.includes("\u0000")) {
    return invalidPath(max.max);
  }
  if (isRecord(input)) return invalidPath(max.max);

  const original = normalizeSlashes(input);
  if (original.length > 1_000_000 || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(original)) {
    return invalidPath(max.max);
  }
  if (original.includes("://") || original.includes("?") || original.includes("#")) {
    return invalidPath(max.max);
  }

  const absolute = isAbsolutePath(original);
  const inferredHome = inferredHomeRoot(original);
  const projectRoot = isValidRoot(options.projectRoot) ? stripTrailingSlashes(normalizeSlashes(options.projectRoot)) : undefined;
  const configuredHome = isValidRoot(options.homeDirectory)
    ? stripTrailingSlashes(normalizeSlashes(options.homeDirectory))
    : undefined;
  const homeDirectory =
    configuredHome !== undefined && isWithin(original, configuredHome)
      ? configuredHome
      : inferredHome ?? configuredHome;
  const roots = uniqueRoots(projectRoot, homeDirectory, options.systemRoots);
  const secret = looksLikeSecretPath(original);
  const protectedPath = looksLikeProtectedPath(original);
  const homeMatch = homeDirectory !== undefined && isWithin(original, homeDirectory);
  const projectMatch = projectRoot !== undefined && isWithin(original, projectRoot);
  const systemMatch = roots.some((root) => root !== projectRoot && root !== homeDirectory && isWithin(original, root));

  let display: string;
  let category: ResourceScope;
  let complete = true;

  if (secret) {
    const relative = relativeForMatch(
      original,
      projectMatch ? projectRoot : homeMatch ? homeDirectory : undefined,
      projectMatch || homeMatch,
    );
    const suffix = projectSuffix(relative);
    display = `${SECRET_PATH_TOKEN}/${suffix.value}`;
    category = "secret";
    complete = suffix.complete;
  } else if (protectedPath) {
    const relative = relativeForMatch(
      original,
      projectMatch ? projectRoot : homeMatch ? homeDirectory : undefined,
      projectMatch || homeMatch,
    );
    const suffix = projectSuffix(relative);
    display = `${PROTECTED_PATH_TOKEN}/${suffix.value}`;
    category = "protected";
    complete = suffix.complete;
  } else if (projectMatch) {
    const relative = relativeForMatch(original, projectRoot, projectMatch);
    const suffix = projectSuffix(relative);
    display = relative.length === 0 ? PROJECT_PATH_TOKEN : `${PROJECT_PATH_TOKEN}/${suffix.value}`;
    category = "project";
    complete = suffix.complete;
  } else if (homeMatch) {
    const relative = relativeForMatch(original, homeDirectory, homeMatch);
    const suffix = projectSuffix(relative);
    display = relative.length === 0 ? HOME_PATH_TOKEN : `${HOME_PATH_TOKEN}/${suffix.value}`;
    category = "home";
    complete = suffix.complete;
  } else if (systemMatch) {
    const systemRoot = roots
      .filter((root) => root !== projectRoot && root !== homeDirectory && isWithin(original, root))
      .sort((left, right) => right.length - left.length)[0];
    const relative = systemRoot === undefined ? original.replace(/^\/+/, "") : relativeToRoot(original, systemRoot);
    const suffix = projectSuffix(relative);
    display = `${SYSTEM_PATH_TOKEN}/${suffix.value}`;
    category = "system";
    complete = suffix.complete;
  } else if (absolute) {
    const withoutRoot = original.replace(/^\/+/, "");
    const suffix = projectSuffix(withoutRoot);
    display = `${EXTERNAL_PATH_TOKEN}/${suffix.value}`;
    category = "external";
    complete = suffix.complete;
  } else {
    const segments = segmentsOf(original);
    if (segments.includes("..")) return invalidPath(max.max);
    const suffix = projectSuffix(original);
    display = suffix.value.length === 0 ? PROJECT_PATH_TOKEN : suffix.value;
    category = "project";
    complete = suffix.complete;
  }

  return makeProjection(display, category, complete && max.valid, secret, max.max);
}

/** String convenience wrapper around {@link projectPathDetailed}. */
export function redactPath(input: unknown, options: PathRedactionOptions = {}): string {
  return projectPathDetailed(input, options).value;
}

/** Stable scope classification for callers that need only the category. */
export function classifyPathScope(input: unknown, options: PathRedactionOptions = {}): ResourceScope {
  return projectPathDetailed(input, options).category;
}
