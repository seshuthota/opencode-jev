/**
 * Pure path inspection with an injected canonicalization port.
 *
 * No filesystem, shell, OpenCode, or TypeSafe imports. All expressions are
 * fixed by the implementation. Location and project boundaries are supplied
 * by the caller; canonicalization is injected so tests can use a fake.
 */

import type {
  ActionCategory,
  GuardrailSignalCode,
  ResourceScope,
} from "../domain.js";
import { dedupeAndSortSignals } from "./signals.js";

/** Narrow canonicalization port. Production resolves the nearest existing ancestor. */
export interface PathResolver {
  canonicalize(input: string): string | undefined;
}

export interface PathBoundaries {
  readonly projectRoot: string;
  readonly homeDirectory?: string;
}

export interface PathAssessment {
  readonly signals: readonly GuardrailSignalCode[];
  readonly hardDeny: boolean;
  readonly scope: ResourceScope;
}

export interface AssessPathOptions {
  readonly boundaries: PathBoundaries;
  readonly resolver?: PathResolver;
  readonly actionCategory?: ActionCategory | string;
}

const SYSTEM_ROOTS: readonly string[] = Object.freeze([
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

const SECRET_BASENAMES: ReadonlySet<string> = new Set([
  ".npmrc",
  ".pypirc",
  "credentials",
  "credentials.json",
  "credentials.yaml",
  "credentials.yml",
  "secrets",
  "secrets.json",
  "secrets.yaml",
  "secrets.yml",
  "cookies",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "authorized_keys",
  "shadow",
  "gshadow",
]);

const PUBLIC_ENV_BASENAMES: ReadonlySet<string> = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
]);

const SECRET_SEGMENTS: ReadonlySet<string> = new Set([
  "credentials",
  "secrets",
  "keychain",
  ".ssh",
  ".aws",
  ".gnupg",
  ".pki",
]);

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

function pathKey(value: string): string {
  const normalized = normalizeSlashes(value);
  return isWindowsDrivePath(normalized) ? normalized.toLowerCase() : normalized;
}

function isWithin(candidate: string, root: string): boolean {
  const candidateKey = pathKey(stripTrailingSlashes(candidate));
  const rootKey = pathKey(stripTrailingSlashes(root));
  return candidateKey === rootKey || candidateKey.startsWith(`${rootKey}/`);
}

function segmentsOf(value: string): readonly string[] {
  return normalizeSlashes(value)
    .split("/")
    .filter((segment) => segment.length > 0);
}

function basenameOf(value: string): string {
  const segments = segmentsOf(value);
  const last = segments.at(-1);
  return last ?? "";
}

function isValidAbsoluteRoot(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0 && isAbsolutePath(normalizeSlashes(value));
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

/** Lexical secret check used before and after canonicalization. */
function isSecretLexical(value: string): boolean {
  const lower = value.toLowerCase();
  const basename = basenameOf(lower);

  if (basename === ".env") return true;
  if (basename.startsWith(".env.") && !PUBLIC_ENV_BASENAMES.has(basename)) return true;
  if (SECRET_BASENAMES.has(basename)) return true;
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/.test(basename)) return true;
  if (/(?:^|[._-])(?:secret|secrets|token|tokens|password|passwd|private[_-]?key|credential|credentials)(?:$|[._-])/.test(basename)) {
    return true;
  }
  const segments = segmentsOf(lower);
  if (segments.some((segment) => SECRET_SEGMENTS.has(segment))) return true;
  if (lower.includes("/.ssh/") || lower.endsWith("/.ssh")) return true;
  if (lower.includes("/.aws/") || lower.endsWith("/.aws")) return true;
  if (lower.includes("/.config/gcloud")) return true;
  if (lower.includes("/.azure/") || lower.endsWith("/.azure")) return true;
  if (lower.includes("keychain")) return true;
  if (lower.includes("login data")) return true;
  if (lower.includes("cookies")) return true;
  if (lower.includes("credential store")) return true;
  return false;
}

/** Narrow protected check: VCS hooks, OpenCode/plugin locations, auth configs. */
function isProtectedLexical(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.includes("/.opencode/") || lower.endsWith("/.opencode")) return true;
  if (lower.endsWith("/opencode.json") || lower.endsWith("/opencode.jsonc")) return true;
  if (basenameOf(lower) === "opencode.json" || basenameOf(lower) === "opencode.jsonc") return true;
  if (lower.includes("/.git/hooks/") || lower.endsWith("/.git/hooks")) return true;
  if (lower.includes("/etc/sudo")) return true;
  if (lower.includes("/etc/ssh/") || lower.endsWith("/etc/ssh")) return true;
  if (lower.includes("/etc/pam")) return true;
  if (lower.includes("/etc/security")) return true;
  return false;
}

function isWriteActionCategory(value: ActionCategory | string | undefined): boolean {
  if (value === "read" || value === "glob" || value === "grep" || value === "webfetch" || value === "websearch") {
    return false;
  }
  return true;
}

function hasMalformedPathChars(value: string): boolean {
  if (value.includes("\u0000")) return true;
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)) return true;
  return false;
}

function looksLikeUrl(value: string): boolean {
  const normalized = normalizeSlashes(value);
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(normalized)) return true;
  if (normalized.includes("://")) return true;
  return false;
}

function classifyResolved(
  resolved: string,
  boundaries: PathBoundaries,
): ResourceScope {
  if (isSecretLexical(resolved)) return "secret";
  if (isProtectedLexical(resolved)) return "protected";

  const projectRoot = isValidAbsoluteRoot(boundaries.projectRoot)
    ? stripTrailingSlashes(normalizeSlashes(boundaries.projectRoot))
    : undefined;
  const configuredHome =
    boundaries.homeDirectory !== undefined && isValidAbsoluteRoot(boundaries.homeDirectory)
      ? stripTrailingSlashes(normalizeSlashes(boundaries.homeDirectory))
      : undefined;
  const inferredHome = inferredHomeRoot(resolved);
  const homeDirectory =
    configuredHome !== undefined && isWithin(resolved, configuredHome)
      ? configuredHome
      : (inferredHome ?? configuredHome);

  if (projectRoot !== undefined && isWithin(resolved, projectRoot)) return "project";
  if (homeDirectory !== undefined && isWithin(resolved, homeDirectory)) return "home";
  if (homeDirectory === undefined && inferredHome !== undefined && isWithin(resolved, inferredHome)) {
    return "home";
  }

  const normalized = normalizeSlashes(resolved);
  for (const root of SYSTEM_ROOTS) {
    if (isWithin(normalized, root)) return "system";
  }
  if (normalized === "/") return "system";
  if (isAbsolutePath(normalized)) return "external";
  return "project";
}

function joinProjectRelative(projectRoot: string, relative: string): string {
  const root = stripTrailingSlashes(normalizeSlashes(projectRoot));
  const suffix = normalizeSlashes(relative).replace(/^\/+/, "");
  return suffix.length === 0 ? root : `${root}/${suffix}`;
}

function frozenAssessment(
  signals: readonly GuardrailSignalCode[],
  scope: ResourceScope,
): PathAssessment {
  const deduped = dedupeAndSortSignals(signals);
  const hardDeny =
    deduped.includes("secret_access") ||
    deduped.includes("destructive_operation") ||
    deduped.includes("privilege_change") ||
    deduped.includes("security_boundary_change") ||
    deduped.includes("obvious_exfiltration");
  return Object.freeze({ signals: deduped, hardDeny, scope });
}

/**
 * Assess one path-like resource value with location boundaries and an
 * injected canonicalizer. Never returns matched values, only stable codes.
 */
export function assessPathResource(
  value: unknown,
  options: AssessPathOptions,
): PathAssessment {
  const boundaries = options.boundaries;
  const actionCategory = options.actionCategory;

  if (typeof value !== "string" || value.length === 0 || value.length > 1_000_000) {
    return frozenAssessment(["unparseable_syntax", "ambiguous_resource"], "unknown");
  }
  if (hasMalformedPathChars(value)) {
    return frozenAssessment(["unparseable_syntax", "ambiguous_resource"], "unknown");
  }
  if (looksLikeUrl(value)) {
    return frozenAssessment(["ambiguous_resource", "unknown_scope"], "unknown");
  }

  const original = normalizeSlashes(value);
  const lexicalSecret = isSecretLexical(original);
  const lexicalProtected = isProtectedLexical(original);

  const projectValid = isValidAbsoluteRoot(boundaries.projectRoot);
  if (!projectValid) {
    const base: GuardrailSignalCode[] = ["unresolved_path", "unknown_scope", "ambiguous_resource"];
    if (lexicalSecret) base.push("secret_access");
    return frozenAssessment(base, lexicalSecret ? "secret" : "unknown");
  }

  const candidate = isAbsolutePath(original)
    ? original
    : joinProjectRelative(boundaries.projectRoot, original);

  // Resolve the project boundary through the same trusted port as the
  // candidate. Otherwise a project opened through a symlink would make all
  // of its real paths appear external after candidate canonicalization.
  let resolvedProjectRoot: string | undefined;
  try {
    resolvedProjectRoot = options.resolver?.canonicalize(boundaries.projectRoot);
  } catch {
    resolvedProjectRoot = undefined;
  }
  if (
    typeof resolvedProjectRoot !== "string" ||
    resolvedProjectRoot.length === 0 ||
    resolvedProjectRoot.length > 1_000_000
  ) {
    if (lexicalSecret) {
      return frozenAssessment(["secret_access", "unresolved_path", "unknown_scope"], "secret");
    }
    return frozenAssessment(["unresolved_path", "unknown_scope"], "unknown");
  }

  const resolvedBoundaries: PathBoundaries = {
    ...boundaries,
    projectRoot: resolvedProjectRoot,
  };

  let resolved: string | undefined;
  try {
    resolved = options.resolver?.canonicalize(candidate);
  } catch {
    resolved = undefined;
  }

  if (typeof resolved !== "string" || resolved.length === 0 || resolved.length > 1_000_000) {
    if (lexicalSecret) {
      return frozenAssessment(
        ["secret_access", "unresolved_path", "unknown_scope"],
        "secret",
      );
    }
    if (lexicalProtected && isWriteActionCategory(actionCategory)) {
      return frozenAssessment(
        ["destructive_operation", "security_boundary_change", "unresolved_path", "unknown_scope"],
        "unknown",
      );
    }
    return frozenAssessment(["unresolved_path", "unknown_scope"], "unknown");
  }

  if (hasMalformedPathChars(resolved) || looksLikeUrl(resolved)) {
    if (lexicalSecret || isSecretLexical(resolved)) {
      return frozenAssessment(["secret_access", "unresolved_path", "unknown_scope"], "secret");
    }
    return frozenAssessment(["unresolved_path", "unknown_scope"], "unknown");
  }

  const scope = classifyResolved(resolved, resolvedBoundaries);

  if (scope === "secret") {
    return frozenAssessment(["secret_access"], "secret");
  }
  if (isWriteActionCategory(actionCategory) && (scope === "protected" || scope === "system")) {
    return frozenAssessment(["destructive_operation", "security_boundary_change"], scope);
  }
  return frozenAssessment([], scope);
}

/** Convenience wrapper that reports only the stable scope. */
export function classifyPathScope(
  value: unknown,
  options: AssessPathOptions,
): ResourceScope {
  return assessPathResource(value, options).scope;
}
