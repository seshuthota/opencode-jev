/**
 * Pure shell inspection without execution.
 *
 * Tokenizes shell text with fixed lexical rules and correlates secret sources
 * with network sinks. No shell is spawned, no value is logged, and no caller
 * expression is compiled. Stable codes only.
 */

import type { GuardrailSignalCode } from "../domain.js";
import { dedupeAndSortSignals } from "./signals.js";

export interface ShellAssessment {
  readonly signals: readonly GuardrailSignalCode[];
  readonly hardDeny: boolean;
  readonly hasSecretSource: boolean;
  readonly hasNetworkSink: boolean;
  readonly unparseable: boolean;
}

const PRIVILEGE_COMMANDS: ReadonlySet<string> = new Set([
  "sudo",
  "doas",
  "su",
  "runas",
  "gsudo",
  "sudoedit",
  "sg",
]);

const NETWORK_COMMANDS: ReadonlySet<string> = new Set([
  "curl",
  "wget",
  "aria2c",
  "nc",
  "netcat",
  "ncat",
  "socat",
  "ssh",
  "scp",
  "sftp",
  "rsync",
  "ftp",
  "lftp",
  "rclone",
  "gsutil",
  "azcopy",
]);

const FIREWALL_COMMANDS: ReadonlySet<string> = new Set([
  "iptables",
  "ip6tables",
  "ufw",
  "firewall-cmd",
  "nft",
  "pfctl",
  "setenforce",
  "csrutil",
]);

const EDITOR_COMMANDS: ReadonlySet<string> = new Set([
  "vi",
  "vim",
  "nvim",
  "nano",
  "emacs",
  "code",
  "ed",
]);

const WRITE_COMMANDS: ReadonlySet<string> = new Set([
  "cp",
  "mv",
  "tee",
  "install",
  "dd",
  "chmod",
  "chown",
  "chgrp",
]);

const SHELL_KEYWORDS: ReadonlySet<string> = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "function",
  "select",
  "time",
  "coproc",
]);

const PASTE_HOSTS: readonly string[] = Object.freeze([
  "pastebin",
  "paste.rs",
  "transfer.sh",
  "0x0.st",
  "file.io",
  "termbin",
  "ix.io",
  "hastebin",
]);

const WRAPPER_SHELLS: ReadonlySet<string> = new Set([
  "sh",
  "bash",
  "dash",
  "zsh",
  "fish",
  "ksh",
  "ash",
]);

const MAX_WRAPPER_DEPTH = 3;

const SYSTEM_PREFIXES: readonly string[] = Object.freeze([
  "/etc/",
  "/usr/bin/",
  "/usr/sbin/",
  "/sbin/",
  "/bin/",
  "/boot/",
  "/proc/",
  "/sys/",
  "/dev/",
  "/root/",
]);

function commandBasename(token: string): string {
  const stripped = token.replace(/^["']+|["']+$/g, "");
  const withoutQuotes = stripped.replaceAll("\\", "/");
  const parts = withoutQuotes.split("/");
  const last = parts.at(-1) ?? "";
  return last.toLowerCase();
}

function stripTokenWrapping(token: string): string {
  let result = token;
  if (
    (result.startsWith('"') && result.endsWith('"') && result.length >= 2) ||
    (result.startsWith("'") && result.endsWith("'") && result.length >= 2)
  ) {
    result = result.slice(1, -1);
  }
  return result.replace(/^[@]+/, "").replace(/^=+/, "");
}

function trimShellPunctuation(value: string): string {
  return value.replace(/^[@=:,;<>[\]{}()]+|[@=:,;<>[\]{}().,;:!?)+]+$/g, "");
}

function shellTokenIsSecretPath(token: string): boolean {
  const cleaned = stripTokenWrapping(token).toLowerCase();
  if (cleaned.length === 0) return false;
  const trimmed = trimShellPunctuation(cleaned);
  if (trimmed.length === 0) return false;
  const basename = trimmed.split("/").at(-1) ?? "";
  if (basename === ".env") return true;
  if (
    basename.startsWith(".env.") &&
    basename !== ".env.example" &&
    basename !== ".env.sample" &&
    basename !== ".env.template"
  ) {
    return true;
  }
  if (
    basename === ".npmrc" ||
    basename === ".pypirc" ||
    basename === "credentials" ||
    basename === "credentials.json" ||
    basename === "credentials.yaml" ||
    basename === "credentials.yml" ||
    basename === "secrets" ||
    basename === "secrets.json" ||
    basename === "secrets.yaml" ||
    basename === "secrets.yml" ||
    basename === "cookies" ||
    basename === "cookies.sqlite" ||
    basename === "id_rsa" ||
    basename === "id_dsa" ||
    basename === "id_ecdsa" ||
    basename === "id_ed25519" ||
    basename === "authorized_keys" ||
    basename === "shadow" ||
    basename === "gshadow"
  ) {
    return true;
  }
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/.test(basename)) return true;
  const segments = trimmed.split("/").filter((segment) => segment.length > 0);
  if (
    segments.some(
      (segment) =>
        segment === "credentials" ||
        segment === "secrets" ||
        segment === "keychain" ||
        segment === ".ssh" ||
        segment === ".aws" ||
        segment === ".gnupg" ||
        segment === ".pki",
    )
  ) {
    return true;
  }
  if (cleaned.includes("/.ssh/") || cleaned.endsWith("/.ssh")) return true;
  if (cleaned.includes("/.aws/") || cleaned.endsWith("/.aws")) return true;
  if (cleaned.includes("/.gnupg/") || cleaned.endsWith("/.gnupg")) return true;
  if (cleaned.includes("/.pki/") || cleaned.endsWith("/.pki")) return true;
  if (cleaned.includes("/.config/gcloud")) return true;
  if (cleaned.includes("/.azure/") || cleaned.endsWith("/.azure")) return true;
  if (cleaned.includes("keychain")) return true;
  if (cleaned.includes("login data")) return true;
  if (cleaned.includes("cookies")) return true;
  if (cleaned.includes("credential store")) return true;
  if (cleaned.includes("/etc/shadow") || cleaned.includes("/etc/gshadow")) return true;
  if (cleaned.includes(".ssh/id_rsa") || cleaned.includes(".ssh/id_ed25519")) return true;
  // Generic secret-word basename pattern applies only to path-like tokens so
  // bare search terms such as `grep password` stay safe. Path resources still
  // catch bare names through the path policy.
  const pathLike =
    trimmed.includes("/") ||
    trimmed.includes(".") ||
    trimmed.startsWith("~") ||
    trimmed.startsWith("$") ||
    trimmed.startsWith(".");
  if (
    pathLike &&
    /(?:^|[._-])(?:secret|secrets|token|tokens|password|passwd|private[_-]?key|credential|credentials)(?:$|[._-])/.test(
      basename,
    )
  ) {
    return true;
  }
  return false;
}

function shellTokenIsProtectedPath(token: string): boolean {
  const cleaned = stripTokenWrapping(token).toLowerCase();
  if (cleaned.includes("/.opencode/") || cleaned.endsWith("/.opencode")) return true;
  if (cleaned.endsWith("opencode.json") || cleaned.endsWith("opencode.jsonc")) return true;
  if (cleaned.includes("/.git/hooks/")) return true;
  if (cleaned.includes("/etc/sudo")) return true;
  if (cleaned.includes("/etc/ssh/")) return true;
  if (cleaned.includes("/etc/pam")) return true;
  if (cleaned.includes("/etc/security")) return true;
  return false;
}

function shellTokenIsSystemPath(token: string): boolean {
  const cleaned = stripTokenWrapping(token);
  for (const prefix of SYSTEM_PREFIXES) {
    if (cleaned.startsWith(prefix) || cleaned.toLowerCase().startsWith(prefix)) return true;
  }
  if (cleaned === "/etc" || cleaned === "/usr" || cleaned === "/bin" || cleaned === "/sbin") return true;
  return false;
}

function tokenRevealsSecret(token: string): boolean {
  const lower = token.toLowerCase();
  if (token.includes("-----begin") && token.toLowerCase().includes("private key")) return true;
  if (lower.startsWith("--") || lower.startsWith("-")) {
    if (
      lower.includes("password") ||
      lower.includes("passwd") ||
      lower.includes("secret") ||
      lower.includes("token") ||
      lower.includes("api-key") ||
      lower.includes("apikey") ||
      lower.includes("cookie") ||
      lower.includes("credential") ||
      lower.includes("private-key") ||
      lower.includes("auth")
    ) {
      if (lower.startsWith("--") && lower.length > 3) return true;
      if (lower.includes("=") || lower.includes(":")) return true;
    }
    if (lower === "--user" || lower === "-u" || lower === "--password" || lower === "--token") return true;
  }
  if (token.includes("=")) {
    const beforeEqual = lower.split("=").at(0) ?? "";
    if (
      beforeEqual.includes("password") ||
      beforeEqual.includes("passwd") ||
      beforeEqual.includes("secret") ||
      beforeEqual.includes("token") ||
      beforeEqual.includes("api_key") ||
      beforeEqual.includes("apikey") ||
      beforeEqual.includes("credential") ||
      beforeEqual.includes("private_key") ||
      beforeEqual.includes("cookie") ||
      beforeEqual.includes("auth") ||
      beforeEqual.includes("signature")
    ) {
      return true;
    }
  }
  if (token.includes(":")) {
    if (
      lower.startsWith("authorization:") ||
      lower.startsWith("cookie:") ||
      lower.startsWith("set-cookie:") ||
      lower.includes("bearer") ||
      lower.includes("basic ")
    ) {
      return true;
    }
  }
  if (/authorization\s*:\s*bearer/i.test(token)) return true;
  if (/\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/i.test(token)) return true;
  return false;
}

function tokenIsNetworkUrl(token: string): boolean {
  const lower = stripTokenWrapping(token).toLowerCase();
  if (lower.startsWith("https://") || lower.startsWith("http://") || lower.startsWith("ftp://")) return true;
  for (const host of PASTE_HOSTS) {
    if (lower.includes(host)) return true;
  }
  return false;
}

function chmodTokenIsSetuid(token: string): boolean {
  const lower = token.toLowerCase();
  if (lower === "u+s" || lower === "g+s" || lower === "+s" || lower === "a+s") return true;
  if (lower.includes("u+s") || lower.includes("g+s")) return true;
  if (/^[0-7]{4}$/.test(token)) {
    const first = token.at(0) ?? "";
    if (first === "4" || first === "2" || first === "6" || first === "7") return true;
  }
  if (/^[0-7]{3}$/.test(token)) return false;
  return false;
}

function hasControlChars(value: string): boolean {
  if (value.includes("\u0000")) return true;
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)) return true;
  return false;
}

function hasUnmatchedQuotes(value: string): boolean {
  let single = false;
  let double = false;
  let escaped = false;
  for (const ch of value) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "'" && !double) single = !single;
    if (ch === '"' && !single) double = !double;
  }
  return single || double;
}

function detectLexicalUnparseable(command: string): boolean {
  if (command.includes("`")) return true;
  if (command.includes("$(") || command.includes("${")) return true;
  if (/\bbase64\b/i.test(command)) return true;
  if (/\bxxd\b/i.test(command)) return true;
  if (/\bhexdump\b/i.test(command)) return true;
  if (/\buuencode\b/i.test(command)) return true;
  if (/\bopenssl\b/i.test(command) && /enc/i.test(command)) return true;
  if (/\beval\b/i.test(command)) return true;
  if (/(?:^|[\s;&|])(?:exec)(?:\s|$|;)/i.test(command)) return true;
  return false;
}

function detectOperatorUnparseable(command: string): boolean {
  let single = false;
  let double = false;
  let escaped = false;
  for (let i = 0; i < command.length; i += 1) {
    const ch = command.at(i) ?? "";
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "'" && !double) {
      single = !single;
      continue;
    }
    if (ch === '"' && !single) {
      double = !double;
      continue;
    }
    if (single || double) continue;
    if (ch === "`") return true;
    if (ch === "(" || ch === ")") return true;
    if (ch === "!") return true;
    if (ch === "&") {
      const next = command.at(i + 1) ?? "";
      const prev = command.at(i - 1) ?? "";
      if (next === "&" || prev === "&") continue;
      return true;
    }
  }
  return false;
}

/** Split shell text into tokens with separators preserved for boundary checks. */
function tokenizeWithSeparators(command: string): readonly string[] {
  const tokens: string[] = [];
  let current = "";
  let single = false;
  let double = false;
  let escaped = false;
  const flush = (): void => {
    if (current.length > 0) {
      tokens.push(current);
      current = "";
    }
  };
  for (let i = 0; i < command.length; i += 1) {
    const ch = command.at(i) ?? "";
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && !single) {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === "'" && !double) {
      single = !single;
      current += ch;
      continue;
    }
    if (ch === '"' && !single) {
      double = !double;
      current += ch;
      continue;
    }
    if (single || double) {
      current += ch;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      flush();
      continue;
    }
    const next = command.at(i + 1) ?? "";
    if (ch === "&" && next === "&") {
      flush();
      tokens.push("&&");
      i += 1;
      continue;
    }
    if (ch === "|" && next === "|") {
      flush();
      tokens.push("||");
      i += 1;
      continue;
    }
    if (ch === ">" && next === ">") {
      flush();
      tokens.push(">>");
      i += 1;
      continue;
    }
    if (ch === "|" || ch === ";" || ch === ">" || ch === "<" || ch === "&" || ch === "(" || ch === ")") {
      flush();
      tokens.push(ch);
      continue;
    }
    current += ch;
  }
  flush();
  return Object.freeze(tokens);
}

function isSeparator(token: string): boolean {
  return (
    token === "|" ||
    token === "&&" ||
    token === "||" ||
    token === ";" ||
    token === ">" ||
    token === ">>" ||
    token === "<" ||
    token === "&" ||
    token === "(" ||
    token === ")"
  );
}

function stripOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed.at(0) ?? "";
    const last = trimmed.at(-1) ?? "";
    if ((first === "'" && last === "'") || (first === '"' && last === '"')) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function extractQuotedPayloads(tokens: readonly string[]): readonly string[] {
  const payloads: string[] = [];
  for (const token of tokens) {
    if (isSeparator(token)) continue;
    const stripped = token.trim();
    if (stripped.length >= 2) {
      const first = stripped.at(0) ?? "";
      const last = stripped.at(-1) ?? "";
      if ((first === "'" && last === "'") || (first === '"' && last === '"')) {
        const inner = stripped.slice(1, -1);
        if (inner.trim().length > 0 && inner.length < 100_000) payloads.push(inner);
      }
    }
  }
  return Object.freeze(payloads);
}

function assessNestedWrappers(
  rawInput: string,
  tokens: readonly string[],
  commandStarts: ReadonlyArray<{ index: number; name: string }>,
  depth: number,
): {
  signals: GuardrailSignalCode[];
  hasSecretSource: boolean;
  hasNetworkSink: boolean;
} {
  const signals: GuardrailSignalCode[] = [];
  let hasSecretSource = false;
  let hasNetworkSink = false;
  let hasWrapper = false;
  const inners: string[] = [];

  if (depth >= MAX_WRAPPER_DEPTH) {
    for (const { name } of commandStarts) {
      if (WRAPPER_SHELLS.has(name) || name === "xargs") {
        hasWrapper = true;
        break;
      }
    }
    if (hasWrapper && !signals.includes("unparseable_syntax")) {
      signals.push("unparseable_syntax");
    }
    return { signals, hasSecretSource, hasNetworkSink };
  }

  for (const { index, name } of commandStarts) {
    if (!WRAPPER_SHELLS.has(name)) continue;
    const args: string[] = [];
    for (let i = index + 1; i < tokens.length; i += 1) {
      const token = tokens[i] ?? "";
      if (isSeparator(token)) break;
      args.push(token);
    }
    let dashC = -1;
    for (let k = 0; k < args.length; k += 1) {
      const candidate = (args[k] ?? "").toLowerCase();
      if (candidate === "-c" || candidate === "-lc" || candidate === "-ic") {
        dashC = k;
        break;
      }
    }
    if (dashC >= 0) {
      hasWrapper = true;
      const payloadTokens = args.slice(dashC + 1);
      if (payloadTokens.length === 0) continue;
      const joined = payloadTokens.join(" ").trim();
      if (joined.length === 0) continue;
      const inner = stripOuterQuotes(joined);
      if (inner.length === 0 || inner === rawInput) continue;
      if (inner.length < 100_000 && !inners.includes(inner)) inners.push(inner);
    } else {
      hasWrapper = true;
    }
  }

  for (const { index, name } of commandStarts) {
    if (name !== "xargs") continue;
    hasWrapper = true;
    const args: string[] = [];
    for (let i = index + 1; i < tokens.length; i += 1) {
      const token = tokens[i] ?? "";
      if (isSeparator(token)) break;
      args.push(token);
    }
    let start = 0;
    while (start < args.length) {
      const candidate = args[start] ?? "";
      if (candidate === "--") {
        start += 1;
        break;
      }
      if (candidate === "{}") {
        start += 1;
        continue;
      }
      if (candidate.startsWith("-")) {
        start += 1;
        continue;
      }
      break;
    }
    const rest = args.slice(start);
    if (rest.length === 0) continue;
    const joined = rest.join(" ").trim();
    if (joined.length === 0 || joined === rawInput) continue;
    if (joined.length < 100_000 && !inners.includes(joined)) inners.push(joined);
  }

  for (let i = 0; i < tokens.length; i += 1) {
    const candidate = (tokens[i] ?? "").toLowerCase();
    if (candidate !== "-exec" && candidate !== "-execdir") continue;
    hasWrapper = true;
    const payload: string[] = [];
    for (let j = i + 1; j < tokens.length; j += 1) {
      const token = tokens[j] ?? "";
      if (token === ";" || token === "\\;" || token === "+" || token === "\\+") break;
      if (token === "|" || token === "&&" || token === "||") break;
      payload.push(token);
    }
    if (payload.length === 0) continue;
    const joined = payload.join(" ").trim();
    if (joined.length === 0 || joined === rawInput) continue;
    if (joined.length < 100_000 && !inners.includes(joined)) inners.push(joined);
  }

  for (let i = 0; i < tokens.length; i += 1) {
    if ((tokens[i] ?? "") !== "|") continue;
    const next = tokens[i + 1] ?? "";
    if (next.length === 0 || isSeparator(next)) continue;
    const name = commandBasename(next);
    if (WRAPPER_SHELLS.has(name) || name === "xargs") {
      hasWrapper = true;
      for (const quoted of extractQuotedPayloads(tokens)) {
        if (quoted !== rawInput && !inners.includes(quoted)) inners.push(quoted);
      }
      break;
    }
  }

  if (!hasWrapper) return { signals, hasSecretSource, hasNetworkSink };

  let anyDirty = false;
  for (const inner of inners) {
    if (inner === rawInput) continue;
    const result = assessShellCommandDepth(inner, depth + 1);
    for (const signal of result.signals) {
      if (!signals.includes(signal)) signals.push(signal);
    }
    if (result.hasSecretSource) hasSecretSource = true;
    if (result.hasNetworkSink) hasNetworkSink = true;
    if (result.signals.length > 0 || result.unparseable || result.hardDeny) anyDirty = true;
  }

  if (inners.length === 0) {
    if (!signals.includes("unparseable_syntax")) signals.push("unparseable_syntax");
  } else if (anyDirty) {
    if (!signals.includes("unparseable_syntax")) signals.push("unparseable_syntax");
  }
  return { signals, hasSecretSource, hasNetworkSink };
}

function frozenShellAssessment(
  signals: readonly GuardrailSignalCode[],
  hasSecretSource: boolean,
  hasNetworkSink: boolean,
  unparseable: boolean,
): ShellAssessment {
  const deduped = dedupeAndSortSignals(signals);
  const hardDeny =
    deduped.includes("secret_access") ||
    deduped.includes("destructive_operation") ||
    deduped.includes("privilege_change") ||
    deduped.includes("security_boundary_change") ||
    deduped.includes("obvious_exfiltration");
  return Object.freeze({
    signals: deduped,
    hardDeny,
    hasSecretSource: hasSecretSource || deduped.includes("secret_access"),
    hasNetworkSink,
    unparseable,
  });
}

/**
 * Inspect one shell command string without execution. Returns stable codes
 * only and flags secret-source / network-sink correlation for the caller.
 */
export function assessShellCommand(input: unknown): ShellAssessment {
  return assessShellCommandDepth(input, 0);
}

function assessShellCommandDepth(input: unknown, depth: number): ShellAssessment {
  if (typeof input !== "string" || input.length === 0 || input.length > 1_000_000) {
    return frozenShellAssessment(["unparseable_syntax"], false, false, true);
  }
  if (input.trim().length === 0) {
    return frozenShellAssessment(["unparseable_syntax"], false, false, true);
  }
  if (hasControlChars(input)) {
    return frozenShellAssessment(["unparseable_syntax"], false, false, true);
  }

  const lexicalUnparseable = detectLexicalUnparseable(input);
  const operatorUnparseable = detectOperatorUnparseable(input);
  const quotesUnparseable = hasUnmatchedQuotes(input);
  const unparseable = lexicalUnparseable || operatorUnparseable || quotesUnparseable;

  const signals: GuardrailSignalCode[] = [];
  if (unparseable) signals.push("unparseable_syntax");

  if (input.includes("BEGIN") && input.includes("PRIVATE KEY")) {
    signals.push("secret_access");
  }

  const tokens = tokenizeWithSeparators(input);
  if (tokens.length === 0) {
    if (!signals.includes("unparseable_syntax")) signals.push("unparseable_syntax");
    return frozenShellAssessment(signals, false, false, true);
  }

  let hasSecretSource = signals.includes("secret_access");
  let hasNetworkSink = false;

  const atCommandStartIndexes = new Set<number>();
  let atStart = true;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i] ?? "";
    if (isSeparator(token)) {
      atStart = true;
      continue;
    }
    if (atStart) atCommandStartIndexes.add(i);
    atStart = false;
  }

  const commandStarts: Array<{ index: number; name: string }> = [];
  for (const index of atCommandStartIndexes) {
    const token = tokens[index] ?? "";
    commandStarts.push({ index, name: commandBasename(token) });
  }

  for (const { name } of commandStarts) {
    if (PRIVILEGE_COMMANDS.has(name)) {
      if (!signals.includes("privilege_change")) signals.push("privilege_change");
    }
    if (FIREWALL_COMMANDS.has(name)) {
      if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
    }
    if (name === "setcap") {
      if (!signals.includes("privilege_change")) signals.push("privilege_change");
    }
    if (SHELL_KEYWORDS.has(name)) {
      if (!signals.includes("unparseable_syntax")) signals.push("unparseable_syntax");
    }
  }

  for (const token of tokens) {
    if (isSeparator(token)) continue;
    if (tokenRevealsSecret(token)) hasSecretSource = true;
    if (shellTokenIsSecretPath(token)) hasSecretSource = true;
    if (tokenIsNetworkUrl(token)) hasNetworkSink = true;
  }

  for (const { name } of commandStarts) {
    if (NETWORK_COMMANDS.has(name)) hasNetworkSink = true;
  }
  if (tokens.some((token) => token.toLowerCase() === "s3" && tokens.some((t) => t.toLowerCase() === "aws"))) {
    hasNetworkSink = true;
  }
  for (const token of tokens) {
    const lower = stripTokenWrapping(token).toLowerCase();
    if (
      lower === "pastebin" ||
      lower.includes("paste.rs") ||
      lower.includes("transfer.sh") ||
      lower.includes("0x0.st")
    ) {
      hasNetworkSink = true;
    }
  }

  if (hasSecretSource && !signals.includes("secret_access")) signals.push("secret_access");

  const nonSeparatorTokens = tokens.filter((token) => !isSeparator(token));
  const lowerTokens = nonSeparatorTokens.map((token) => token.toLowerCase());

  const checkRm = (): void => {
    for (const { index, name } of commandStarts) {
      if (name !== "rm") continue;
      const args: string[] = [];
      for (let i = index + 1; i < tokens.length; i += 1) {
        const token = tokens[i] ?? "";
        if (isSeparator(token)) break;
        args.push(token);
      }
      const flags = args.filter((arg) => arg.startsWith("-")).join(" ");
      const hasRecursive = flags.includes("r") || flags.includes("R") || lowerTokens.includes("--recursive");
      const hasForce = flags.includes("f") || lowerTokens.includes("--force");
      const isHelpOnly = args.length === 1 && (args[0] === "--help" || args[0] === "-h");
      if (isHelpOnly) continue;
      if (hasRecursive || hasForce) {
        if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
      }
    }
  };

  const checkSimpleDestructive = (): void => {
    for (const { name } of commandStarts) {
      if (
        name === "mkfs" ||
        name.startsWith("mkfs.") ||
        name === "fdisk" ||
        name === "parted" ||
        name === "wipefs" ||
        name === "shred"
      ) {
        if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
      }
      if (name === "kill" || name === "killall" || name === "pkill") {
        if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
      }
      if (name === "shutdown" || name === "reboot" || name === "halt" || name === "poweroff") {
        if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
      }
    }
    for (const { index, name } of commandStarts) {
      if (name === "dd") {
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          const lower = token.toLowerCase();
          if (lower.startsWith("of=") && lower.includes("/dev/")) {
            if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
          }
        }
      }
      if (name === "chmod" || name === "chown" || name === "chgrp") {
        const args: string[] = [];
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          args.push(token);
        }
        if (args.some((arg) => arg === "-R" || arg === "--recursive" || arg === "-r")) {
          if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
        }
        for (const arg of args) {
          if (chmodTokenIsSetuid(arg)) {
            if (!signals.includes("privilege_change")) signals.push("privilege_change");
          }
        }
        if (args.some((arg) => arg === "777" || arg === "666" || arg === "a+w" || arg === "o+w")) {
          if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
        }
      }
      if (name === "systemctl") {
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = (tokens[i] ?? "").toLowerCase();
          if (isSeparator(tokens[i] ?? "")) break;
          if (
            token === "stop" ||
            token === "reboot" ||
            token === "poweroff" ||
            token === "halt" ||
            token === "kill"
          ) {
            if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
            break;
          }
        }
      }
      if (name === "git") {
        const args: string[] = [];
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          args.push(token.toLowerCase());
        }
        const sub = args.at(0) ?? "";
        if (sub === "reset" && args.includes("--hard")) {
          if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
        }
        if (sub === "clean" && args.some((arg) => arg === "-f" || arg === "-d" || arg === "-fd" || arg === "-df" || arg.includes("f"))) {
          const hasForceFlag = args.some((arg) => arg.startsWith("-") && arg.includes("f"));
          if (hasForceFlag) {
            if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
          }
        }
        if (sub === "push" && (args.includes("--force") || args.includes("-f"))) {
          if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
        }
      }
    }
    const joined = ` ${lowerTokens.join(" ")} `;
    if (
      joined.includes(" drop database ") ||
      joined.includes(" drop table ") ||
      joined.includes(" drop schema ") ||
      /\bdrop\s+(database|table|schema)\b/i.test(input)
    ) {
      if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
    }
    if (/(?:^|\s)truncate(?:\s|$)/.test(joined) || /\btruncate\b/i.test(input)) {
      if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
    }
    if (
      unparseable &&
      /\brm\b/i.test(input) &&
      (/\brm\b[^\n;|&]*-[A-Za-z]*r/i.test(input) ||
        /\brm\b[^\n;|&]*-[A-Za-z]*f/i.test(input) ||
        input.toLowerCase().includes("--recursive") ||
        input.toLowerCase().includes("--force"))
    ) {
      if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
    }
  };

  const checkSystemBoundaryWrites = (): void => {
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i] ?? "";
      if (token === ">" || token === ">>") {
        const target = tokens[i + 1] ?? "";
        if (target.length === 0 || isSeparator(target)) continue;
        if (shellTokenIsSecretPath(target)) {
          if (!signals.includes("secret_access")) signals.push("secret_access");
          hasSecretSource = true;
        }
        if (shellTokenIsProtectedPath(target) || shellTokenIsSystemPath(target)) {
          if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
          if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
        }
      }
    }
    for (const { index, name } of commandStarts) {
      if (EDITOR_COMMANDS.has(name) || WRITE_COMMANDS.has(name)) {
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          if (token.startsWith("-")) continue;
          if (shellTokenIsProtectedPath(token) || shellTokenIsSystemPath(token)) {
            if (!signals.includes("destructive_operation")) signals.push("destructive_operation");
            if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
          }
          if (shellTokenIsSecretPath(token)) {
            if (!signals.includes("secret_access")) signals.push("secret_access");
            hasSecretSource = true;
          }
        }
      }
      if (name === "export" || name === "setenv" || name === "set") {
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          if (token.startsWith("PATH=") || token.includes(" PATH=")) {
            if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
          }
        }
      }
      if (name === "env" || name === "printenv") {
        if (!signals.includes("secret_access")) signals.push("secret_access");
        hasSecretSource = true;
      }
      if (name === "export") {
        const args: string[] = [];
        for (let i = index + 1; i < tokens.length; i += 1) {
          const token = tokens[i] ?? "";
          if (isSeparator(token)) break;
          args.push(token);
        }
        const hasAssignment = args.some((arg) => arg.includes("="));
        if (!hasAssignment) {
          if (!signals.includes("secret_access")) signals.push("secret_access");
          hasSecretSource = true;
        }
        if (args.some((arg) => arg.startsWith("PATH="))) {
          if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
        }
      }
    }
    for (const token of tokens) {
      if (isSeparator(token)) continue;
      if (token.startsWith("PATH=") && token.includes("/")) {
        if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
      }
      if (shellTokenIsProtectedPath(token)) {
        const owningStart = commandStarts.some(({ index }) => {
          const cmdToken = tokens[index] ?? "";
          const cmdName = commandBasename(cmdToken);
          return (
            EDITOR_COMMANDS.has(cmdName) ||
            WRITE_COMMANDS.has(cmdName) ||
            cmdName === "echo" ||
            cmdName === "printf"
          );
        });
        void owningStart;
      }
    }
    for (const token of tokens) {
      if (isSeparator(token)) continue;
      const cleaned = stripTokenWrapping(token).toLowerCase();
      if (
        cleaned.includes("/etc/sudoers") ||
        cleaned.includes("/etc/ssh/") ||
        cleaned.includes("/etc/pam") ||
        cleaned.includes("/etc/security")
      ) {
        const isReadOnlyCat =
          commandStarts.length === 1 &&
          ["cat", "less", "head", "tail", "grep", "ls"].includes(commandStarts[0]?.name ?? "");
        if (!isReadOnlyCat) {
          if (!signals.includes("security_boundary_change")) signals.push("security_boundary_change");
        } else if (cleaned.includes("/etc/shadow") || cleaned.includes("/etc/gshadow")) {
          continue;
        }
      }
    }
  };

  checkRm();
  checkSimpleDestructive();
  checkSystemBoundaryWrites();
  const nested = assessNestedWrappers(input, tokens, commandStarts, depth);
  for (const signal of nested.signals) {
    if (!signals.includes(signal)) signals.push(signal);
  }
  if (nested.hasSecretSource) hasSecretSource = true;
  if (nested.hasNetworkSink) hasNetworkSink = true;

  if (hasSecretSource && !signals.includes("secret_access")) signals.push("secret_access");
  if (hasSecretSource && hasNetworkSink) {
    if (!signals.includes("obvious_exfiltration")) signals.push("obvious_exfiltration");
  }

  const finalUnparseable = unparseable || signals.includes("unparseable_syntax");
  return frozenShellAssessment(signals, hasSecretSource, hasNetworkSink, finalUnparseable);
}
