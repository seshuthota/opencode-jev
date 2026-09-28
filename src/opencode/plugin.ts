/**
 * Promise V2 server plugin wiring (Slice 5).
 *
 * Parses and validates options; invalid config enters a safe no-op mode that
 * leaves requests pending. For valid config, creates the coordinator and
 * intent cache, registers the public prompt hook, starts the public event
 * consumer before reconciliation, and returns cleanup that synchronously
 * stops new transitions, aborts event/Jev work, clears timers, disposes the
 * prompt registration, clears raw/intent data, and prevents post-cleanup
 * replies. Package-only; no activation outside this package.
 */

import { Plugin } from "@opencode/plugin";
import { parsePluginOptions } from "../config.js";
import { RelevantIntentCache } from "./intent-cache.js";
import { JevClient } from "../jev/client.js";
import { createAuditSink, type AuditSink } from "../observability/audit.js";
import type { AuditEvent, AuditReason } from "../domain.js";
import { PermissionCoordinator } from "./coordinator.js";

type Context = Parameters<Parameters<typeof Plugin.define>[0]["setup"]>[0];
type Cleanup = () => Promise<void> | void;

export const PLUGIN_ID = "opencode-jev-permissions" as const;

function createSilentAudit(): AuditSink {
  return createAuditSink(() => {});
}

const WARNING_AUDIT_REASONS: ReadonlySet<AuditReason> = new Set([
  "config_invalid",
  "jev_failed",
  "reply_failed",
  "stream_error",
]);

function writePluginAudit(event: AuditEvent, warning: boolean): void {
  try {
    // The audit boundary has already rebuilt the event from closed primitive
    // fields. Serializing that fresh object prevents console inspection from
    // reaching any raw request or exception object.
    const line = JSON.stringify({ plugin: PLUGIN_ID, event });
    if (warning) console.warn(line);
    else console.info(line);
  } catch {
    // Observability must never affect permission handling.
  }
}

export function createPluginAudit(level: "info" | "warn" | "off"): AuditSink {
  if (level === "off") return createSilentAudit();
  return createAuditSink((event) => {
    const warning = WARNING_AUDIT_REASONS.has(event.reason);
    if (level === "warn" && !warning) return;
    writePluginAudit(event, warning);
  });
}

/**
 * Plugin setup for the Promise V2 server runtime.
 *
 * Never reads TYPESAFE_API_KEY, never performs network calls during setup,
 * and never throws for invalid options (enters safe no-op instead).
 */
export async function setup(context: Context): Promise<Cleanup> {
  const parsed = parsePluginOptions(context.options);
  if (parsed.ok !== true) {
    const audit = createPluginAudit("warn");
    try {
      audit.emit({ schemaVersion: 1, reason: "config_invalid", outcome: "skipped" });
    } catch {
      // Never throw for invalid config.
    }
    return () => {};
  }
  const config = parsed.value;

  const audit = createPluginAudit(config.pluginLogLevel);
  const intentCache = new RelevantIntentCache({
    maxChars: config.limits.intentChars,
  });

  const client = new JevClient({
    model: config.model,
    timeoutMs: config.timeoutMs,
    maxRetries: config.maxRetries,
  });

  const locationDirectory: string = context.location.directory;

  const coordinator = new PermissionCoordinator({
    locationDirectory,
    maxConcurrency: config.maxConcurrency,
    maxQueueSize: config.maxQueueSize,
    reconcileIntervalMs: config.reconcileIntervalMs,
    thresholds: config.thresholds,
    limits: {
      commandChars: config.limits.commandChars,
      intentChars: config.limits.intentChars,
      resources: config.limits.resources,
      resourceChars: config.limits.resourceChars,
    },
    ports: {
      sessionGet: (input) => context.session.get(input),
      permissionList: (input) => context.permission.list(input),
      permissionGet: (input) => context.permission.get(input),
      permissionReply: (input) => context.permission.reply(input),
      sessionContext: (input) => context.session.context(input),
    },
    intentCache,
    jevEvaluate: (redacted, assessment, options) =>
      client.evaluate(redacted, assessment, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        timeoutMs: config.timeoutMs,
      }),
    audit,
    subscribeEvents: (signal) => context.event.subscribe({ signal }),
  });

  // Register prompt-hook intent updates before starting the event consumer,
  // then enable interval/reconciliation work only after subscription starts.
  let registration: { dispose: () => Promise<void> } | undefined;
  try {
    registration = await context.session.hook("prompt", async (input) => {
      try {
        await coordinator.notifyPrompt(input);
      } catch {
        // Never break the host on intent failures.
      }
    });
  } catch {
    coordinator.dispose();
    try {
      intentCache.clear();
    } catch {
      // Ignore.
    }
    return () => {};
  }

  coordinator.startEventLoop();
  coordinator.startInterval();
  void coordinator.reconcileAll().catch(() => {});

  let cleaned = false;
  const cleanup: Cleanup = async () => {
    if (cleaned) return;
    cleaned = true;
    // Synchronously stop new transitions first.
    try {
      coordinator.dispose();
    } catch {
      // Never throw from cleanup.
    }
    try {
      intentCache.clear();
    } catch {
      // Ignore.
    }
    const active = registration;
    registration = undefined;
    if (active !== undefined) {
      try {
        await active.dispose();
      } catch {
        // Disposal failures never throw.
      }
    }
  };

  return cleanup;
}

export const plugin = { id: PLUGIN_ID, setup };
