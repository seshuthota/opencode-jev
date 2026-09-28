import { Plugin } from "@opencode/plugin";
import {
  choice,
  type SystemOneRequest,
  type TypeSafeClient,
  type TypeSafeClientConfig,
} from "@typesafe-ai/sdk";

import type { AutomaticReply, InternalPermissionReply } from "../../src/domain.js";

/*
 * This file is intentionally compile-only. The functions below describe the
 * installed public contracts; they are never invoked by the test suite.
 */
type PluginDefinition = Parameters<typeof Plugin.define>[0];
type Setup = PluginDefinition["setup"];
type Context = Parameters<Setup>[0];
type Cleanup = Exclude<Awaited<ReturnType<Setup>>, void>;

type EventStream = ReturnType<Context["event"]["subscribe"]>;
type OpenCodeEvent = EventStream extends AsyncIterable<infer Event> ? Event : never;
type PermissionAskedEvent = Extract<OpenCodeEvent, { readonly type: "permission.asked" }>;
type PermissionListInput = Parameters<Context["permission"]["list"]>[0];

// The installed public context requires a session for permission.list.
export type PermissionListIsSessionScoped = Assert<
  PermissionListInput extends { readonly sessionID: string } ? true : false
>;

// Session.list is not part of the installed Promise Context. Do not infer it.
export type SessionListIsNotExposed = Assert<"list" extends keyof Context["session"] ? false : true>;

function isPermissionAsked(event: OpenCodeEvent): event is PermissionAskedEvent {
  return event.type === "permission.asked";
}

function readPermissionEvent(event: OpenCodeEvent): { sessionID: string; requestID: string } | undefined {
  if (!isPermissionAsked(event)) return undefined;

  // Installed public event shape: permission.asked carries the request at data.
  return { sessionID: event.data.sessionID, requestID: event.data.id };
}

async function verifyOpenCodeContracts(context: Context, signal: AbortSignal): Promise<void> {
  const locationDirectory: string = context.location.directory;
  void locationDirectory;
  const sessionID = "session-id";
  const fallbackRequestID = "request-id";

  // Installed public list contract is session-scoped, not a location-wide overload.
  const listInput: Parameters<Context["permission"]["list"]>[0] = { sessionID };
  const listed = await context.permission.list(listInput);
  const requestID = listed[0]?.id ?? fallbackRequestID;

  // Installed public get contract returns the request directly. The Promise
  // signature does not declare a thrown-error type, so this fixture does not
  // infer one.
  const getInput: Parameters<Context["permission"]["get"]>[0] = { sessionID, requestID };
  const request = await context.permission.get(getInput);
  const action: string = request.action;
  const resources: readonly string[] = request.resources;
  void action;
  void resources;

  // The installed public Promise input names this field `decision`.
  const automaticReply: InternalPermissionReply = "once";
  const replyInput: Parameters<Context["permission"]["reply"]>[0] = {
    sessionID,
    requestID: request.id,
    decision: automaticReply,
  };
  const replyResult: void = await context.permission.reply(replyInput);
  void replyResult;

  // Reject uses the same decision field; `always` is never an automatic reply.
  const rejectInput: Parameters<Context["permission"]["reply"]>[0] = {
    sessionID,
    requestID: request.id,
    decision: "reject",
  };
  const rejectResult: void = await context.permission.reply(rejectInput);
  void rejectResult;

  // Authoritative session location verifies ownership before any reply.
  const session = await context.session.get({ sessionID });
  const sessionDirectory: string = session.location.directory;
  void sessionDirectory;

  // Local fallback intent reads only the public session context.
  const contextMessages = await context.session.context({ sessionID });
  void contextMessages;

  // Installed public event subscription is an async iterable of OpenCodeEvent.
  for await (const event of context.event.subscribe({ signal })) {
    const identity = readPermissionEvent(event);
    if (identity !== undefined) {
      const observedSession: string = identity.sessionID;
      const observedRequest: string = identity.requestID;
      void observedSession;
      void observedRequest;
    }
  }

  // Installed public prompt hook callback and disposable registration.
  const registration = await context.session.hook("prompt", async (input) => {
    const session: string = input.sessionID;
    const message: string = input.messageID;
    const promptText: string = input.prompt.text;
    void session;
    void message;
    void promptText;
  });
  await registration.dispose();
}

const sdkQuestion = choice("Choose the policy outcome.", {
  allow_once: "The request is safe for one use.",
  deny: "The request must be rejected.",
  manual_review: "A human must review the request.",
});

type SdkQuestions = Readonly<{
  policy_decision: typeof sdkQuestion;
}>;

const sdkRequest: SystemOneRequest<SdkQuestions> = {
  state: { policy: "closed" },
  questions: { policy_decision: sdkQuestion },
  model: "jev-latest",
};

const sdkConfig: TypeSafeClientConfig = {
  baseURL: "https://api.typesafe.ai",
  defaultModel: "jev-latest",
  logLevel: "off",
  timeout: 1000,
  retry: { maxRetries: 1 },
};

function verifySdkContract(client: TypeSafeClient, signal: AbortSignal) {
  const config: TypeSafeClientConfig = sdkConfig;
  void config;
  return client.systemOne(sdkRequest, {
    signal,
    retry: { maxRetries: 1 },
  });
}

void verifyOpenCodeContracts;
void verifySdkContract;

const pluginDefinition: PluginDefinition = {
  id: "opencode-jev-permissions",
  setup: async (_context): Promise<Cleanup> => async () => {
    // The real setup will register the verified contracts in Slice 5.
  },
};

export const compileOnlyPlugin = Plugin.define(pluginDefinition);
export default compileOnlyPlugin;

type IsAssignable<From, To> = [From] extends [To] ? true : false;
type Assert<T extends true> = T;

/** Compile-time lock: `always` is not an automatic reply. */
export type AlwaysIsNotAutomaticReply = Assert<
  IsAssignable<"always", AutomaticReply> extends false ? true : false
>;

/** Compile-time lock: `always` cannot widen the actual internal reply alias. */
export type AlwaysIsNotInternalPermissionReply = Assert<
  IsAssignable<"always", InternalPermissionReply> extends false ? true : false
>;
