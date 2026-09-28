delete process.env.TYPESAFE_API_KEY;

globalThis.fetch = (() => {
  throw new Error("Network access is disabled in tests");
}) as typeof fetch;
