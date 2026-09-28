import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["./test/setup.ts"],
    include: ["test/**/*.test.ts"],
    passWithNoTests: false,
    restoreMocks: true,
    clearMocks: true,
  },
});
