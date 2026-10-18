import { defineConfig } from "vitest/config";

export default defineConfig({
  // Solid's browser build: the server build has no reactive stores
  resolve: { conditions: ["browser"] },
  test: {
    environment: "node",
    include: ["src/**/__tests__/*.test.ts"],
  },
});
