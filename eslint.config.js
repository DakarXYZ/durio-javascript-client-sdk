import eslint from "@eslint/js";
import prettier from "eslint-plugin-prettier/recommended";
import solid from "eslint-plugin-solid/configs/typescript";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig([
  {
    languageOptions: {
      parserOptions: { tsconfigRootDir: import.meta.dirname },
    },
  },
  eslint.configs.recommended,
  tseslint.configs.recommended,
  solid,
  prettier,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          caughtErrors: "all",
          varsIgnorePattern: "^_",
          argsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    // dur.io: no plaintext or keys in the console, even in development (decision 6);
    // e2ee/log.ts is the one sanctioned logger (fixed texts and codes)
    files: ["src/e2ee/**"],
    rules: {
      "no-console": "error",
    },
  },
]);
