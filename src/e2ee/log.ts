// The only console output of the E2EE code (50-web-sdk decision 6): a fixed text and a
// code or status — never plaintext, keys, payloads, bodies or ids of other users.
// `console` is forbidden elsewhere in src/e2ee by the lint config.

/**
 * Warn about an E2EE problem
 * @param what Fixed description
 * @param code Error code, class name or HTTP status
 */
export function e2eeWarn(what: string, code?: string | number): void {
  // eslint-disable-next-line no-console
  console.warn(`[e2ee] ${what}${code === undefined ? "" : `: ${code}`}`);
}
