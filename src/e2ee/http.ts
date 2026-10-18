// Raw HTTP for the E2EE paths: the typed `API` client throws the body of a failed
// response without its status, but the core needs the real status of every attempt
// (0 = no response), and the outbox needs 409/429 and `retry_after`.
import type { Client } from "../Client.js";

/** Status and raw body of one request; `retryAfterMs` from a 429 */
export interface RawResponse {
  status: number;
  body: string;
  retryAfterMs?: number;
}

/** Whether the status is a 2xx */
export const isSuccess = (status: number) => status >= 200 && status < 300;

/**
 * Run one request against the account's API with its session
 * @param client Client
 * @param method HTTP method
 * @param path Path relative to the API root (with its query)
 * @param body JSON body
 * @param headers Extra headers
 * @returns Status and body
 * @throws on a network error (no response)
 */
export async function rawRequest(
  client: Client,
  method: string,
  path: string,
  body?: string,
  headers: Record<string, string> = {},
): Promise<RawResponse> {
  const [authKey, authValue] = client.authenticationHeader;
  const upper = method.toUpperCase();
  const hasBody = body !== undefined && body !== "" && upper !== "GET";

  const response = await fetch(client.options.baseURL + path, {
    method: upper,
    headers: {
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
      [authKey]: authValue,
      ...headers,
    },
    body: hasBody ? body : undefined,
  });

  const text = response.status === 204 ? "" : await response.text();
  return {
    status: response.status,
    body: text,
    retryAfterMs:
      response.status === 429
        ? retryAfterMs(text, response.headers.get("Retry-After"))
        : undefined,
  };
}

/**
 * Stoat's limiter answers `{"retry_after": ms}`; a proxy may send `Retry-After: seconds`
 * @param body Response body
 * @param header Retry-After header
 * @returns Milliseconds to wait, if known
 */
export function retryAfterMs(
  body: string,
  header: string | null,
): number | undefined {
  try {
    const value = (JSON.parse(body) as { retry_after?: unknown }).retry_after;
    if (typeof value === "number" && value >= 0) return value;
  } catch {
    // not JSON
  }

  const seconds = Number(header?.trim());
  if (header && Number.isFinite(seconds) && seconds >= 0) return seconds * 1e3;
}

/**
 * The `type` of a Stoat error body, if any
 * @param body Response body
 */
export function errorType(body: string): string | undefined {
  try {
    const type = (JSON.parse(body) as { type?: unknown }).type;
    if (typeof type === "string") return type;
  } catch {
    // not JSON
  }
}
