// The outbox of every new message, plain and encrypted (dur.io fork, block 5E of the
// Android plan, `stoat-crypto/docs/load-chaos.md` B2): one body, one `nonce`, sent again
// as is.
//
// - The `Idempotency-Key` header is the nonce. The server answers a repeat of either
//   from the same author in the same channel with the message the first attempt stored,
//   so a lost answer does not make a second message. An encrypted body keeps its
//   envelope: it is encrypted once, a retry never spends another Megolm index.
// - Network errors, 5xx and 429 are retried (`SendRetry`).
// - `400 InvalidOperation` / `409` after a retry (racing the first attempt, or the
//   server's nonce cache lost in a restart) mean "probably sent": the channel's latest
//   messages are read and the message is found by its nonce. So are retries that ran
//   out. Only a message not found is an error.
import type { Message as APIMessage } from "stoat-api";

import type { Client } from "../Client.js";

import { type RawResponse, errorType, isSuccess, rawRequest } from "./http.js";
import { e2eeWarn } from "./log.js";
import { E2eeError } from "./provider.js";

/** How many latest messages are searched for the nonce */
export const LOOKUP_LIMIT = 50;

/** Retries of one send: the pause doubling from `initialDelayMs` up to `maxDelayMs` */
export interface SendRetry {
  retries: number;
  initialDelayMs: number;
  maxDelayMs: number;
  /** Up to a quarter of jitter, so clients do not come back together */
  jitter: boolean;
  /** Pauses before each nonce lookup: the first attempt may still be on its way */
  lookupDelaysMs: number[];
  /** Longest wait a 429 may ask for */
  maxRateLimitWaitMs: number;
}

export const DEFAULT_SEND_RETRY: SendRetry = {
  retries: 5,
  initialDelayMs: 1_000,
  maxDelayMs: 16_000,
  jitter: true,
  lookupDelaysMs: [0, 2_000, 4_000],
  maxRateLimitWaitMs: 60_000,
};

/** The server refused a send for good, or it still failed after every retry */
export class MessageSendError extends E2eeError {
  readonly status: number;
  readonly type?: string;
  /** The server's error body (no message content) */
  readonly body: string;

  /**
   * Construct error
   * @param status HTTP status (0: no response)
   * @param type Stoat error type
   * @param body Error body
   */
  constructor(status: number, type: string | undefined, body: string) {
    super("MessageSendFailed", `message send failed: ${type ?? status}`);
    this.status = status;
    this.type = type;
    this.body = body;
  }
}

/** What a send ended with; `recovered`: through a retry or found by its nonce */
export interface SentMessage {
  message: APIMessage;
  recovered: boolean;
}

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

function delayMs(retry: SendRetry, attempt: number) {
  const base = Math.min(
    retry.initialDelayMs * 2 ** Math.max(attempt - 1, 0),
    retry.maxDelayMs,
  );
  return retry.jitter && base >= 4
    ? base + Math.floor(Math.random() * (base / 4))
    : base;
}

const isDuplicate = (e: MessageSendError) =>
  e.status === 409 || (e.status === 400 && e.type === "InvalidOperation");

/**
 * `POST /channels/{id}/messages` with a body that never changes between attempts
 * @param client Client
 * @param channelId Channel
 * @param body Request body (with `nonce`)
 * @param options Nonce, idempotency key, own user id for the lookup, retries
 * @returns The stored message
 * @throws MessageSendError refused, or a server error after every retry, and not found
 */
export async function sendWithRetry(
  client: Client,
  channelId: string,
  body: object,
  options: {
    nonce: string;
    idempotencyKey?: string;
    /** An earlier run already sent this nonce: a duplicate answer is "probably sent" */
    resend?: boolean;
    selfId?: string;
    retry?: SendRetry;
  },
): Promise<SentMessage> {
  const retry = options.retry ?? DEFAULT_SEND_RETRY;
  const json = JSON.stringify(body);
  const path = `/channels/${channelId}/messages`;

  let attempt = 0;
  let failure: MessageSendError;
  for (;;) {
    let waitMs: number | undefined;
    let response: RawResponse | undefined;

    try {
      response = await rawRequest(client, "POST", path, json, {
        "Idempotency-Key": options.idempotencyKey ?? options.nonce,
      });
    } catch (e) {
      e2eeWarn("send attempt failed", (e as Error)?.name);
      failure = new MessageSendError(0, undefined, "");
    }

    if (response) {
      if (isSuccess(response.status)) {
        return {
          message: JSON.parse(response.body) as APIMessage,
          recovered: attempt > 0,
        };
      }

      failure = new MessageSendError(
        response.status,
        errorType(response.body),
        response.body,
      );

      if (response.status === 429) {
        waitMs =
          response.retryAfterMs === undefined
            ? undefined
            : Math.min(response.retryAfterMs, retry.maxRateLimitWaitMs);
      } else if (response.status < 500) {
        if (isDuplicate(failure) && (attempt > 0 || options.resend)) {
          const found = await lookupByNonce(client, channelId, options, retry);
          if (found) return found;
        }

        throw failure;
      }
    }

    if (attempt >= retry.retries) break;
    attempt++;
    await sleep(waitMs ?? delayMs(retry, attempt));
  }

  // out of retries: an attempt may still have reached the server
  if (attempt > 0 || options.resend) {
    const found = await lookupByNonce(client, channelId, options, retry);
    if (found) return found;
  }

  throw failure!;
}

/**
 * The message with this nonce among the channel's latest, or undefined
 * @param client Client
 * @param channelId Channel
 * @param options Nonce and own user id
 * @param retry Lookup delays
 */
export async function lookupByNonce(
  client: Client,
  channelId: string,
  options: { nonce: string; selfId?: string },
  retry: SendRetry = DEFAULT_SEND_RETRY,
): Promise<SentMessage | undefined> {
  for (const pause of retry.lookupDelaysMs) {
    if (pause > 0) await sleep(pause);

    let latest: APIMessage[];
    try {
      const response = await rawRequest(
        client,
        "GET",
        `/channels/${channelId}/messages?limit=${LOOKUP_LIMIT}&include_users=false`,
      );
      if (!isSuccess(response.status)) continue;
      latest = JSON.parse(response.body) as APIMessage[];
    } catch (e) {
      e2eeWarn("send lookup failed", (e as Error)?.name);
      continue;
    }

    const found = latest.find(
      (m) =>
        m.nonce === options.nonce &&
        (!options.selfId || m.author === options.selfId),
    );

    if (found) return { message: found, recovered: true };
  }

  e2eeWarn("sent message not found by its nonce");
}
