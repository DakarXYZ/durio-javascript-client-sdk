// The one place encrypted messages are turned into displayable ones (dur.io fork, plan
// WEB-05, Q25; Android's `MessageDecryptor`): realtime, history, single fetches, replies
// and pins all come through `MessageCollection.getOrCreate` / `MessageUpdate`.
//
// Hydration is synchronous: a message is stored at once with `e2ee.state = "pending"`
// (no text: the server's placeholder never reaches the UI), queued here, and a
// micro-batch (16 ms) goes to the core in one `decryptMany`; the results are written in
// one `batch` with `updateUnderlyingObject`. Before writing, the message must still be
// there with the same ciphertext (an edit that came meanwhile has its own turn).
//
// Messages waiting for their key are remembered by Megolm session and decrypted again
// when it arrives. Own messages are shown from `local` (the payload we encrypted, keyed
// by its ciphertext) without a round trip to the worker: the socket echo may come before
// the answer of the `POST`.
import { batch } from "solid-js";

import type { Metadata } from "stoat-api";
import { decodeTime } from "ulid";

import type { Client } from "../Client.js";
import { File } from "../classes/File.js";
import type { HydratedMessage } from "../hydration/message.js";

import { e2eeWarn } from "./log.js";
import {
  type E2eePayloadAttachment,
  mentionedUsers,
  parsePayload,
} from "./payload.js";
import type {
  E2eeDecryptResult,
  E2eeDecryptedMessage,
  E2eeIncomingMessage,
  E2eeProvider,
  E2eeVerification,
} from "./provider.js";

/** E2EE state of a message in the model (WEB-05) */
export type E2eeMessageState =
  /** Not decrypted yet */
  | "pending"
  | "ok"
  /** Waiting for its room key */
  | "missing_key"
  | "failed"
  /** Tampered with by the server: never shown as text */
  | "suspicious"
  /** A newer format: update the app */
  | "unsupported";

/** Why a message could not be decrypted */
export type E2eeFailureReason =
  | "withheld"
  | "broken"
  /** The key did not come within a few minutes (it may still) */
  | "missing_key"
  /** No crypto core: encryption is unavailable on this device */
  | "unavailable"
  /** Encryption is active in another window */
  | "locked";

export interface MessageE2ee {
  state: E2eeMessageState;
  reason?: E2eeFailureReason;
  /** Shield of a decrypted message */
  verification?: E2eeVerification;
  senderDevice?: string | null;
  sessionId?: string;
  /** When it started waiting for its key (ms) */
  since?: number;
}

/** Envelope v1 as it comes in a message */
export interface EncryptedEnvelope {
  v: number;
  algorithm: string;
  session_id: string;
  device_id: string;
  ciphertext: string;
}

/** Keys of a decrypted attachment (secret: memory only) */
export interface E2eeFileKeys {
  fileJson: string;
  contentType: string;
  thumbnail?: { id: string; fileJson: string; width: number; height: number };
}

const BATCH_MS = 16;
const MISSING_KEY_MS = 5 * 60_000;
const MISSING_KEY_CHECK_MS = 60_000;

const settled = (e2ee: MessageE2ee | undefined) =>
  !e2ee || e2ee.state !== "pending";

/**
 * Decryption queue of one client
 */
export class E2eeDecryptor {
  readonly #client: Client;
  readonly #provider: () => E2eeProvider | undefined;

  #queue = new Map<string, string>();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #chain: Promise<void> = Promise.resolve();
  #unavailable: E2eeFailureReason | undefined;

  // Megolm session id → messages waiting for its key; and store failures, retried on any key
  readonly #waiting = new Map<string, Set<string>>();
  readonly #retry = new Set<string>();
  #missingTimer: ReturnType<typeof setInterval> | undefined;

  // what an edit needs of the version shown: its edit_seq and attachments (with keys)
  readonly #payloads = new Map<
    string,
    { editSeq: number; attachments: E2eePayloadAttachment[] }
  >();
  readonly #fileKeys = new Map<string, E2eeFileKeys>();
  readonly #local = new Map<string, string>();
  readonly #waiters = new Map<string, Set<() => void>>();

  /**
   * Construct the decryption queue
   * @param client Client
   * @param provider Current crypto core, if any
   */
  constructor(client: Client, provider: () => E2eeProvider | undefined) {
    this.#client = client;
    this.#provider = provider;
  }

  /**
   * Queue a message for decryption
   * @param id Message id
   */
  queue(id: string): void {
    const message = this.#message(id);
    if (!message?.encrypted) return;
    this.#queue.set(id, message.encrypted.ciphertext);
    if (this.#timer === undefined)
      this.#timer = setTimeout(() => {
        this.#timer = undefined;
        this.#chain = this.#chain
          .then(() => this.#flush())
          .catch((e) =>
            e2eeWarn("decryption batch failed", (e as Error)?.name),
          );
      }, BATCH_MS);
  }

  /** Queue every encrypted message that is not shown yet (crypto core installed) */
  queueAll(): void {
    this.#unavailable = undefined;
    for (const id of this.#client.messages.keys()) {
      const message = this.#message(id);
      if (message?.encrypted && message.e2ee?.state !== "ok") this.queue(id);
    }
  }

  /**
   * New room keys: messages waiting for them (and store failures) are decrypted again
   * @param sessionIds Megolm sessions that arrived
   */
  onRoomKeys(sessionIds: string[]): void {
    const ids = new Set(this.#retry);
    this.#retry.clear();
    for (const session of sessionIds) {
      for (const id of this.#waiting.get(session) ?? []) ids.add(id);
      this.#waiting.delete(session);
    }

    for (const id of ids) this.queue(id);
  }

  /**
   * No crypto core (another window holds it, or none can be started): what is not
   * decrypted yet says why instead of waiting forever
   * @param reason Why
   */
  markUnavailable(reason: E2eeFailureReason): void {
    this.#unavailable = reason;
    batch(() => {
      for (const id of this.#client.messages.keys()) {
        const message = this.#message(id);
        if (
          message?.encrypted &&
          (!message.e2ee || message.e2ee.state === "pending")
        ) {
          this.#hide(id, { state: "failed", reason });
        }
      }
    });
  }

  /**
   * Show an own message from the payload we encrypted (the echo may beat the response)
   * @param ciphertext Envelope ciphertext
   * @param payloadJson Payload JSON
   */
  rememberLocal(ciphertext: string, payloadJson: string): void {
    this.#local.set(ciphertext, payloadJson);
  }

  /**
   * Payload parts an edit of this message needs (only once it is decrypted)
   * @param id Message id
   */
  payloadOf(id: string) {
    return this.#payloads.get(id);
  }

  /**
   * Keys of an attachment of a decrypted message
   * @param fileId autumn id
   */
  fileKeys(fileId: string): E2eeFileKeys | undefined {
    return this.#fileKeys.get(fileId);
  }

  /**
   * Resolves once the message is decrypted or known not to be (or after `timeoutMs`)
   * @param id Message id
   * @param timeoutMs Longest wait
   */
  whenDecrypted(id: string, timeoutMs = 10_000): Promise<void> {
    if (settled(this.#message(id)?.e2ee) && !this.#queue.has(id))
      return Promise.resolve();

    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.#waiters.get(id)?.delete(done);
        resolve();
      };

      const timer = setTimeout(done, timeoutMs);
      let set = this.#waiters.get(id);
      if (!set) this.#waiters.set(id, (set = new Set()));
      set.add(done);
    });
  }

  /** Forget everything (sign-out, account switch): keys and plaintext leave memory */
  clear(): void {
    clearTimeout(this.#timer);
    clearInterval(this.#missingTimer);
    this.#timer = undefined;
    this.#missingTimer = undefined;
    this.#queue.clear();
    this.#waiting.clear();
    this.#retry.clear();
    this.#payloads.clear();
    this.#fileKeys.clear();
    this.#local.clear();
    for (const set of this.#waiters.values()) for (const done of set) done();
    this.#waiters.clear();
  }

  #message(id: string): HydratedMessage | undefined {
    if (!this.#client.messages.has(id)) return;
    return this.#client.messages.getUnderlyingObject(id);
  }

  #settle(id: string) {
    for (const done of [...(this.#waiters.get(id) ?? [])]) done();
  }

  async #flush() {
    const entries = [...this.#queue];
    this.#queue.clear();

    const selfId = this.#client.user?.id;
    const incoming: E2eeIncomingMessage[] = [];
    const local: [string, string, E2eeDecryptResult][] = [];
    const remote: [string, string][] = [];

    for (const [id, ciphertext] of entries) {
      const message = this.#message(id);
      if (!message?.encrypted || message.encrypted.ciphertext !== ciphertext)
        continue;

      const payloadJson = this.#local.get(ciphertext);
      if (payloadJson !== undefined && message.authorId === selfId) {
        local.push([
          id,
          ciphertext,
          {
            type: "Decrypted",
            message: {
              payloadJson,
              senderUser: selfId!,
              senderDevice: this.#client.sessionId ?? null,
              verification: "Verified",
              sessionId: message.encrypted.session_id,
              messageIndex: -1,
              isReplay: false,
              staleEdit: false,
              editMismatch: false,
              replyMismatch: false,
              isClean: true,
            },
          },
        ]);
        continue;
      }

      remote.push([id, ciphertext]);
      incoming.push({
        messageId: id,
        channelId: message.channelId,
        author: message.authorId ?? "",
        envelopeJson: JSON.stringify(message.encrypted),
        replies: message.replyIds ?? [],
        timestamp: timestampOf(id),
      });
    }

    let results: E2eeDecryptResult[] = [];
    const provider = this.#provider();
    if (incoming.length) {
      if (!provider) {
        // no core yet: stays pending, `queueAll` runs once one is installed
        if (this.#unavailable) {
          const reason = this.#unavailable;
          batch(() => {
            for (const [id] of remote) {
              this.#hide(id, { state: "failed", reason });
              this.#settle(id);
            }
          });
        }
        remote.length = 0;
      } else {
        try {
          results = await provider.decryptMany(incoming);
        } catch (e) {
          e2eeWarn("decrypt failed", (e as { code?: string })?.code);
          results = incoming.map(() => ({
            type: "Failed",
            kind: "RetryLater",
            code: "Exception",
          }));
        }
      }
    }

    batch(() => {
      for (const [id, ciphertext, result] of local) {
        this.#local.delete(ciphertext);
        this.#apply(id, ciphertext, result);
      }

      remote.forEach(([id, ciphertext], i) => {
        if (results[i]) this.#apply(id, ciphertext, results[i]);
      });
    });
  }

  #apply(id: string, ciphertext: string, result: E2eeDecryptResult) {
    const message = this.#message(id);
    // deleted meanwhile, or edited: a newer decryption is queued
    if (!message?.encrypted || message.encrypted.ciphertext !== ciphertext)
      return;

    this.#forget(id);
    if (result.type === "Decrypted") {
      this.#decrypted(id, message, result.message);
    } else {
      switch (result.kind) {
        case "WaitingForKey": {
          const session = message.encrypted.session_id;
          let set = this.#waiting.get(session);
          if (!set) this.#waiting.set(session, (set = new Set()));
          set.add(id);
          this.#hide(id, {
            state: "missing_key",
            sessionId: session,
            since: Date.now(),
          });
          this.#watchMissing();
          break;
        }
        case "RetryLater":
          this.#retry.add(id);
          this.#hide(id, { state: "pending" });
          break;
        case "Withheld":
          this.#hide(id, { state: "failed", reason: "withheld" });
          break;
        case "UpdateApp":
          this.#hide(id, { state: "unsupported" });
          break;
        case "Suspicious":
          this.#hide(id, { state: "suspicious" });
          break;
        default:
          this.#hide(id, { state: "failed", reason: "broken" });
      }
    }

    this.#settle(id);
  }

  #decrypted(
    id: string,
    message: HydratedMessage,
    result: E2eeDecryptedMessage,
  ) {
    const onlyStale =
      result.staleEdit &&
      !result.isReplay &&
      !result.editMismatch &&
      !result.replyMismatch &&
      result.verification !== "Mismatch";

    // the server replayed an older version of an edit: keep what is shown
    if (onlyStale && message.e2ee?.state === "ok") return;
    if (!result.isClean) return this.#hide(id, { state: "suspicious" });

    const payload = parsePayload(result.payloadJson);
    if (!payload) return this.#hide(id, { state: "failed", reason: "broken" });

    const attachments = (payload.attachments ?? []).map((a) => {
      this.#fileKeys.set(a.id, {
        fileJson: JSON.stringify(a.file),
        contentType: a.content_type,
        thumbnail: a.thumbnail && {
          id: a.thumbnail.id,
          fileJson: JSON.stringify(a.thumbnail.file),
          width: a.thumbnail.width,
          height: a.thumbnail.height,
        },
      });

      return new File(this.#client, {
        _id: a.id,
        tag: "attachments",
        // upstream marks spoilers by the file name
        filename: a.spoiler ? `SPOILER_${a.name}` : a.name,
        metadata: a.metadata as Metadata,
        content_type: a.content_type,
        size: a.size,
        e2ee: true,
      });
    });

    this.#payloads.set(id, {
      editSeq: payload.edit_seq,
      attachments: payload.attachments ?? [],
    });

    const mentionIds = [
      ...new Set([
        ...(message.mentionIds ?? []),
        ...mentionedUsers(payload.content),
      ]),
    ];

    this.#client.messages.updateUnderlyingObject(id, {
      content: payload.content,
      attachments: attachments.length ? attachments : undefined,
      embeds: undefined,
      mentionIds: mentionIds.length ? mentionIds : undefined,
      e2ee: {
        state: "ok",
        verification: result.verification,
        senderDevice: result.senderDevice,
        sessionId: result.sessionId,
      },
    });

    this.#trackMention(id, message, mentionIds);
  }

  // "mentioned" is known only after decryption (C10): unread mentions are counted here
  #trackMention(id: string, message: HydratedMessage, mentionIds: string[]) {
    const self = this.#client.user?.id;
    if (!self || !mentionIds.includes(self) || message.authorId === self)
      return;
    if (!this.#client.options.syncUnreads) return;

    const channel = this.#client.channels.get(message.channelId);
    if (!channel) return;
    const unread = this.#client.channelUnreads.for(channel);
    if ((unread.lastMessageId ?? "0").localeCompare(id) === -1)
      unread.messageMentionIds.add(id);
  }

  #hide(id: string, e2ee: MessageE2ee) {
    this.#client.messages.updateUnderlyingObject(id, {
      content: undefined,
      attachments: undefined,
      embeds: undefined,
      e2ee,
    });
  }

  #forget(id: string) {
    for (const [session, set] of this.#waiting) {
      set.delete(id);
      if (!set.size) this.#waiting.delete(session);
    }

    this.#retry.delete(id);
  }

  // after a few minutes without the key: "could not decrypt" (it is still decrypted
  // when the key comes later)
  #watchMissing() {
    if (this.#missingTimer !== undefined) return;
    this.#missingTimer = setInterval(() => {
      const now = Date.now();
      let waiting = false;
      batch(() => {
        for (const set of this.#waiting.values()) {
          for (const id of set) {
            const e2ee = this.#message(id)?.e2ee;
            if (e2ee?.state !== "missing_key") continue;
            if (now - (e2ee.since ?? now) < MISSING_KEY_MS) {
              waiting = true;
              continue;
            }

            this.#client.messages.updateUnderlyingObject(id, "e2ee", {
              ...e2ee,
              state: "failed",
              reason: "missing_key",
            });
          }
        }
      });

      if (!waiting) {
        clearInterval(this.#missingTimer);
        this.#missingTimer = undefined;
      }
    }, MISSING_KEY_CHECK_MS);
  }
}

/**
 * Timestamp of a message id
 * @param id ULID
 */
function timestampOf(id: string) {
  try {
    return decodeTime(id);
  } catch {
    return 0;
  }
}
