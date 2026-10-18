// Test doubles for the E2EE flows (plan WEB-08): a fake crypto core whose "encryption"
// is base64(JSON) and a fake server behind `fetch`. No wasm, no worker.
import type { RevoltConfig } from "stoat-api";
import { ulid } from "ulid";
import { vi } from "vitest";

import { Client } from "../../Client.js";
import { handleEvent } from "../../events/v1.js";
import type {
  E2eeDecryptResult,
  E2eeDevice,
  E2eeIncomingMessage,
  E2eeOutgoingRequest,
  E2eeProvider,
  E2eeRecoverySecrets,
  E2eeRequestKind,
  E2eeRoomKey,
  E2eeSasFlow,
  E2eeSasState,
  E2eeSettableTrust,
  E2eeToDeviceResult,
} from "../provider.js";

export const SELF = ulid();
export const OTHER = ulid();
export const THIRD = ulid();
export const SESSION = ulid();
export const API = "https://api.test";
export const AUTUMN = "https://files.test";

export const b64 = (text: string) => Buffer.from(text).toString("base64");
export const unb64 = (text: string) =>
  Buffer.from(text, "base64").toString("utf8");

/** An error of the core */
export const coreError = (code: string) =>
  Object.assign(new Error(code), { name: "StoatCryptoError", code });

/**
 * Fake crypto core: requests are scripted, "ciphertext" is base64 of
 * `{channelId, payload}`, sessions listed in `missing` wait for their key.
 */
export class FakeProvider implements E2eeProvider {
  readonly userId = SELF;
  readonly deviceId = SESSION;

  calls: string[] = [];
  outgoing: E2eeOutgoingRequest[] = [];
  prepare: E2eeOutgoingRequest[] = [];
  sent: { id: string; kind: E2eeRequestKind; body: string }[] = [];
  failed: { id: string; kind: E2eeRequestKind; status: number }[] = [];
  /** Code `markRequestFailed` throws for a request id */
  failThrows: Record<string, string> = {};
  acked: string[] = [];
  members = new Map<string, string[]>();
  devicesOf: Record<string, E2eeDevice[]> = {};
  notSharedOnce = 0;
  encrypted: string[] = [];
  missing = new Set<string>();
  suspicious = new Set<string>();
  decryptCalls = 0;
  session = "S1";
  closed = false;
  destroyed = false;

  async setServerLimits() {
    this.calls.push("setServerLimits");
  }

  async outgoingRequests() {
    return [...this.outgoing];
  }

  async markRequestSent(id: string, kind: E2eeRequestKind, body: string) {
    this.sent.push({ id, kind, body });
    this.outgoing = this.outgoing.filter((r) => r.id !== id);
    this.prepare = this.prepare.filter((r) => r.id !== id);
  }

  async markRequestFailed(id: string, kind: E2eeRequestKind, status: number) {
    this.failed.push({ id, kind, status });
    const code = this.failThrows[id];
    if (code) {
      delete this.failThrows[id];
      this.outgoing = this.outgoing.filter((r) => r.id !== id);
      throw coreError(code);
    }
  }

  async wakeupInMs() {
    return null;
  }

  async receiveToDevice(body: string): Promise<E2eeToDeviceResult> {
    this.calls.push("receiveToDevice");
    const { messages } = JSON.parse(body) as {
      messages: { id: string; type: string; content: Record<string, string> }[];
    };

    return {
      fetched: messages.length,
      ackIds: messages.map((m) => m.id),
      roomKeys: messages
        .filter((m) => m.type === "m.room_key")
        .map((m) => {
          this.missing.delete(m.content.session);
          return { channelId: m.content.channel, sessionId: m.content.session };
        }),
      verifications: [],
    };
  }

  async markAckSent(ids: string[]) {
    this.acked.push(...ids);
  }

  async receiveDeviceListUpdate(users: string[]) {
    this.calls.push(`deviceList:${users.join(",")}`);
  }

  async receiveReconnect() {
    this.calls.push("receiveReconnect");
  }

  async receiveOtkCounts() {
    this.calls.push("receiveOtkCounts");
  }

  async setChannelMembers(channelId: string, members: string[]) {
    this.members.set(channelId, members);
  }

  async prepareSend() {
    return [...this.prepare];
  }

  async encrypt(channelId: string, payloadJson: string) {
    if (!this.members.has(channelId)) throw coreError("UnknownChannel");
    if (this.notSharedOnce > 0) {
      this.notSharedOnce--;
      throw coreError("RoomKeyNotShared");
    }

    this.encrypted.push(payloadJson);
    return JSON.stringify({
      v: 1,
      algorithm: "m.megolm.v1.aes-sha2",
      session_id: this.session,
      device_id: SESSION,
      ciphertext: b64(
        JSON.stringify({ channelId, payload: payloadJson, n: ulid() }),
      ),
      // the library also emits this; it must not reach the server
      sender_key: "curve",
    });
  }

  async decryptMany(
    messages: E2eeIncomingMessage[],
  ): Promise<E2eeDecryptResult[]> {
    this.decryptCalls++;
    return messages.map((m) => {
      const envelope = JSON.parse(m.envelopeJson) as {
        session_id: string;
        ciphertext: string;
      };

      if (this.missing.has(envelope.session_id))
        return {
          type: "Failed",
          kind: "WaitingForKey",
          code: "MissingRoomKey",
        };

      const inner = JSON.parse(unb64(envelope.ciphertext)) as {
        channelId: string;
        payload: string;
      };

      const clean =
        inner.channelId === m.channelId && !this.suspicious.has(m.messageId);
      return {
        type: "Decrypted",
        message: {
          payloadJson: inner.payload,
          senderUser: m.author,
          senderDevice: "DEV",
          verification: "Unverified",
          sessionId: envelope.session_id,
          messageIndex: 0,
          isReplay: false,
          staleEdit: false,
          editMismatch: false,
          replyMismatch: false,
          isClean: clean,
        },
      };
    });
  }

  async devices(userId: string) {
    return (
      this.devicesOf[userId] ?? [
        {
          userId,
          deviceId: "D",
          ed25519: "k",
          trust: "Unverified" as const,
          deleted: false,
        },
      ]
    );
  }

  // ------------------------------------------------- devices, SAS, backup

  trustCalls: string[] = [];
  flows = new Map<string, FakeSasFlow>();
  /** Secrets as the core saw them (copies, before the caller wiped its own) */
  secretsSeen: string[] = [];
  backup = {
    enabled: false,
    version: null as string | null,
    created: 0,
    restoreBatches: 2,
  };
  /** Code `importRoomKeys` / `unlockBackup` throw */
  importThrows?: string;
  unlockThrows?: string;
  importedKeys: E2eeRoomKey[] = [];

  async setDeviceTrust(
    userId: string,
    deviceId: string,
    trust: E2eeSettableTrust,
  ) {
    this.trustCalls.push(`${userId}/${deviceId}:${trust}`);
  }

  async identityKeys() {
    return {
      curve25519: "curve",
      ed25519: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
    };
  }

  async undeliveredDevices() {
    return [];
  }

  async requestVerification(userId: string, deviceId: string) {
    const flow = new FakeSasFlow(`F${this.flows.size + 1}`, userId, deviceId);
    this.flows.set(flow.flowId, flow);
    return flow;
  }

  async verification(flowId: string) {
    return this.flows.get(flowId) ?? null;
  }

  async verifications() {
    return [...this.flows.values()];
  }

  async sasEmojiTable() {
    return Array.from({ length: 64 }, (_, index) => ({
      index,
      symbol: String.fromCodePoint(0x1f400 + index),
      description: `E${index}`,
    }));
  }

  #request(kind: E2eeRequestKind): E2eeOutgoingRequest {
    this.backup.created++;
    return {
      id: `b${this.backup.created}`,
      kind,
      method: "POST",
      path: "/e2ee/backup/version",
      body: '{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2"}',
    };
  }

  async createRecovery(passphrase?: Uint8Array) {
    if (passphrase) this.secretsSeen.push(new TextDecoder().decode(passphrase));
    return {
      recoveryKey: "EsTc 1234 abcd",
      request: this.#request("BackupVersionCreate"),
    };
  }

  async rotateBackup() {
    return { recoveryKey: null, request: this.#request("BackupVersionCreate") };
  }

  async unlockBackup(input: Uint8Array, secrets: E2eeRecoverySecrets) {
    this.secretsSeen.push(new TextDecoder().decode(input));
    this.calls.push(`unlock:${secrets.defaultKey}|${secrets.backupVersion}`);
    if (this.unlockThrows) throw coreError(this.unlockThrows);
    return "7";
  }

  async restoreBackup(body: string) {
    this.calls.push(`restore:${body}`);
    let done = 0;
    const total = this.backup.restoreBatches;
    const progress = () => ({
      done,
      total,
      imported: done,
      failed: 0,
      finished: done >= total,
    });
    return {
      progress: async () => progress(),
      next: async () => {
        done++;
        return progress();
      },
      free: async () => {
        this.calls.push("restore:free");
      },
    };
  }

  async backupStatus() {
    return {
      version: this.backup.version,
      enabled: this.backup.enabled,
      recoverySetUp: this.backup.enabled,
      outdated: false,
      keysTotal: 3,
      keysBackedUp: this.backup.enabled ? 3 : 0,
    };
  }

  async disableBackup() {
    this.backup.enabled = false;
  }

  async recoveryKeyCheck(input: Uint8Array) {
    const text = new TextDecoder().decode(input);
    this.secretsSeen.push(text);
    return text.startsWith("EsT") ? ("Valid" as const) : ("NotAKey" as const);
  }

  async exportRoomKeys(passphrase: Uint8Array, channelIds: string[] = []) {
    this.secretsSeen.push(new TextDecoder().decode(passphrase));
    return {
      data: `-----BEGIN MEGOLM SESSION DATA-----${channelIds.join(",")}`,
      sessions: 2,
    };
  }

  async importRoomKeys(file: string, passphrase: Uint8Array) {
    this.secretsSeen.push(new TextDecoder().decode(passphrase));
    if (this.importThrows) throw coreError(this.importThrows);
    for (const key of this.importedKeys) this.missing.delete(key.sessionId);
    return {
      total: this.importedKeys.length + 1,
      imported: this.importedKeys.length,
      skipped: file.includes("matrix") ? 1 : 0,
      roomKeys: this.importedKeys,
    };
  }

  async debugReport() {
    return '{"core_version":"0.2.0"}';
  }

  async encryptBlob(blob: Blob) {
    return { blob, fileJson: '{"v":"v2"}', size: blob.size };
  }

  async encryptAttachment(data: Uint8Array) {
    return { ciphertext: data, fileJson: '{"v":"v2"}' };
  }

  async decryptBlob(blob: Blob, _fileJson: string, contentType?: string) {
    return new Blob([await blob.arrayBuffer()], { type: contentType });
  }

  async close() {
    this.closed = true;
  }

  async destroy() {
    this.destroyed = true;
  }
}

/** A SAS flow driven by the test: `state` is set from outside */
export class FakeSasFlow implements E2eeSasFlow {
  readonly isSelfVerification: boolean;
  current: E2eeSasState = { type: "Requested" };
  actions: string[] = [];
  freed = false;

  constructor(
    readonly flowId: string,
    readonly otherUserId: string,
    readonly device: string,
  ) {
    this.isSelfVerification = otherUserId === SELF;
  }

  async state() {
    return this.current;
  }

  async otherDeviceId() {
    return this.device;
  }

  async accept() {
    this.actions.push("accept");
    this.current = { type: "Ready" };
  }

  async start() {
    this.actions.push("start");
    this.current = { type: "Started" };
  }

  async confirm() {
    this.actions.push("confirm");
    this.current = { type: "Confirmed" };
  }

  async mismatch() {
    this.actions.push("mismatch");
    this.current = {
      type: "Cancelled",
      reason: "Mismatch",
      code: "m.mismatched_sas",
      byUs: true,
    };
  }

  async cancel() {
    this.actions.push("cancel");
    this.current = {
      type: "Cancelled",
      reason: "User",
      code: "m.user",
      byUs: true,
    };
  }

  async free() {
    this.freed = true;
  }
}

/** Envelope the fake core would produce for a payload */
export function fakeEnvelope(
  channelId: string,
  payload: object,
  session = "S1",
) {
  return {
    v: 1,
    algorithm: "m.megolm.v1.aes-sha2",
    session_id: session,
    device_id: "DEV",
    ciphertext: b64(
      JSON.stringify({
        channelId,
        payload: JSON.stringify(payload),
        n: ulid(),
      }),
    ),
  };
}

export interface FakeRequest {
  method: string;
  url: string;
  path: string;
  body?: string;
  headers: Record<string, string>;
}

export type FakeRoute = (
  request: FakeRequest,
) =>
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | "network"
  | undefined;

/**
 * Replace `fetch` with a scripted server
 * @param route Answers a request; undefined → 404
 */
export function fakeServer(route: FakeRoute) {
  const requests: FakeRequest[] = [];
  vi.stubGlobal(
    "fetch",
    async (input: string | URL, init: RequestInit = {}) => {
      const url = input.toString();
      const request: FakeRequest = {
        method: (init.method ?? "GET").toUpperCase(),
        url,
        path: url.startsWith(API) ? url.slice(API.length) : url,
        body: init.body as string | undefined,
        headers: (init.headers ?? {}) as Record<string, string>,
      };
      requests.push(request);

      const answer = route(request);
      if (answer === "network") throw new TypeError("Failed to fetch");
      const status = answer?.status ?? 404;
      const body =
        answer?.body === undefined
          ? ""
          : answer.body instanceof Blob || typeof answer.body === "string"
            ? answer.body
            : JSON.stringify(answer.body);
      return new Response(status === 204 ? null : body, {
        status,
        headers: answer?.headers,
      });
    },
  );

  return requests;
}

/** A configured client with a session and its own user */
export function makeClient(options: { syncUnreads?: boolean } = {}) {
  const config = {
    stoat: "0.16.0",
    revolt: "0.16.0",
    ws: "wss://events.test",
    app: "https://app.test",
    vapid: "",
    features: {
      autumn: { enabled: true, url: AUTUMN },
      january: { enabled: false, url: "" },
      e2ee: {
        enabled: true,
        envelope_versions: [1],
        max_envelope_bytes: 16384,
        default_for_new_dms: false,
        max_to_device_batch: 1000,
        max_to_device_bytes: 65536,
        max_attachments: 10,
        max_request_bytes: 4194304,
      },
    },
  } as unknown as RevoltConfig;

  const client = new Client(
    { baseURL: API, syncUnreads: options.syncUnreads ?? false },
    config,
  );
  client.useExistingSession({ _id: SESSION, token: "token", user_id: SELF });
  client.user = client.users.getOrCreate(SELF, {
    _id: SELF,
    username: "me",
    discriminator: "0001",
    relationship: "User",
    online: true,
  } as never);
  client.users.getOrCreate(OTHER, {
    _id: OTHER,
    username: "other",
    discriminator: "0002",
    relationship: "Friend",
    online: true,
  } as never);
  return client;
}

/** Feed a socket event to the client */
export const emit = (client: Client, event: object) =>
  handleEvent(client, event as never, () => {});

export const encryption = {
  algorithm: "m.megolm.v1.aes-sha2",
  enabled_at: "2026-10-18T00:00:00Z",
  enabled_by: OTHER,
};

/** An encrypted DM between SELF and OTHER */
export function encryptedDm(client: Client, id = ulid(), encrypted = true) {
  return client.channels.getOrCreate(id, {
    _id: id,
    channel_type: "DirectMessage",
    active: true,
    recipients: [SELF, OTHER],
    ...(encrypted ? { encryption } : {}),
  } as never);
}

/** Let the 16 ms decryption batch and promise chains run */
export async function settle(ms = 40) {
  await vi.advanceTimersByTimeAsync(ms);
}
