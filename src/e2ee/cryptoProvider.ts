// `stoat.js/e2ee` — the `E2eeProvider` over `@durio/stoat-crypto` (CR-14; plan WEB-03,
// Q29). The SDK takes no dependency on the package: the app creates the worker and
// `StoatCrypto` (Vite has to see `new Worker(new URL(...))` in its own code) and passes
// it in; this adapter only needs its shape.
import type {
  E2eeChannelSettings,
  E2eeDecryptResult,
  E2eeDevice,
  E2eeEncryptedBlob,
  E2eeEncryptedBytes,
  E2eeIncomingMessage,
  E2eeOutgoingRequest,
  E2eeProvider,
  E2eeRequestKind,
  E2eeServerLimits,
  E2eeToDeviceResult,
} from "./provider.js";

export * from "./provider.js";

/** The part of `StoatCrypto` (`@durio/stoat-crypto`) the SDK uses */
export interface StoatCryptoLike {
  close(): Promise<void>;
  destroyStore(accountKey: string): Promise<void>;
  terminate(): void;
  setServerLimits(limits: E2eeServerLimits): Promise<void>;
  outgoingRequests(): Promise<E2eeOutgoingRequest[]>;
  markRequestSent(
    id: string,
    kind: E2eeRequestKind,
    body: string,
  ): Promise<void>;
  markRequestFailed(
    id: string,
    kind: E2eeRequestKind,
    status: number,
  ): Promise<void>;
  wakeupInMs(): Promise<number | null>;
  receiveToDevice(body: string): Promise<E2eeToDeviceResult>;
  markAckSent(ids: string[]): Promise<void>;
  receiveDeviceListUpdate(users: string[]): Promise<void>;
  receiveReconnect(): Promise<void>;
  receiveOtkCounts(body: string): Promise<void>;
  setChannelMembers(
    channelId: string,
    members: string[],
    settings?: E2eeChannelSettings,
  ): Promise<void>;
  prepareSend(channelId: string): Promise<E2eeOutgoingRequest[]>;
  encrypt(channelId: string, payloadJson: string): Promise<string>;
  decryptBatch(messages: E2eeIncomingMessage[]): Promise<E2eeDecryptResult[]>;
  devices(userId: string): Promise<E2eeDevice[]>;
  encryptBlob(blob: Blob): Promise<E2eeEncryptedBlob>;
  encryptAttachment(data: Uint8Array): Promise<E2eeEncryptedBytes>;
  decryptBlob(
    blob: Blob,
    fileJson: string,
    contentType?: string,
  ): Promise<Blob>;
}

/**
 * Wrap an opened `StoatCrypto` (one worker = one account) as the SDK's provider
 * @param crypto `StoatCrypto` after `open`
 * @param account User and device the machine was opened for; `accountKey` names the
 *   IndexedDB store deleted on sign-out (none for a memory store)
 * @returns Provider for `client.e2ee.install`
 */
export function createStoatCryptoProvider(
  crypto: StoatCryptoLike,
  account: { userId: string; deviceId: string; accountKey?: string },
): E2eeProvider {
  let terminated = false;
  const terminate = () => {
    if (terminated) return;
    terminated = true;
    crypto.terminate();
  };

  return {
    userId: account.userId,
    deviceId: account.deviceId,
    setServerLimits: (limits) => crypto.setServerLimits(limits),
    outgoingRequests: () => crypto.outgoingRequests(),
    markRequestSent: (id, kind, body) => crypto.markRequestSent(id, kind, body),
    markRequestFailed: (id, kind, status) =>
      crypto.markRequestFailed(id, kind, status),
    wakeupInMs: () => crypto.wakeupInMs(),
    receiveToDevice: (body) => crypto.receiveToDevice(body),
    markAckSent: (ids) => crypto.markAckSent(ids),
    receiveDeviceListUpdate: (users) => crypto.receiveDeviceListUpdate(users),
    receiveReconnect: () => crypto.receiveReconnect(),
    receiveOtkCounts: (body) => crypto.receiveOtkCounts(body),
    setChannelMembers: (channelId, members, settings) =>
      crypto.setChannelMembers(channelId, members, settings),
    prepareSend: (channelId) => crypto.prepareSend(channelId),
    encrypt: (channelId, payloadJson) => crypto.encrypt(channelId, payloadJson),
    decryptMany: (messages) =>
      messages.length ? crypto.decryptBatch(messages) : Promise.resolve([]),
    devices: (userId) => crypto.devices(userId),
    encryptBlob: (blob) => crypto.encryptBlob(blob),
    encryptAttachment: (data) => crypto.encryptAttachment(data),
    decryptBlob: (blob, fileJson, contentType) =>
      crypto.decryptBlob(blob, fileJson, contentType),

    async close() {
      if (terminated) return;
      try {
        await crypto.close();
      } finally {
        terminate();
      }
    },

    async destroy() {
      if (terminated) return;
      try {
        await crypto.close();
        if (account.accountKey) await crypto.destroyStore(account.accountKey);
      } finally {
        terminate();
      }
    },
  };
}
