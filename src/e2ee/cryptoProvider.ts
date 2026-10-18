// `stoat.js/e2ee` — the `E2eeProvider` over `@durio/stoat-crypto` (CR-14; plan WEB-03,
// Q29). The SDK takes no dependency on the package: the app creates the worker and
// `StoatCrypto` (Vite has to see `new Worker(new URL(...))` in its own code) and passes
// it in; this adapter only needs its shape.
import {
  type E2eeBackupRestore,
  type E2eeBackupStatus,
  type E2eeChannelSettings,
  type E2eeDecryptResult,
  type E2eeDevice,
  type E2eeEncryptedBlob,
  type E2eeEncryptedBytes,
  E2eeError,
  type E2eeIdentityKeys,
  type E2eeIncomingMessage,
  type E2eeKeyExport,
  type E2eeKeyImportResult,
  type E2eeOutgoingRequest,
  type E2eeProvider,
  type E2eeRecoveryKeyCheck,
  type E2eeRecoverySecrets,
  type E2eeRecoverySetup,
  type E2eeRequestKind,
  type E2eeSasEmoji,
  type E2eeSasFlow,
  type E2eeServerLimits,
  type E2eeSettableTrust,
  type E2eeToDeviceResult,
  type E2eeUndeliveredDevice,
  e2eeErrorCode,
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
  setDeviceTrust(
    userId: string,
    deviceId: string,
    trust: E2eeSettableTrust,
  ): Promise<void>;
  identityKeys(): Promise<E2eeIdentityKeys>;
  undeliveredDevices(): Promise<E2eeUndeliveredDevice[]>;
  requestVerification(userId: string, deviceId: string): Promise<E2eeSasFlow>;
  verification(flowId: string): Promise<E2eeSasFlow | null>;
  verifications(): Promise<E2eeSasFlow[]>;
  sasEmojiTable(): Promise<E2eeSasEmoji[]>;
  createRecovery(passphrase?: Uint8Array): Promise<E2eeRecoverySetup>;
  rotateBackup(): Promise<E2eeRecoverySetup>;
  unlockBackup(
    input: Uint8Array,
    secrets: E2eeRecoverySecrets,
  ): Promise<string>;
  restoreBackup(keysBody: string): Promise<E2eeBackupRestore>;
  backupStatus(): Promise<E2eeBackupStatus>;
  disableBackup(): Promise<void>;
  recoveryKeyCheck(input: Uint8Array): Promise<E2eeRecoveryKeyCheck>;
  exportRoomKeys(
    passphrase: Uint8Array,
    channelIds?: string[],
  ): Promise<E2eeKeyExport>;
  importRoomKeys(
    file: string,
    passphrase: Uint8Array,
  ): Promise<E2eeKeyImportResult>;
  debugReport(): Promise<string>;
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
    setDeviceTrust(userId, deviceId, trust) {
      // `Verified` comes from SAS only (review O-3), whatever the caller typed
      if (trust !== "Unverified" && trust !== "Blocked")
        return Promise.reject(
          new E2eeError("InvalidInput", "trust is set by verification only"),
        );
      return crypto.setDeviceTrust(userId, deviceId, trust);
    },
    identityKeys: () => crypto.identityKeys(),
    undeliveredDevices: () => crypto.undeliveredDevices(),
    requestVerification: (userId, deviceId) =>
      crypto.requestVerification(userId, deviceId),
    verification: (flowId) => crypto.verification(flowId),
    verifications: () => crypto.verifications(),
    sasEmojiTable: () => crypto.sasEmojiTable(),
    createRecovery: (passphrase) => crypto.createRecovery(passphrase),
    rotateBackup: () => crypto.rotateBackup(),
    unlockBackup: (input, secrets) => crypto.unlockBackup(input, secrets),
    restoreBackup: (body) => crypto.restoreBackup(body),
    backupStatus: () => crypto.backupStatus(),
    disableBackup: () => crypto.disableBackup(),
    recoveryKeyCheck: (input) => crypto.recoveryKeyCheck(input),
    exportRoomKeys: (passphrase, channelIds) =>
      crypto.exportRoomKeys(passphrase, channelIds),
    importRoomKeys: (file, passphrase) =>
      crypto.importRoomKeys(file, passphrase),
    debugReport: () => crypto.debugReport(),
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
        const accountKey = account.accountKey;
        if (accountKey)
          await retryWhileLocked(() => crypto.destroyStore(accountKey));
      } finally {
        terminate();
      }
    },
  };
}

/** Delays between attempts of a store deletion that was blocked (WEB-12) */
export const DESTROY_RETRY_MS = [100, 400, 1_500];

/**
 * Run a store deletion again while it is blocked: `indexedDB.deleteDatabase` waits
 * for connections still open (a machine being closed, another window letting go),
 * and the worker reports that as `StoreLocked`
 * @param destroy Deletion
 * @param delays Waits between attempts
 */
export async function retryWhileLocked(
  destroy: () => Promise<void>,
  delays: readonly number[] = DESTROY_RETRY_MS,
): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await destroy();
    } catch (e) {
      if (e2eeErrorCode(e) !== "StoreLocked" || attempt >= delays.length)
        throw e;
      await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
    }
  }
}
