// The crypto core of one account as the SDK sees it (dur.io fork, plan WEB-03, Q29).
//
// The SDK never loads the wasm: the client hands it an implementation of this
// interface — over `@durio/stoat-crypto` (a dedicated Web Worker per account) through
// the `stoat.js/e2ee` entry, or a fake in tests. Shapes are those of
// `@durio/stoat-crypto` (camelCase records of the Android FFI); bodies, payloads,
// envelopes and `EncryptedFile`s are JSON strings.
//
// The core does no HTTP and has no timers: `E2eeSync` (requests.ts) runs its requests,
// following the host contract in `stoat-crypto/crates/stoat-crypto/src/lib.rs`.
//
// Never log a `E2eeDecryptResult`, a payload, `fileJson` or anything from a blob.

/** `GET /` → `features.e2ee` limits the core needs */
export interface E2eeServerLimits {
  maxToDeviceBatch: number;
  maxRequestBytes: number;
}

export type E2eeRequestKind =
  | "KeysUpload"
  | "KeysQuery"
  | "KeysClaim"
  | "ToDevice"
  | "BackupVersionCreate"
  | "BackupKeys"
  | "SecretPut";

/**
 * One HTTP request of the core: `method` `path` (relative to the API root, with its
 * query) and the JSON `body`. `id` stays the same in every retry; mark each attempt
 * exactly once (`markRequestSent` / `markRequestFailed`).
 */
export interface E2eeOutgoingRequest {
  id: string;
  kind: E2eeRequestKind;
  method: string;
  path: string;
  body: string;
}

/** A Megolm session arrived: messages of `channelId` waiting for it can be decrypted */
export interface E2eeRoomKey {
  channelId: string;
  sessionId: string;
}

/** What one mailbox page did; keys and plaintext never leave the core */
export interface E2eeToDeviceResult {
  /** Messages in the page: fetch again while it equals the limit */
  fetched: number;
  /** For `POST /e2ee/to_device/ack` (≤ 100 per call), then `markAckSent` */
  ackIds: string[];
  roomKeys: E2eeRoomKey[];
  /** Verification flows that changed (WEB-07) */
  verifications: string[];
}

/** From `Channel.encryption`; absent = library defaults (1 week / 100 messages) */
export interface E2eeChannelSettings {
  rotationPeriodMs?: number | null;
  rotationPeriodMsgs?: number | null;
}

/** An encrypted message as the server sent it; author and replies are its open claims */
export interface E2eeIncomingMessage {
  messageId: string;
  channelId: string;
  author: string;
  /** The message's `encrypted` object as JSON */
  envelopeJson: string;
  replies: string[];
  /** Milliseconds */
  timestamp: number;
}

/** Shield of a decrypted message: who is proven to have sent it */
export type E2eeVerification =
  | "Verified"
  | "Unverified"
  | "UnknownDevice"
  /** Key from the backup or forwarded: the author is not proven */
  | "Unauthenticated"
  | "Mismatch";

/** A decrypted message: `payloadJson` is plaintext, never log it */
export interface E2eeDecryptedMessage {
  /** Payload v1 JSON (without padding) */
  payloadJson: string;
  senderUser: string;
  senderDevice: string | null;
  verification: E2eeVerification;
  sessionId: string;
  messageIndex: number;
  /** Same (session, index) seen under another message id (CR-19) */
  isReplay: boolean;
  /** An older version of an edit than one already seen */
  staleEdit: boolean;
  /** `edit_of` does not name this message */
  editMismatch: boolean;
  /** `in_reply_to` differs from the open `replies` */
  replyMismatch: boolean;
  /** Nothing suspicious (the shield still applies) */
  isClean: boolean;
}

/** What the UI shows for a message that could not be decrypted */
export type E2eeFailureKind =
  /** "Waiting for the key…": decrypted again when the key arrives */
  | "WaitingForKey"
  | "Withheld"
  /** A newer format: update the app */
  | "UpdateApp"
  /** Tampered with by the server: never shown as text */
  | "Suspicious"
  | "Broken"
  /** Store trouble: try again later */
  | "RetryLater";

/** A failure is a value, not an exception; results come in input order */
export type E2eeDecryptResult =
  | { type: "Decrypted"; message: E2eeDecryptedMessage }
  | {
      type: "Failed";
      kind: E2eeFailureKind;
      withheldReason?: string | null;
      /** Stable code (diagnostics) */
      code: string;
    };

export interface E2eeDevice {
  userId: string;
  deviceId: string;
  ed25519: string | null;
  trust: "Verified" | "Unverified" | "Blocked";
  deleted: boolean;
}

/** `encryptBlob`: upload `blob`, put `fileJson` (secret: the key) into the payload */
export interface E2eeEncryptedBlob {
  blob: Blob;
  fileJson: string;
  size: number;
}

/** A small blob in one call (thumbnails) */
export interface E2eeEncryptedBytes {
  ciphertext: Uint8Array;
  fileJson: string;
}

/**
 * Error codes of the core (`StoatCryptoError.code`) the SDK reacts to; others pass
 * through as they are
 */
export type E2eeErrorCode =
  | "StoreLocked"
  | "RoomKeyNotShared"
  | "PayloadTooLarge"
  | "UnknownChannel"
  | "MfaRequired"
  | "BackupVersionChanged"
  | "DeviceKeysConflict"
  | "RequestRejected"
  | "AttachmentHashMismatch"
  | "Panic"
  | "WorkerClosed"
  | "NotOpen"
  | (string & NonNullable<unknown>);

/**
 * The crypto core of one account (one machine, one store, one worker). Every method may
 * reject with an error carrying `code` (`E2eeErrorCode`).
 */
export interface E2eeProvider {
  /** User (ULID) and device (= session id) the machine was opened for */
  readonly userId: string;
  readonly deviceId: string;

  setServerLimits(limits: E2eeServerLimits): Promise<void>;

  /** The request pass: the same id comes back while it is in flight */
  outgoingRequests(): Promise<E2eeOutgoingRequest[]>;
  /** 2xx; `body` = the response JSON ("" for 204) */
  markRequestSent(
    id: string,
    kind: E2eeRequestKind,
    body: string,
  ): Promise<void>;
  /** Non-2xx, or 0 when there was no response */
  markRequestFailed(
    id: string,
    kind: E2eeRequestKind,
    status: number,
  ): Promise<void>;
  /** When to run the next pass without another event; `null`: nothing scheduled */
  wakeupInMs(): Promise<number | null>;

  /** `GET /e2ee/to_device?limit=N` response body */
  receiveToDevice(body: string): Promise<E2eeToDeviceResult>;
  markAckSent(ids: string[]): Promise<void>;
  receiveDeviceListUpdate(users: string[]): Promise<void>;
  /** Socket `Ready` (every connect) */
  receiveReconnect(): Promise<void>;
  /** `GET /e2ee/keys/count` response body */
  receiveOtkCounts(body: string): Promise<void>;

  /** Full member list of an encrypted DM/group */
  setChannelMembers(
    channelId: string,
    members: string[],
    settings?: E2eeChannelSettings,
  ): Promise<void>;
  /** Requests to run before `encrypt`; loop until empty */
  prepareSend(channelId: string): Promise<E2eeOutgoingRequest[]>;
  /** Payload v1 JSON → envelope v1 JSON (`RoomKeyNotShared` → back to `prepareSend`) */
  encrypt(channelId: string, payloadJson: string): Promise<string>;
  /** A page of messages, results in input order */
  decryptMany(messages: E2eeIncomingMessage[]): Promise<E2eeDecryptResult[]>;

  /** Known devices of a user (ULID); empty if none has E2EE */
  devices(userId: string): Promise<E2eeDevice[]>;

  /** Encrypt a file (streamed in the worker) */
  encryptBlob(blob: Blob): Promise<E2eeEncryptedBlob>;
  /** Encrypt a small blob (a thumbnail) */
  encryptAttachment(data: Uint8Array): Promise<E2eeEncryptedBytes>;
  /** Check the hash of the whole ciphertext, then decrypt (`AttachmentHashMismatch`) */
  decryptBlob(
    blob: Blob,
    fileJson: string,
    contentType?: string,
  ): Promise<Blob>;

  /** Close the machine and stop its worker (account switch) */
  close(): Promise<void>;
  /** Sign-out: close, delete the account's store, stop the worker */
  destroy(): Promise<void>;
}

/** The `code` of an error of the core, if it has one */
export function e2eeErrorCode(error: unknown): E2eeErrorCode | undefined {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === "string") return code;
  }
}

/** Errors of the SDK's E2EE paths; `code` names the case, the message is fixed */
export class E2eeError extends Error {
  readonly code: string;

  /**
   * Construct E2EE error
   * @param code Code
   * @param message Fixed message without content
   */
  constructor(code: string, message: string) {
    super(message);
    this.name = "E2eeError";
    this.code = code;
  }
}
