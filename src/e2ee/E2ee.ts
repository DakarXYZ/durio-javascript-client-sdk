// E2EE of one client (dur.io fork, plan WEB-03…06): direct messages and groups only.
//
// Always present as `client.e2ee`; the crypto core (`E2eeProvider`, a Web Worker over
// `@durio/stoat-crypto` in the app) is installed by the host after login and removed on
// account switch (`uninstall`) or sign-out (`uninstall({ destroy: true })`). Without a
// core encrypted channels stay encrypted — pinned locally — and nothing can be sent to
// them; their messages wait in the `pending` state or say why they cannot be read.
import type { Accessor, Setter } from "solid-js";
import { createSignal } from "solid-js";

import type {
  Channel as APIChannel,
  Message as APIMessage,
  DataMessageSend,
} from "stoat-api";
import { ulid } from "ulid";

import type { Client } from "../Client.js";
import type { Channel } from "../classes/Channel.js";
import type { File } from "../classes/File.js";
import type { Message } from "../classes/Message.js";

import { E2eeBackup } from "./backup.js";
import { E2eeChannels, type E2eePinStore } from "./channels.js";
import {
  E2eeDecryptor,
  type E2eeFailureReason,
  type EncryptedEnvelope,
} from "./decryptor.js";
import { errorType, isSuccess, rawRequest } from "./http.js";
import { e2eeWarn } from "./log.js";
import { MessageSendError, sendWithRetry } from "./outbox.js";
import {
  type E2eePayload,
  type E2eePayloadAttachment,
  editPayload,
  messagePayload,
  payloadFileIds,
} from "./payload.js";
import {
  type E2eeChannelSettings,
  type E2eeDevice,
  type E2eeEncryptedBlob,
  type E2eeEncryptedBytes,
  E2eeError,
  type E2eeIdentityKeys,
  type E2eeKeyExport,
  type E2eeKeyImportResult,
  type E2eeProvider,
  type E2eeRecoveryKeyCheck,
  type E2eeSasEmoji,
  type E2eeSasFlow,
  type E2eeSettableTrust,
  type E2eeUndeliveredDevice,
  e2eeErrorCode,
} from "./provider.js";
import {
  E2eeSendPreparationError,
  E2eeSync,
  type E2eeSyncEvent,
  type E2eeSyncOptions,
} from "./requests.js";

/**
 * Where E2EE of this client stands:
 * - `off`: no crypto core (not started, or the server has no E2EE)
 * - `starting`: the host is starting the core
 * - `ready`: encrypted channels can be read and written
 * - `locked`: encryption is active in another window (Web Lock, Q28)
 * - `unavailable`: this build or device cannot run the core (no store key)
 * - `error`: the core failed (a trap) and was stopped
 * - `keyLost`: the store of this device cannot be opened with its key (the key was
 *   lost, or the store is damaged): reset = sign out and in again (C22, AN-42)
 * - `updateApp`: the store was written by a newer version of the core (CR-23)
 */
export type E2eeStatus =
  | "off"
  | "starting"
  | "ready"
  | "locked"
  | "unavailable"
  | "error"
  | "keyLost"
  | "updateApp";

/** SAS actions of the user */
export type E2eeSasAction =
  | "accept"
  | "start"
  | "confirm"
  | "mismatch"
  | "cancel";

/** What the app hears from E2EE (WEB-07 builds its UI on it) */
export type E2eeEvent =
  | E2eeSyncEvent
  | { type: "status"; status: E2eeStatus }
  /** A user's device list changed (own: maybe a new device to verify) */
  | { type: "deviceList"; user: string };

const MAX_ENCRYPT_ATTEMPTS = 3;
const ALGORITHM = "m.megolm.v1.aes-sha2";

/**
 * E2EE of one client
 */
export class E2ee {
  readonly #client: Client;
  readonly channels = new E2eeChannels();
  readonly decryptor: E2eeDecryptor;
  /** Key backup and recovery (WEB-07) */
  readonly backup: E2eeBackup;

  readonly status: Accessor<E2eeStatus>;
  readonly #setStatus: Setter<E2eeStatus>;

  #provider: E2eeProvider | undefined;
  #sync: E2eeSync | undefined;
  readonly #listeners = new Set<(event: E2eeEvent) => void>();

  /**
   * Construct E2EE of a client
   * @param client Client
   */
  constructor(client: Client) {
    this.#client = client;
    this.decryptor = new E2eeDecryptor(client, () => this.#provider);
    this.backup = new E2eeBackup(
      client,
      () => this.#ready(),
      () => this.decryptor.queueAll(),
    );

    const [status, setStatus] = createSignal<E2eeStatus>("off");
    this.status = status;
    this.#setStatus = setStatus;
  }

  /** The installed crypto core */
  get provider(): E2eeProvider | undefined {
    return this.#provider;
  }

  /** The installed sync loop */
  get sync(): E2eeSync | undefined {
    return this.#sync;
  }

  /** Whether the server has E2EE (`GET /` → `features.e2ee.enabled`) */
  get enabled(): boolean {
    return !!this.#client.configuration?.features.e2ee?.enabled;
  }

  /**
   * Listen to E2EE events
   * @returns Function to remove the listener
   */
  on(listener: (event: E2eeEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(event: E2eeEvent) {
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch (e) {
        e2eeWarn("listener failed", (e as Error)?.name);
      }
    }
  }

  /**
   * Set the status (the host while starting the core, or when it cannot)
   * @param status Status
   */
  setStatus(status: E2eeStatus): void {
    this.#setStatus(status);
    const reason: E2eeFailureReason | undefined =
      status === "locked"
        ? "locked"
        : status === "unavailable" ||
            status === "error" ||
            status === "keyLost" ||
            status === "updateApp"
          ? "unavailable"
          : undefined;
    if (reason) this.decryptor.markUnavailable(reason);
    this.#emit({ type: "status", status });
  }

  /**
   * Install the account's crypto core: limits, the sync loop, members of encrypted
   * channels, and every encrypted message decrypted again
   * @param provider Opened crypto core of the logged-in account
   * @param options Sync options (tests)
   */
  async install(
    provider: E2eeProvider,
    options: { sync?: E2eeSyncOptions } = {},
  ): Promise<void> {
    if (this.#provider) await this.uninstall();

    const features = this.#client.configuration?.features.e2ee;
    if (features) {
      await provider.setServerLimits({
        maxToDeviceBatch: features.max_to_device_batch,
        maxRequestBytes: features.max_request_bytes,
      });
    }

    this.#provider = provider;
    const sync = (this.#sync = new E2eeSync(
      this.#client,
      provider,
      options.sync,
    ));

    sync.onEvent((event) => this.#onSyncEvent(event));
    sync.start();

    for (const channel of this.#client.channels.values()) {
      if (this.isEncrypted(channel)) this.membersChanged(channel);
    }

    if (this.#client.ready()) sync.onReady();
    this.setStatus("ready");
    this.decryptor.queueAll();
  }

  /**
   * Remove the crypto core: close it (account switch) or destroy its store (sign-out).
   * Keys and plaintext of this client leave memory.
   * @param options Whether to delete the account's crypto store
   * @returns Whether a store was destroyed (false: none installed, or the deletion
   *   failed — the host then deletes it with a worker of its own, WEB-12)
   */
  async uninstall(options: { destroy?: boolean } = {}): Promise<boolean> {
    const provider = this.#provider;
    this.#sync?.stop();
    this.#sync = undefined;
    this.#provider = undefined;
    this.decryptor.clear();

    let destroyed = false;
    if (provider) {
      try {
        await (options.destroy ? provider.destroy() : provider.close());
        destroyed = !!options.destroy;
      } catch (e) {
        e2eeWarn("crypto core not closed", e2eeErrorCode(e));
      }
    }

    if (options.destroy) this.channels.clear();
    this.setStatus("off");
    return destroyed;
  }

  #onSyncEvent(event: E2eeSyncEvent) {
    switch (event.type) {
      case "roomKeys":
        this.decryptor.onRoomKeys(event.keys.map((k) => k.sessionId));
        break;
      case "fatal":
        void this.uninstall().then(() => this.setStatus("error"));
        break;
    }

    this.#emit(event);
  }

  // ------------------------------------------------------------- channels

  /**
   * Use the account's pin store; channels already known are checked against it again
   * (a pinned channel the server sent without `encryption` is a downgrade)
   * @param store Pin store of the account
   */
  setPinStore(store: E2eePinStore | undefined): void {
    this.channels.setStore(store);
    for (const channel of this.#client.channels.values()) {
      this.channels.observe(channel.id, channel.type, !!channel.encryption);
    }
  }

  /**
   * Whether messages to a channel must be encrypted (encrypted or pinned)
   * @param channel Channel
   */
  isEncrypted(channel: Channel): boolean {
    return this.channels.isEncrypted(
      channel.id,
      channel.type,
      !!channel.encryption,
    );
  }

  /**
   * Pinned as encrypted, but the server now sends it without `encryption`
   * @param channel Channel
   */
  isDowngraded(channel: Channel): boolean {
    return this.isEncrypted(channel) && this.channels.isDowngraded(channel.id);
  }

  /**
   * Whether this client can write to a channel right now
   * @param channel Channel
   */
  canSend(channel: Channel): boolean {
    return !this.isEncrypted(channel) || this.status() === "ready";
  }

  /**
   * A channel as the server sent it: pin it, warn on a downgrade, members to the core
   * @param data Channel data (or its changes)
   * @param id Channel id, if not in the data
   */
  observeChannel(data: Partial<APIChannel>, id = data._id): void {
    if (!id) return;
    const channel = this.#client.channels.get(id);
    const type = data.channel_type ?? channel?.type;
    if (type !== "DirectMessage" && type !== "Group") return;

    const encryption = (data as { encryption?: unknown }).encryption;
    // a partial update without the field says nothing about it
    if (!("channel_type" in data) && encryption === undefined) return;

    if (this.channels.observe(id, type, !!encryption) && channel)
      this.membersChanged(channel);
  }

  /**
   * The member list of a channel changed (or it became encrypted)
   * @param channel Channel
   */
  membersChanged(channel: Channel): void {
    if (!this.#sync || !this.isEncrypted(channel)) return;
    this.#sync.onChannelMembers(
      channel.id,
      [...channel.recipientIds],
      settingsOf(channel),
    );
  }

  // --------------------------------------------------------------- socket

  /**
   * Socket `Ready`: every encrypted channel as the server sent it, then the core's
   * reconnect (device lists, the mailbox, key counts)
   * @param channels Channels of the Ready payload
   */
  onReady(channels: APIChannel[] = []): void {
    for (const channel of channels) this.observeChannel(channel);
    if (!this.#sync) return;

    for (const channel of this.#client.channels.values()) {
      if (this.isEncrypted(channel)) this.membersChanged(channel);
    }

    this.#sync.onReady();
  }

  /** `E2eeToDevice`: a doorbell for this device's mailbox */
  onToDevice(): void {
    this.#sync?.onToDevice();
  }

  /** `E2eeDeviceListUpdate {user}` */
  onDeviceListUpdate(user: string): void {
    if (!this.#sync) return;
    this.#sync.onDeviceListUpdate(user);
    this.#emit({ type: "deviceList", user });
  }

  /** `E2eeKeysLow` */
  onKeysLow(): void {
    this.#sync?.onKeysLow();
  }

  // ------------------------------------------------------------- messages

  #ready(): [E2eeProvider, E2eeSync] {
    if (this.status() !== "ready" || !this.#provider || !this.#sync)
      throw new E2eeError(
        this.status() === "locked" ? "Locked" : "Unavailable",
        this.status() === "locked"
          ? "encryption is active in another window"
          : "encryption is not available",
      );
    return [this.#provider, this.#sync];
  }

  /**
   * The send loop (contract step 7): `prepareSend` until nothing is left, then
   * `encrypt` — once; `RoomKeyNotShared` (devices changed meanwhile) goes back
   * @returns Envelope v1
   */
  async #encrypt(channel: Channel, payload: E2eePayload) {
    const [provider, sync] = this.#ready();
    const members = [...channel.recipientIds];
    const selfId = this.#client.user?.id;
    const partner =
      channel.type === "DirectMessage"
        ? members.find((id) => id !== selfId)
        : undefined;

    const payloadJson = JSON.stringify(payload);
    for (let attempt = 0; attempt < MAX_ENCRYPT_ATTEMPTS; attempt++) {
      await sync.prepareSend(channel.id, members, settingsOf(channel));

      // without a single E2EE device on the other side the message reaches nobody
      if (
        partner &&
        !(await provider.devices(partner)).some((device) => !device.deleted)
      )
        throw new E2eeError(
          "NoRecipientDevices",
          "the recipient has no device that can read encrypted messages",
        );

      try {
        const envelope = JSON.parse(
          await provider.encrypt(channel.id, payloadJson),
        ) as EncryptedEnvelope;

        // exactly the fields of envelope v1 (the server refuses others)
        const v1: EncryptedEnvelope = {
          v: envelope.v,
          algorithm: envelope.algorithm,
          session_id: envelope.session_id,
          device_id: envelope.device_id,
          ciphertext: envelope.ciphertext,
        };

        this.decryptor.rememberLocal(v1.ciphertext, payloadJson);
        return v1;
      } catch (e) {
        // a member's device list changed between the share and the encrypt
        if (e2eeErrorCode(e) !== "RoomKeyNotShared") throw e;
      }
    }

    throw new E2eeSendPreparationError(true);
  }

  /**
   * Send an encrypted message (from `Channel.sendMessage`; `@silent` is already parsed)
   * @param channel Encrypted channel
   * @param data Message data: content, replies, flags; attachments come as payload
   * @param idempotencyKey Nonce and `Idempotency-Key` of the request
   * @param options Encrypted attachments (uploaded blobs, WEB-06); `resend`: an
   *   earlier attempt sent this key already
   * @returns The stored message (ciphertext; the model shows the plaintext)
   */
  async sendMessage(
    channel: Channel,
    data: DataMessageSend,
    idempotencyKey: string,
    options: { attachments?: E2eePayloadAttachment[]; resend?: boolean } = {},
  ): Promise<APIMessage> {
    const attachments = options.attachments ?? [];
    const nonce = idempotencyKey;
    const replies = data.replies ?? [];
    const payload = messagePayload(
      data.content ?? undefined,
      nonce,
      replies.map((reply) => reply.id),
      attachments,
    );

    const encrypted = await this.#encrypt(channel, payload);
    const fileIds = payloadFileIds(payload);

    const { message } = await sendWithRetry(
      this.#client,
      channel.id,
      {
        encrypted,
        nonce,
        ...(replies.length ? { replies } : {}),
        ...(fileIds.length ? { attachments: fileIds } : {}),
        ...(data.flags ? { flags: data.flags } : {}),
      },
      {
        nonce,
        idempotencyKey,
        resend: options.resend,
        selfId: this.#client.user?.id,
      },
    );

    return message;
  }

  /**
   * Edit an encrypted message (from `Message.edit`)
   * @param message Message, decrypted
   * @param content New text
   * @returns The stored message
   */
  async editMessage(message: Message, content: string): Promise<APIMessage> {
    const channel = message.channel;
    const stored = this.#client.messages.getUnderlyingObject(message.id);
    if (!channel || !stored.encrypted)
      // plaintext messages of an encrypted channel are not edited (BE-13)
      throw new E2eeError("NotEditable", "this message cannot be edited");

    const previous = this.decryptor.payloadOf(message.id);
    if (!previous)
      throw new E2eeError("NotDecrypted", "the message is not decrypted");

    const encrypted = await this.#encrypt(
      channel,
      editPayload(
        message.id,
        content,
        ulid(),
        previous.editSeq,
        stored.replyIds ?? [],
        previous.attachments,
      ),
    );

    const response = await rawRequest(
      this.#client,
      "PATCH",
      `/channels/${channel.id}/messages/${message.id}`,
      JSON.stringify({ encrypted }),
    );

    if (!isSuccess(response.status))
      throw new MessageSendError(
        response.status,
        errorType(response.body),
        response.body,
      );

    return JSON.parse(response.body) as APIMessage;
  }

  /**
   * Resolves once the message is decrypted or known not to be (notifications, D5)
   * @param id Message id
   * @param timeoutMs Longest wait
   */
  whenDecrypted(id: string, timeoutMs?: number): Promise<void> {
    return this.decryptor.whenDecrypted(id, timeoutMs);
  }

  /**
   * Turn encryption on for a DM or group: irreversible (O5: `ManageChannel`)
   * @param channel Channel
   */
  async enableEncryption(channel: Channel): Promise<void> {
    const data = await this.#client.api.put(
      `/channels/${channel.id as ""}/encryption`,
      { algorithm: ALGORITHM },
    );

    this.#client.channels.updateUnderlyingObject(
      channel.id,
      "encryption",
      (data as { encryption?: APIChannel & object }).encryption as never,
    );
    this.observeChannel(data as APIChannel, channel.id);
  }

  // ------------------------------------------------- devices (WEB-07, AN-30)

  /** This device's identity keys (its fingerprint is the Ed25519 key) */
  async identityKeys(): Promise<E2eeIdentityKeys> {
    return this.#ready()[0].identityKeys();
  }

  /**
   * Known E2EE devices of a user
   * @param userId User
   */
  async devices(userId: string): Promise<E2eeDevice[]> {
    return this.#ready()[0].devices(userId);
  }

  /**
   * Block a device or reset it to unverified; `Verified` only through SAS (O-3)
   * @param device Device
   * @param trust New trust
   */
  async setDeviceTrust(
    device: Pick<E2eeDevice, "userId" | "deviceId">,
    trust: E2eeSettableTrust,
  ): Promise<void> {
    return this.#ready()[0].setDeviceTrust(
      device.userId,
      device.deviceId,
      trust,
    );
  }

  /** Devices that miss our keys (their mailbox stays full) */
  async undeliveredDevices(): Promise<E2eeUndeliveredDevice[]> {
    return this.#ready()[0].undeliveredDevices();
  }

  // --------------------------------------------- verification (WEB-07, CR-11)

  /**
   * Ask a device for a SAS verification; the request leaves at once
   * @param userId User (own id: one of our other devices)
   * @param deviceId Device
   */
  async requestVerification(
    userId: string,
    deviceId: string,
  ): Promise<E2eeSasFlow> {
    const [provider, sync] = this.#ready();
    const flow = await provider.requestVerification(userId, deviceId);
    sync.requestPass();
    return flow;
  }

  /**
   * The flow of an id from a `verifications` event
   * @param flowId Flow id
   */
  async verification(flowId: string): Promise<E2eeSasFlow | null> {
    return this.#ready()[0].verification(flowId);
  }

  /** Every open verification flow */
  async verifications(): Promise<E2eeSasFlow[]> {
    return this.#ready()[0].verifications();
  }

  /**
   * Act on a flow; its messages leave at once
   * @param flow Flow
   * @param action What the user did
   */
  async verificationAction(
    flow: E2eeSasFlow,
    action: E2eeSasAction,
  ): Promise<void> {
    await flow[action]();
    this.#sync?.requestPass();
  }

  /** The SAS emoji table (symbols and English names by index) */
  async sasEmojiTable(): Promise<E2eeSasEmoji[]> {
    return this.#ready()[0].sasEmojiTable();
  }

  // ---------------------------------------- key files and report (CR-21, 22)

  /**
   * Room keys into a passphrase-protected file
   * @param passphrase UTF-8 (wiped here)
   * @param channelIds Channels, all if empty
   */
  async exportKeys(
    passphrase: Uint8Array,
    channelIds: string[] = [],
  ): Promise<E2eeKeyExport> {
    try {
      return await this.#ready()[0].exportRoomKeys(passphrase, channelIds);
    } finally {
      passphrase.fill(0);
    }
  }

  /**
   * Import a key file; messages waiting for its keys are decrypted again
   * @param file File content (text)
   * @param passphrase UTF-8 (wiped here)
   * @throws `WrongPassphrase` (or a modified file), `InvalidKeyFile`
   */
  async importKeys(
    file: string,
    passphrase: Uint8Array,
  ): Promise<E2eeKeyImportResult> {
    try {
      const result = await this.#ready()[0].importRoomKeys(file, passphrase);
      if (result.roomKeys.length)
        this.decryptor.onRoomKeys(result.roomKeys.map((key) => key.sessionId));
      return result;
    } finally {
      passphrase.fill(0);
    }
  }

  /**
   * Whether the input looks like a recovery key, has a typo, or is a passphrase
   * @param input UTF-8 (wiped here)
   */
  async recoveryKeyCheck(input: Uint8Array): Promise<E2eeRecoveryKeyCheck> {
    try {
      return await this.#ready()[0].recoveryKeyCheck(input);
    } finally {
      input.fill(0);
    }
  }

  /** The core's diagnostic report: counts, states and error codes only */
  async debugReport(): Promise<string> {
    return this.#ready()[0].debugReport();
  }

  // ---------------------------------------------------------------- files

  /**
   * Encrypt a file before upload (WEB-06)
   * @param blob File
   */
  encryptFile(blob: Blob): Promise<E2eeEncryptedBlob> {
    return this.#ready()[0].encryptBlob(blob);
  }

  /**
   * Encrypt a small blob (thumbnail) before upload
   * @param data Bytes
   */
  encryptThumbnail(data: Uint8Array): Promise<E2eeEncryptedBytes> {
    return this.#ready()[0].encryptAttachment(data);
  }

  /**
   * Download and decrypt an attachment of a decrypted message (hash checked first;
   * `AttachmentHashMismatch`: the server swapped the blob, show nothing)
   * @param file Attachment
   * @param thumbnail Its thumbnail instead, if it has one
   * @returns Plaintext blob with the real content type (memory only)
   */
  async decryptFile(file: File, thumbnail = false): Promise<Blob> {
    const provider = this.#provider;
    const keys = this.decryptor.fileKeys(file.id);
    if (!provider || !keys)
      throw new E2eeError("NoFileKey", "the attachment cannot be decrypted");

    const thumb = thumbnail ? keys.thumbnail : undefined;
    const autumn = this.#client.configuration?.features.autumn.url;
    const response = await fetch(
      `${autumn}/attachments/${thumb?.id ?? file.id}/file.bin`,
    );

    if (!response.ok)
      throw new E2eeError("DownloadFailed", "the attachment did not download");

    return provider.decryptBlob(
      await response.blob(),
      thumb?.fileJson ?? keys.fileJson,
      thumb ? "image/jpeg" : keys.contentType,
    );
  }

  /**
   * Whether an attachment has a decryptable thumbnail
   * @param file Attachment
   */
  hasThumbnail(file: File): boolean {
    return !!this.decryptor.fileKeys(file.id)?.thumbnail;
  }
}

/**
 * Rotation settings of an encrypted channel
 * @param channel Channel
 */
function settingsOf(channel: Channel): E2eeChannelSettings | undefined {
  const encryption = channel.encryption;
  if (!encryption) return;
  return {
    rotationPeriodMs: encryption.rotation_period_ms ?? null,
    rotationPeriodMsgs: encryption.rotation_period_msgs ?? null,
  };
}
