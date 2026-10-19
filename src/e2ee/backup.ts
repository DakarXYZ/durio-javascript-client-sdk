// The key backup of one account (dur.io fork, plan WEB-07; Android's `E2eeBackup` is the
// reference; host contract "Key backup and recovery" in
// `stoat-crypto/crates/stoat-crypto/src/lib.rs`). The recovery key is the secret storage
// key: a rotation keeps it, and it unlocks the backup on a new device.
//
// Setup: `create` → show the key → `activate` (an MFA ticket when a backup exists, asked
// for up front: without one the server answers 401) → the secret and key uploads leave
// with the normal request passes. Restore: `unlock` → `restore` → messages waiting for
// keys are decrypted again.
//
// Secrets (recovery key, passphrase) come in as `Uint8Array`s and are wiped here
// whatever happens; never log them, nor a `E2eeRecoverySetup`.
import type { Client } from "../Client.js";

import { isSuccess, rawRequest } from "./http.js";
import {
  type E2eeBackupStatus,
  E2eeError,
  type E2eeProvider,
  type E2eeRecoverySetup,
  type E2eeRestoreProgress,
} from "./provider.js";
import { E2eeRequestError, type E2eeSync } from "./requests.js";

/** Header of an MFA ticket: replacing a backup needs one (Q13) */
export const MFA_TICKET_HEADER = "x-mfa-ticket";

/** Secret storage entries a restore reads */
export const SECRET_DEFAULT_KEY = "m.secret_storage.default_key";
export const SECRET_KEY_PREFIX = "m.secret_storage.key.";
export const SECRET_MEGOLM_BACKUP = "m.megolm_backup.v1";

/**
 * Key backup of one account
 */
export class E2eeBackup {
  readonly #client: Client;
  readonly #core: () => [E2eeProvider, E2eeSync];
  readonly #onRestored: () => void;

  /**
   * Construct the backup helper
   * @param client Client whose session runs the requests
   * @param core The installed crypto core and its sync loop (throws without one)
   * @param onRestored Keys arrived: decrypt waiting messages again
   */
  constructor(
    client: Client,
    core: () => [E2eeProvider, E2eeSync],
    onRestored: () => void,
  ) {
    this.#client = client;
    this.#core = core;
    this.#onRestored = onRestored;
  }

  /** Backup state of this device */
  async status(): Promise<E2eeBackupStatus> {
    return this.#core()[0].backupStatus();
  }

  /** Whether the server holds a backup of this account (404: none) */
  async exists(): Promise<boolean> {
    const response = await this.#get("/e2ee/backup/version", true);
    return response !== undefined;
  }

  /**
   * A new recovery key and backup; nothing changes on the server until `activate`
   * @param passphrase Optional passphrase (wiped here)
   */
  async create(passphrase?: Uint8Array): Promise<E2eeRecoverySetup> {
    try {
      return await this.#core()[0].createRecovery(passphrase);
    } finally {
      passphrase?.fill(0);
    }
  }

  /** A new backup under the same recovery key (after a suspected leak); needs MFA */
  async rotate(): Promise<E2eeRecoverySetup> {
    return this.#core()[0].rotateBackup();
  }

  /**
   * Create the backup version on the server: the backup is on once this resolves
   * @param setup From `create` or `rotate`
   * @param mfaTicket Token of an MFA ticket (a backup exists, or a rotation)
   * @throws `MfaRequired` (a backup exists: call again with a ticket), or
   *   `E2eeRequestError` when the server refused or did not answer
   */
  async activate(setup: E2eeRecoverySetup, mfaTicket?: string): Promise<void> {
    return this.#core()[1].runNow(
      setup.request,
      mfaTicket ? { [MFA_TICKET_HEADER]: mfaTicket } : {},
    );
  }

  /**
   * Unlock the server's backup on this device with the recovery key or passphrase;
   * from now on this device uploads its keys too
   * @param input Recovery key or passphrase, UTF-8 (wiped here)
   * @returns Backup version for `restore`
   * @throws `NoBackup`, `RecoveryKeyTypo`, `WrongRecoveryKey`, `BackupKeyMismatch`,
   *   or `E2eeRequestError`
   */
  async unlock(input: Uint8Array): Promise<string> {
    try {
      const [provider, sync] = this.#core();
      const defaultKey = await this.#secret(SECRET_DEFAULT_KEY);
      let keyId: unknown;
      try {
        keyId = (JSON.parse(defaultKey) as { key?: unknown }).key;
      } catch {
        keyId = undefined;
      }

      if (typeof keyId !== "string" || !keyId)
        throw new E2eeError(
          "BackupKeyMismatch",
          "the backup does not match its recovery data",
        );

      const secrets = {
        defaultKey,
        keyDescription: await this.#secret(SECRET_KEY_PREFIX + keyId),
        backupSecret: await this.#secret(SECRET_MEGOLM_BACKUP),
        backupVersion: (await this.#get("/e2ee/backup/version"))!,
      };

      const version = await provider.unlockBackup(input, secrets);
      // uploads of this device go to the unlocked version from now on
      sync.requestPass();
      return version;
    } finally {
      input.fill(0);
    }
  }

  /**
   * Download the backup's keys and import them in batches; an interrupted restore can
   * simply run again (an import never makes a key worse)
   * @param version From `unlock`
   * @param onProgress After every batch
   * @returns Final progress
   */
  async restore(
    version: string,
    onProgress: (progress: E2eeRestoreProgress) => void = () => {},
  ): Promise<E2eeRestoreProgress> {
    const body = (await this.#get(
      `/e2ee/backup/keys?version=${encodeURIComponent(version)}`,
    ))!;

    const restore = await this.#core()[0].restoreBackup(body);
    try {
      let progress = await restore.progress();
      onProgress(progress);
      while (!progress.finished) {
        progress = await restore.next();
        onProgress(progress);
      }

      return progress;
    } finally {
      await restore.free().catch(() => undefined);
      this.#onRestored();
    }
  }

  /** Stop uploading keys from this device (the server's backup stays) */
  async disable(): Promise<void> {
    return this.#core()[0].disableBackup();
  }

  /**
   * Turn the backup off for the account: delete the server's backup and its keys, then
   * stop uploading from this device. Other devices stop at their next upload (their
   * version is gone) and say the backup changed. The recovery data in secret storage
   * stays: it unlocks nothing without a backup, and a new backup replaces it.
   * @param mfaTicket Token of an MFA ticket: the server deletes only with one
   * @throws `MfaRequired` (no or a stale ticket), or `E2eeRequestError` when the
   *   server refused or did not answer; then nothing changed on this device
   */
  async turnOff(mfaTicket?: string): Promise<void> {
    const [provider] = this.#core();
    const current = await this.#get("/e2ee/backup/version", true);
    if (current !== undefined) {
      let version: unknown;
      try {
        version = (JSON.parse(current) as { version?: unknown }).version;
      } catch {
        version = undefined;
      }

      if (typeof version !== "string" || !version)
        throw new E2eeError("InvalidResponse", "malformed backup version");

      let response;
      try {
        response = await rawRequest(
          this.#client,
          "DELETE",
          `/e2ee/backup/version/${encodeURIComponent(version)}`,
          undefined,
          mfaTicket ? { [MFA_TICKET_HEADER]: mfaTicket } : {},
        );
      } catch {
        throw new E2eeRequestError(0);
      }

      if (response.status === 401)
        throw new E2eeError("MfaRequired", "deleting the backup needs MFA");
      // 404: deleted meanwhile, by another device
      if (!isSuccess(response.status) && response.status !== 404)
        throw new E2eeRequestError(response.status);
    }

    await provider.disableBackup();
  }

  #secret(type: string): Promise<string> {
    return this.#get(
      `/e2ee/secrets/${encodeURIComponent(type)}`,
    ) as Promise<string>;
  }

  /**
   * GET with the account's session
   * @param path Path
   * @param missingOk 404 resolves to `undefined` instead of `NoBackup`
   */
  async #get(path: string, missingOk = false): Promise<string | undefined> {
    let response;
    try {
      response = await rawRequest(this.#client, "GET", path);
    } catch {
      throw new E2eeRequestError(0);
    }

    if (isSuccess(response.status)) return response.body;
    if (response.status === 404) {
      if (missingOk) return undefined;
      throw new E2eeError("NoBackup", "there is no backup on the server");
    }

    throw new E2eeRequestError(response.status);
  }
}
