// Which DMs and groups of the account are encrypted (dur.io fork, plan WEB-05, Q47, T18;
// Android's `E2eeChannels`). Server channels never are.
//
// A channel seen with `encryption` once is **pinned** in the account's pin store and stays
// encrypted for this client whatever the server says later: a server that drops the flag
// (downgrade) only gets a warning, and nothing ever goes out in plaintext to it. Pins are
// never removed.
import { ReactiveSet } from "@solid-primitives/set";
import type { Channel as APIChannel } from "stoat-api";

import { e2eeWarn } from "./log.js";

/** Where pins live (the client keeps them per accountKey) */
export interface E2eePinStore {
  load(): string[];
  pin(channelId: string): void;
}

type ChannelType = APIChannel["channel_type"];

/**
 * Whether channels of this type can be encrypted
 * @param type Channel type
 */
export const isEncryptableType = (type: ChannelType | undefined) =>
  type === "DirectMessage" || type === "Group";

/**
 * Encrypted channels of one account
 */
export class E2eeChannels {
  readonly #pinned = new ReactiveSet<string>();
  readonly #downgraded = new ReactiveSet<string>();
  #store: E2eePinStore | undefined;

  /**
   * Use a persistent pin store: pins seen so far go into it, its pins come in
   * @param store Store, or undefined for memory only
   */
  setStore(store: E2eePinStore | undefined): void {
    this.#store = store;
    if (!store) return;

    try {
      for (const id of store.load()) this.#pinned.add(id);
      for (const id of this.#pinned) store.pin(id);
    } catch (e) {
      e2eeWarn("channel pins not loaded", (e as Error)?.name);
    }
  }

  /**
   * Whether messages to the channel must be encrypted
   * @param id Channel id
   * @param type Channel type
   * @param encrypted Whether the server says it is encrypted
   */
  isEncrypted(id: string, type: ChannelType | undefined, encrypted: boolean) {
    if (!isEncryptableType(type)) return false;
    return encrypted || this.#pinned.has(id);
  }

  /**
   * Pinned as encrypted, but the server sent it without `encryption`
   * @param id Channel id
   */
  isDowngraded(id: string): boolean {
    return this.#downgraded.has(id);
  }

  /**
   * A channel as the server sent it (`Ready`, `ChannelCreate`, `ChannelUpdate`, a fetch)
   * @param id Channel id
   * @param type Channel type
   * @param encrypted Whether it came with `encryption`
   * @returns Whether it became encrypted just now (its members then go to the core)
   */
  observe(id: string, type: ChannelType | undefined, encrypted: boolean) {
    if (!isEncryptableType(type)) return false;

    const wasPinned = this.#pinned.has(id);
    if (!encrypted) {
      if (wasPinned && !this.#downgraded.has(id)) {
        e2eeWarn("server sent an encrypted channel without encryption");
        this.#downgraded.add(id);
      }

      return false;
    }

    this.#downgraded.delete(id);
    if (wasPinned) return false;

    this.#pinned.add(id);
    try {
      this.#store?.pin(id);
    } catch (e) {
      e2eeWarn("channel pin not stored", (e as Error)?.name);
    }

    return true;
  }

  /** Pinned channel ids */
  pinned(): string[] {
    return [...this.#pinned];
  }

  /** Forget everything in memory (the store is the client's to delete) */
  clear(): void {
    this.#store = undefined;
    this.#pinned.clear();
    this.#downgraded.clear();
  }
}
