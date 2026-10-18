// The crypto core's network side for one account (dur.io fork, plan WEB-04; Android's
// `E2eeSync` is the reference): request passes, the to-device mailbox, one-time key
// counts and the send preparation. The core does no HTTP and has no timers; this is
// its host, following the contract in `stoat-crypto/crates/stoat-crypto/src/lib.rs`:
//
// - `start` (after opening and `setServerLimits`): a request pass;
// - `onReady` (socket `Ready`, every connect): `receiveReconnect`, then *always* the
//   mailbox (a doorbell lost while offline is never repeated) and `keys/count`, a pass;
// - `onToDevice` (`E2eeToDevice` doorbell): mailbox pages of 100 → core → ack →
//   `markAckSent` while the page was full; `onKeysLow`: `keys/count`;
// - `onDeviceListUpdate`, `onChannelMembers`: into the core, then a pass;
// - after every cycle the core's `wakeupInMs` schedules the next pass;
// - a mailbox pass every 60 s regardless of doorbells (block 5E: a socket that went
//   quiet, a lost doorbell).
//
// One loop per account: triggers are merged and handled one cycle at a time, and a
// mutex serializes cycles with `prepareSend`. Each attempt of a request is marked in the
// core exactly once, with the real status (0: no answer). Network errors, 5xx and 429
// back off (429 by its `retry_after`); other 4xx are marked failed and the core decides
// when to retry — its own requests refused for good are dropped after a few tries
// (`syncProblem`), so no pass loops forever. 401 stops everything.
import type { Client } from "../Client.js";

import { type RawResponse, isSuccess, rawRequest } from "./http.js";
import { e2eeWarn } from "./log.js";
import {
  type E2eeChannelSettings,
  E2eeError,
  type E2eeOutgoingRequest,
  type E2eeProvider,
  type E2eeRequestKind,
  type E2eeRoomKey,
  e2eeErrorCode,
} from "./provider.js";

/** Messages per mailbox page; the server's maximum */
export const TO_DEVICE_LIMIT = 100;

/** Ids per ack call */
export const ACK_LIMIT = 100;

/** The safety mailbox pass (block 5E) */
export const SAFETY_PASS_MS = 60_000;

const MAX_PASSES = 16;
const MAX_MAILBOX_PAGES = 50;

/** What the sync loop reports to the app */
export type E2eeSyncEvent =
  /** Re-decrypt messages waiting for these sessions */
  | { type: "roomKeys"; keys: E2eeRoomKey[] }
  /** Verification flows that changed (WEB-07) */
  | { type: "verifications"; flowIds: string[] }
  /** A failed request needs the user: `MfaRequired`, `BackupVersionChanged`, `DeviceKeysConflict` */
  | { type: "actionRequired"; code: string }
  /** The core gave up on one of its own requests (review O-2): a notice, nothing blocks */
  | { type: "syncProblem"; kind: E2eeRequestKind }
  /** 401: the session is gone */
  | { type: "unauthorized" }
  /** The core is gone (`Panic`, `WorkerClosed`): the loop stopped, start a new one */
  | { type: "fatal"; code: string };

export type E2eeSyncState =
  | "idle"
  | "running"
  | "backingOff"
  | "unauthorized"
  | "stopped";

type Trigger =
  | { type: "pass" }
  | { type: "retry" }
  | { type: "ready" }
  | { type: "mailbox" }
  | { type: "keysCount" }
  | { type: "deviceList"; user: string }
  | {
      type: "members";
      channelId: string;
      members: string[];
      settings?: E2eeChannelSettings;
    };

type Step =
  | { type: "ok" }
  /** Marked failed with a 4xx; the core schedules the retry */
  | { type: "rejected" }
  /** Network, 5xx or 429: back off; `delayMs` from the server if it said so */
  | { type: "retry"; delayMs?: number }
  | { type: "unauthorized" };

/**
 * Whether an error code means the core instance is gone
 * @param code Error code
 */
export const isFatal = (code: string | undefined) =>
  code === "Panic" || code === "WorkerClosed" || code === "NotOpen";

/** Exponential backoff for network failures: 1 s doubling up to 5 min */
export class Backoff {
  #current = 0;

  /**
   * Construct backoff
   * @param initialMs First delay
   * @param maxMs Largest delay
   */
  constructor(
    readonly initialMs = 1_000,
    readonly maxMs = 300_000,
  ) {}

  /** Next delay */
  next(): number {
    this.#current =
      this.#current === 0
        ? this.initialMs
        : Math.min(this.#current * 2, this.maxMs);
    return this.#current;
  }

  /** Back to the first delay */
  reset(): void {
    this.#current = 0;
  }
}

/** A promise chain: one holder at a time, in order */
export class Mutex {
  #tail: Promise<unknown> = Promise.resolve();

  /**
   * Run `fn` once every earlier holder is done
   * @param fn Critical section
   */
  run<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(fn, fn);
    this.#tail = result.catch(() => undefined);
    return result;
  }
}

/** The message could not be prepared for encryption; `retryable`: network or server trouble */
export class E2eeSendPreparationError extends E2eeError {
  readonly retryable: boolean;

  /**
   * Construct error
   * @param retryable Whether trying again later may help
   */
  constructor(retryable: boolean) {
    super(
      retryable ? "SendPreparationFailed" : "SendPreparationRejected",
      retryable
        ? "send preparation failed, retry later"
        : "send preparation rejected",
    );
    this.retryable = retryable;
  }
}

export interface E2eeSyncOptions {
  backoff?: Backoff;
  /** Safety mailbox pass interval; 0 turns it off */
  safetyIntervalMs?: number;
  /** Runs one HTTP request (tests replace it) */
  request?: (
    method: string,
    path: string,
    body?: string,
  ) => Promise<RawResponse>;
}

/**
 * Network side of one account's crypto core (WEB-04)
 */
export class E2eeSync {
  readonly #provider: E2eeProvider;
  readonly #request: NonNullable<E2eeSyncOptions["request"]>;
  readonly #backoff: Backoff;
  readonly #safetyIntervalMs: number;
  readonly #listeners = new Set<(event: E2eeSyncEvent) => void>();
  readonly #mutex = new Mutex();
  readonly #inFlight = new Set<string>();

  // what is still to do; a flag is cleared only once its step went through
  readonly #pending = {
    ready: false,
    mailbox: false,
    keysCount: false,
    users: new Set<string>(),
    members: new Map<string, Trigger & { type: "members" }>(),
  };

  #queue: Trigger[] = [];
  #running = false;
  #holding = false;
  #started = false;
  #stopped = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #safety: ReturnType<typeof setInterval> | undefined;
  #state: E2eeSyncState = "idle";

  /**
   * Construct the sync loop
   * @param client Client whose session runs the requests
   * @param provider The account's crypto core
   * @param options Options
   */
  constructor(
    client: Client,
    provider: E2eeProvider,
    options: E2eeSyncOptions = {},
  ) {
    this.#provider = provider;
    this.#request =
      options.request ??
      ((method, path, body) => rawRequest(client, method, path, body));
    this.#backoff = options.backoff ?? new Backoff();
    this.#safetyIntervalMs = options.safetyIntervalMs ?? SAFETY_PASS_MS;
  }

  /** Current state of the loop */
  get state(): E2eeSyncState {
    return this.#state;
  }

  /**
   * Listen to room keys, verifications, actions for the UI and 401
   * @returns Function to remove the listener
   */
  onEvent(listener: (event: E2eeSyncEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  /** Start the loop with a request pass and the safety mailbox pass */
  start(): void {
    if (this.#started || this.#stopped) return;
    this.#started = true;
    this.#trigger({ type: "pass" });
    if (this.#safetyIntervalMs > 0) {
      this.#safety = setInterval(
        () => this.#trigger({ type: "mailbox" }),
        this.#safetyIntervalMs,
      );
    }
  }

  /** Stop the loop; the core stays open (its owner closes it) */
  stop(): void {
    this.#stopped = true;
    clearTimeout(this.#timer);
    clearInterval(this.#safety);
    this.#queue = [];
    if (this.#state !== "unauthorized") this.#state = "stopped";
  }

  /** Run a request pass soon */
  requestPass(): void {
    this.#trigger({ type: "pass" });
  }

  /** Socket `Ready` after every (re)connect */
  onReady(): void {
    this.#trigger({ type: "ready" });
  }

  /** `E2eeToDevice` for this device: only a doorbell, the content is in the mailbox */
  onToDevice(): void {
    this.#trigger({ type: "mailbox" });
  }

  /** `E2eeKeysLow`: only a trigger for `keys/count` */
  onKeysLow(): void {
    this.#trigger({ type: "keysCount" });
  }

  /** `E2eeDeviceListUpdate {user}` */
  onDeviceListUpdate(user: string): void {
    this.#trigger({ type: "deviceList", user });
  }

  /** The full member list of an encrypted DM/group (load, Ready, join/leave, enabled) */
  onChannelMembers(
    channelId: string,
    members: string[],
    settings?: E2eeChannelSettings,
  ): void {
    this.#trigger({ type: "members", channelId, members, settings });
  }

  /**
   * Run the core's `prepareSend` requests for a channel until none are left (contract
   * step 7); then the caller may `encrypt`. Serialized with the background cycles.
   * @param channelId Channel
   * @param members Member list, set in the core first (`onChannelMembers` is async)
   * @param settings Rotation settings of the channel
   * @throws E2eeSendPreparationError if a request failed: the message is not sent
   */
  prepareSend(
    channelId: string,
    members?: string[],
    settings?: E2eeChannelSettings,
  ): Promise<void> {
    return this.#mutex.run(async () => {
      if (members) {
        await this.#provider.setChannelMembers(channelId, members, settings);
      }

      for (let pass = 0; pass < MAX_PASSES; pass++) {
        const requests = (await this.#provider.prepareSend(channelId)).filter(
          (r) => !this.#inFlight.has(r.id),
        );

        if (!requests.length) return;
        for (const request of requests) {
          const step = await this.#runRequest(request);
          switch (step.type) {
            case "ok":
              break;
            case "unauthorized":
              this.#unauthorized();
              throw new E2eeSendPreparationError(false);
            case "rejected":
              throw new E2eeSendPreparationError(false);
            case "retry":
              throw new E2eeSendPreparationError(true);
          }
        }
      }

      throw new E2eeSendPreparationError(true);
    });
  }

  #emit(event: E2eeSyncEvent) {
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch (e) {
        e2eeWarn("sync listener failed", (e as Error)?.name);
      }
    }
  }

  #trigger(trigger: Trigger) {
    if (this.#stopped) return;
    this.#queue.push(trigger);
    void this.#run();
  }

  async #run() {
    if (this.#running) return;
    this.#running = true;

    try {
      while (this.#queue.length && !this.#stopped) {
        let resume = false;
        for (const trigger of this.#queue.splice(0)) {
          this.#add(trigger);
          if (trigger.type === "retry" || trigger.type === "ready")
            resume = true;
        }

        // backing off: collect, run when the timer fires (or the socket is back)
        if (this.#holding && !resume) continue;
        this.#holding = false;

        this.#state = "running";
        let step: Step;
        try {
          step = await this.#mutex.run(() => this.#cycle());
        } catch (e) {
          const code = e2eeErrorCode(e);
          if (isFatal(code)) {
            e2eeWarn("crypto core lost", code);
            this.stop();
            this.#emit({ type: "fatal", code: code! });
            return;
          }

          // a core error (bad response, store trouble): what is pending is kept
          e2eeWarn("cycle failed", code ?? (e as Error)?.name);
          step = { type: "retry" };
        }

        if (this.#stopped) break;
        switch (step.type) {
          case "ok":
          case "rejected": {
            this.#backoff.reset();
            this.#state = "idle";
            let wakeup: number | null = null;
            try {
              wakeup = await this.#provider.wakeupInMs();
            } catch {
              wakeup = null;
            }
            this.#schedule(wakeup, { type: "pass" });
            break;
          }
          case "retry":
            this.#holding = true;
            this.#state = "backingOff";
            this.#schedule(step.delayMs ?? this.#backoff.next(), {
              type: "retry",
            });
            break;
          case "unauthorized":
            this.#unauthorized();
            return;
        }
      }
    } finally {
      this.#running = false;
    }
  }

  #add(trigger: Trigger) {
    switch (trigger.type) {
      case "ready":
        this.#pending.ready = true;
        break;
      case "mailbox":
        this.#pending.mailbox = true;
        break;
      case "keysCount":
        this.#pending.keysCount = true;
        break;
      case "deviceList":
        this.#pending.users.add(trigger.user);
        break;
      case "members":
        this.#pending.members.set(trigger.channelId, trigger);
        break;
    }
  }

  #schedule(delayMs: number | null, trigger: Trigger) {
    clearTimeout(this.#timer);
    if (delayMs === null || this.#stopped) return;
    this.#timer = setTimeout(() => this.#trigger(trigger), delayMs);
  }

  #unauthorized() {
    clearTimeout(this.#timer);
    clearInterval(this.#safety);
    this.#state = "unauthorized";
    this.#stopped = true;
    this.#queue = [];
    this.#emit({ type: "unauthorized" });
  }

  // contract order: reconnect → device lists → members → mailbox → key counts → pass
  async #cycle(): Promise<Step> {
    const pending = this.#pending;

    // local steps: an input the core refuses is dropped, it must not block the mailbox
    if (pending.ready) {
      await this.#local("reconnect", () => this.#provider.receiveReconnect());
      pending.ready = false;
      pending.mailbox = true;
      pending.keysCount = true;
    }

    if (pending.users.size) {
      const users = [...pending.users];
      await this.#local("device list", () =>
        this.#provider.receiveDeviceListUpdate(users),
      );
      for (const user of users) pending.users.delete(user);
    }

    for (const [channelId, m] of [...pending.members]) {
      await this.#local("members", () =>
        this.#provider.setChannelMembers(channelId, m.members, m.settings),
      );
      if (pending.members.get(channelId) === m)
        pending.members.delete(channelId);
    }

    if (pending.mailbox) {
      const step = await this.#mailbox();
      if (step.type !== "ok") return step;
      pending.mailbox = false;
    }

    if (pending.keysCount) {
      const step = await this.#keysCount();
      if (step.type !== "ok") return step;
      pending.keysCount = false;
    }

    return this.#requestPasses();
  }

  async #local(what: string, fn: () => Promise<void>) {
    try {
      await fn();
    } catch (e) {
      const code = e2eeErrorCode(e);
      if (isFatal(code)) throw e;
      e2eeWarn(`${what} refused`, code);
    }
  }

  async #mailbox(): Promise<Step> {
    for (let page = 0; page < MAX_MAILBOX_PAGES; page++) {
      const fetched = await this.#call(
        "GET",
        `/e2ee/to_device?limit=${TO_DEVICE_LIMIT}`,
      );
      if ("step" in fetched) return fetched.step;

      const outcome = await this.#provider.receiveToDevice(
        fetched.response.body,
      );
      if (outcome.roomKeys.length)
        this.#emit({ type: "roomKeys", keys: outcome.roomKeys });
      if (outcome.verifications.length)
        this.#emit({ type: "verifications", flowIds: outcome.verifications });

      for (let i = 0; i < outcome.ackIds.length; i += ACK_LIMIT) {
        const ids = outcome.ackIds.slice(i, i + ACK_LIMIT);
        const ack = await this.#call(
          "POST",
          "/e2ee/to_device/ack",
          JSON.stringify({ ids }),
        );
        if ("step" in ack) return ack.step;
        await this.#provider.markAckSent(ids);
      }

      if (outcome.fetched < TO_DEVICE_LIMIT) return { type: "ok" };
    }

    // a very long mailbox: let other work in, continue in the next cycle
    this.#trigger({ type: "mailbox" });
    return { type: "ok" };
  }

  async #keysCount(): Promise<Step> {
    const counts = await this.#call("GET", "/e2ee/keys/count");
    if ("step" in counts) return counts.step;
    await this.#provider.receiveOtkCounts(counts.response.body);
    return { type: "ok" };
  }

  // until a pass returns nothing new; after a rejected request the core's wakeup takes over
  async #requestPasses(): Promise<Step> {
    for (let pass = 0; pass < MAX_PASSES; pass++) {
      const requests = (await this.#provider.outgoingRequests()).filter(
        (r) => !this.#inFlight.has(r.id),
      );
      if (!requests.length) return { type: "ok" };

      let rejected = false;
      for (const request of requests) {
        const step = await this.#runRequest(request);
        if (step.type === "rejected") rejected = true;
        else if (step.type !== "ok") return step;
      }

      if (rejected) return { type: "rejected" };
    }

    // still busy (a long backup upload): continue after other work
    this.#trigger({ type: "pass" });
    return { type: "ok" };
  }

  /** One attempt of one request, marked in the core exactly once */
  async #runRequest(request: E2eeOutgoingRequest): Promise<Step> {
    this.#inFlight.add(request.id);
    try {
      let response: RawResponse;
      try {
        response = await this.#request(
          request.method,
          request.path,
          request.body,
        );
      } catch (e) {
        e2eeWarn(`${request.kind} failed`, (e as Error)?.name);
        await this.#markFailed(request, 0);
        return { type: "retry" };
      }

      if (isSuccess(response.status)) {
        await this.#provider.markRequestSent(
          request.id,
          request.kind,
          response.body,
        );
        return { type: "ok" };
      }

      e2eeWarn(`${request.kind} failed`, response.status);
      await this.#markFailed(request, response.status);

      if (response.status === 401) return { type: "unauthorized" };
      if (response.status === 429)
        return { type: "retry", delayMs: response.retryAfterMs };
      if (response.status >= 500) return { type: "retry" };
      return { type: "rejected" };
    } finally {
      this.#inFlight.delete(request.id);
    }
  }

  /**
   * Mark a failed attempt. A request of the core refused for good is dropped by the
   * core (`RequestRejected`, once): a notice, not retried here.
   */
  async #markFailed(request: E2eeOutgoingRequest, status: number) {
    try {
      await this.#provider.markRequestFailed(request.id, request.kind, status);
    } catch (e) {
      const code = e2eeErrorCode(e);
      if (code === "RequestRejected") {
        e2eeWarn(`${request.kind} dropped by the core`, status);
        this.#emit({ type: "syncProblem", kind: request.kind });
      } else if (
        code === "MfaRequired" ||
        code === "BackupVersionChanged" ||
        code === "DeviceKeysConflict"
      ) {
        this.#emit({ type: "actionRequired", code });
      } else {
        throw e;
      }
    }
  }

  // mailbox, ack and key counts: any answer other than 2xx is retried later
  // (404: E2EE switched off on the server; 400: nothing this client can fix now)
  async #call(
    method: string,
    path: string,
    body?: string,
  ): Promise<{ response: RawResponse } | { step: Step }> {
    let response: RawResponse;
    try {
      response = await this.#request(method, path, body);
    } catch (e) {
      e2eeWarn("mailbox/key count failed", (e as Error)?.name);
      return { step: { type: "retry" } };
    }

    if (isSuccess(response.status)) return { response };
    if (response.status === 401) return { step: { type: "unauthorized" } };
    e2eeWarn("mailbox/key count failed", response.status);
    return {
      step: {
        type: "retry",
        delayMs: response.status === 429 ? response.retryAfterMs : undefined,
      },
    };
  }
}
