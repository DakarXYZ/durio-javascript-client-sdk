import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { E2eeEvent } from "../E2ee.js";
import { MFA_TICKET_HEADER } from "../backup.js";
import {
  createStoatCryptoProvider,
  retryWhileLocked,
} from "../cryptoProvider.js";
import { e2eeErrorCode } from "../provider.js";
import { E2eeRequestError } from "../requests.js";

import {
  FakeProvider,
  OTHER,
  SELF,
  coreError,
  emit,
  fakeServer,
  makeClient,
  settle,
} from "./fakes.js";

async function installed() {
  const client = makeClient();
  const provider = new FakeProvider();
  await client.e2ee.install(provider, { sync: { safetyIntervalMs: 0 } });
  const events: E2eeEvent[] = [];
  client.e2ee.on((event) => events.push(event));
  return { client, provider, events };
}

const bytes = (text: string) => new TextEncoder().encode(text);

describe("devices and verification (WEB-07)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("starts a SAS flow and runs a pass after every action", async () => {
    const { client, provider } = await installed();
    fakeServer(() => ({ status: 200, body: { messages: [] } }));
    const passes = vi.spyOn(client.e2ee.sync!, "requestPass");

    const flow = await client.e2ee.requestVerification(SELF, "PHONE");
    expect(flow.isSelfVerification).toBe(true);
    expect(await flow.otherDeviceId()).toBe("PHONE");
    expect(passes).toHaveBeenCalledTimes(1);

    await client.e2ee.verificationAction(flow, "start");
    expect((await flow.state()).type).toBe("Started");
    expect(passes).toHaveBeenCalledTimes(2);

    expect(await client.e2ee.verification(flow.flowId)).toBe(flow);
    expect(await client.e2ee.verifications()).toHaveLength(1);
    expect(provider.flows.size).toBe(1);
    await settle();
  });

  it("sets Unverified or Blocked trust; the adapter refuses Verified", async () => {
    const { client, provider } = await installed();
    await client.e2ee.setDeviceTrust(
      { userId: OTHER, deviceId: "D" },
      "Blocked",
    );
    expect(provider.trustCalls).toEqual([`${OTHER}/D:Blocked`]);

    const crypto = { setDeviceTrust: vi.fn(async () => undefined) };
    const adapter = createStoatCryptoProvider(crypto as never, {
      userId: SELF,
      deviceId: "S",
    });
    await expect(
      adapter.setDeviceTrust(OTHER, "D", "Verified" as never),
    ).rejects.toMatchObject({ code: "InvalidInput" });
    expect(crypto.setDeviceTrust).not.toHaveBeenCalled();
  });

  it("tells the app about device list updates", async () => {
    const { client, events } = await installed();
    fakeServer(() => ({ status: 200, body: { messages: [] } }));
    emit(client, { type: "E2eeDeviceListUpdate", user: SELF });
    expect(events).toContainEqual({ type: "deviceList", user: SELF });
    await settle();
  });

  it("refuses everything without a ready core", async () => {
    const client = makeClient();
    await expect(client.e2ee.devices(SELF)).rejects.toMatchObject({
      code: "Unavailable",
    });
    await expect(client.e2ee.backup.rotate()).rejects.toMatchObject({
      code: "Unavailable",
    });
  });
});

describe("key backup (WEB-07, CR-12)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("creates a recovery key and activates the backup with an MFA ticket", async () => {
    const { client, provider, events } = await installed();
    const requests = fakeServer((r) =>
      r.path === "/e2ee/backup/version" && r.method === "POST"
        ? r.headers[MFA_TICKET_HEADER] === "ticket"
          ? { status: 200, body: { version: "1" } }
          : { status: 401, body: { type: "InvalidSession" } }
        : { status: 200, body: { messages: [] } },
    );

    const passphrase = bytes("correct horse");
    const setup = await client.e2ee.backup.create(passphrase);
    expect(passphrase.every((b) => b === 0)).toBe(true);
    expect(provider.secretsSeen).toEqual(["correct horse"]);
    expect(setup.recoveryKey).toBe("EsTc 1234 abcd");

    // without a ticket: the core says MfaRequired, the session is not "expired"
    provider.failThrows[setup.request.id] = "MfaRequired";
    const error = await client.e2ee.backup.activate(setup).catch((e) => e);
    expect(e2eeErrorCode(error)).toBe("MfaRequired");
    expect(provider.failed).toContainEqual({
      id: setup.request.id,
      kind: "BackupVersionCreate",
      status: 401,
    });
    expect(events.some((e) => e.type === "unauthorized")).toBe(false);
    expect(client.e2ee.sync!.state).not.toBe("unauthorized");

    await client.e2ee.backup.activate(setup, "ticket");
    expect(provider.sent).toContainEqual({
      id: setup.request.id,
      kind: "BackupVersionCreate",
      body: '{"version":"1"}',
    });
    const posts = requests.filter((r) => r.method === "POST");
    expect(posts.at(-1)!.headers[MFA_TICKET_HEADER]).toBe("ticket");
    await settle();
  });

  it("reports a refused activation with its status", async () => {
    const { client } = await installed();
    fakeServer((r) =>
      r.method === "POST" ? { status: 500 } : { status: 200, body: {} },
    );
    const setup = await client.e2ee.backup.rotate();
    const error = await client.e2ee.backup.activate(setup, "t").catch((e) => e);
    expect(error).toBeInstanceOf(E2eeRequestError);
    expect((error as E2eeRequestError).status).toBe(500);
  });

  it("knows whether the server has a backup", async () => {
    const { client } = await installed();
    let exists = false;
    fakeServer((r) =>
      r.path === "/e2ee/backup/version"
        ? exists
          ? { status: 200, body: { version: "3" } }
          : { status: 404 }
        : undefined,
    );
    expect(await client.e2ee.backup.exists()).toBe(false);
    exists = true;
    expect(await client.e2ee.backup.exists()).toBe(true);
  });

  it("unlocks with the four GETs, restores in batches and re-decrypts", async () => {
    const { client, provider } = await installed();
    const requests = fakeServer((r) => {
      switch (r.path) {
        case "/e2ee/secrets/m.secret_storage.default_key":
          return { status: 200, body: { key: "K1" } };
        case "/e2ee/secrets/m.secret_storage.key.K1":
          return { status: 200, body: { desc: 1 } };
        case "/e2ee/secrets/m.megolm_backup.v1":
          return { status: 200, body: { enc: 1 } };
        case "/e2ee/backup/version":
          return { status: 200, body: { version: "7" } };
        case "/e2ee/backup/keys?version=7":
          return { status: 200, body: { rooms: {} } };
        default:
          return { status: 200, body: { messages: [] } };
      }
    });
    const queueAll = vi.spyOn(client.e2ee.decryptor, "queueAll");

    const input = bytes("EsTc 1234 abcd");
    const version = await client.e2ee.backup.unlock(input);
    expect(version).toBe("7");
    expect(input.every((b) => b === 0)).toBe(true);
    expect(provider.calls).toContain('unlock:{"key":"K1"}|{"version":"7"}');

    const seen: number[] = [];
    const done = await client.e2ee.backup.restore(version, (p) =>
      seen.push(p.done),
    );
    expect(done.finished).toBe(true);
    expect(seen).toEqual([0, 1, 2]);
    expect(provider.calls).toContain("restore:free");
    expect(queueAll).toHaveBeenCalled();
    expect(requests.map((r) => r.path)).toContain(
      "/e2ee/backup/keys?version=7",
    );
    await settle();
  });

  it("says NoBackup when the secret storage is empty, and wipes the input", async () => {
    const { client } = await installed();
    fakeServer(() => ({ status: 404 }));
    const input = bytes("secret words here");
    await expect(client.e2ee.backup.unlock(input)).rejects.toMatchObject({
      code: "NoBackup",
    });
    expect(input.every((b) => b === 0)).toBe(true);
  });

  it("turns the backup off: deletes the server's version with MFA, then locally", async () => {
    const { client, provider } = await installed();
    provider.backup.enabled = true;
    const requests = fakeServer((r) => {
      if (r.path === "/e2ee/backup/version")
        return { status: 200, body: { version: "7" } };
      if (r.path === "/e2ee/backup/version/7" && r.method === "DELETE")
        return r.headers[MFA_TICKET_HEADER] === "ticket"
          ? { status: 204 }
          : { status: 401, body: { type: "InvalidToken" } };
      return { status: 200, body: { messages: [] } };
    });

    // without a ticket nothing changes on this device
    await expect(client.e2ee.backup.turnOff()).rejects.toMatchObject({
      code: "MfaRequired",
    });
    expect(provider.backup.enabled).toBe(true);

    await client.e2ee.backup.turnOff("ticket");
    expect(provider.backup.enabled).toBe(false);
    const deletes = requests.filter((r) => r.method === "DELETE");
    expect(deletes.map((r) => r.path)).toEqual([
      "/e2ee/backup/version/7",
      "/e2ee/backup/version/7",
    ]);
    expect(deletes.at(-1)!.headers[MFA_TICKET_HEADER]).toBe("ticket");
  });

  it("turns off locally when the server has no backup or refuses", async () => {
    const { client, provider } = await installed();
    provider.backup.enabled = true;
    let refuse = false;
    const requests = fakeServer((r) =>
      r.method === "DELETE"
        ? { status: 500 }
        : refuse
          ? { status: 200, body: { version: "2" } }
          : { status: 404 },
    );

    await client.e2ee.backup.turnOff();
    expect(provider.backup.enabled).toBe(false);
    expect(requests.some((r) => r.method === "DELETE")).toBe(false);

    provider.backup.enabled = true;
    refuse = true;
    const error = await client.e2ee.backup.turnOff("t").catch((e) => e);
    expect(error).toBeInstanceOf(E2eeRequestError);
    expect((error as E2eeRequestError).status).toBe(500);
    expect(provider.backup.enabled).toBe(true);
  });

  it("passes the core's wrong-key errors through", async () => {
    const { client, provider } = await installed();
    provider.unlockThrows = "WrongRecoveryKey";
    fakeServer((r) =>
      r.path.endsWith("default_key")
        ? { status: 200, body: { key: "K" } }
        : { status: 200, body: {} },
    );
    await expect(
      client.e2ee.backup.unlock(bytes("EsTx")),
    ).rejects.toMatchObject({ code: "WrongRecoveryKey" });
  });
});

describe("key files and report (CR-21, CR-22)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("exports with the passphrase wiped afterwards", async () => {
    const { client, provider } = await installed();
    const passphrase = bytes("long enough passphrase");
    const file = await client.e2ee.exportKeys(passphrase, ["C1"]);
    expect(file.sessions).toBe(2);
    expect(file.data).toContain("C1");
    expect(passphrase.every((b) => b === 0)).toBe(true);
    expect(provider.secretsSeen).toEqual(["long enough passphrase"]);
  });

  it("imports and decrypts messages waiting for the imported keys", async () => {
    const { client, provider } = await installed();
    provider.importedKeys = [{ channelId: "C", sessionId: "S9" }];
    const onRoomKeys = vi.spyOn(client.e2ee.decryptor, "onRoomKeys");
    const result = await client.e2ee.importKeys("file", bytes("passphrase!"));
    expect(result.imported).toBe(1);
    expect(onRoomKeys).toHaveBeenCalledWith(["S9"]);
  });

  it("keeps a wrong passphrase apart from a bad file", async () => {
    const { client, provider } = await installed();
    provider.importThrows = "WrongPassphrase";
    const passphrase = bytes("passphrase!");
    await expect(
      client.e2ee.importKeys("file", passphrase),
    ).rejects.toMatchObject({ code: "WrongPassphrase" });
    expect(passphrase.every((b) => b === 0)).toBe(true);

    provider.importThrows = "InvalidKeyFile";
    await expect(
      client.e2ee.importKeys("x", bytes("passphrase!")),
    ).rejects.toMatchObject({ code: "InvalidKeyFile" });
  });

  it("returns the core's report", async () => {
    const { client } = await installed();
    expect(await client.e2ee.debugReport()).toContain("core_version");
  });
});

describe("sign-out (WEB-12)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("says whether the store was destroyed", async () => {
    const { client, provider } = await installed();
    expect(await client.e2ee.uninstall({ destroy: true })).toBe(true);
    expect(provider.destroyed).toBe(true);
    expect(await client.e2ee.uninstall({ destroy: true })).toBe(false);

    const second = await installed();
    second.provider.destroy = async () => {
      throw coreError("StoreLocked");
    };
    expect(await second.client.e2ee.uninstall({ destroy: true })).toBe(false);
  });

  it("retries a blocked store deletion, then gives up", async () => {
    let calls = 0;
    const destroy = async () => {
      if (++calls < 3) throw coreError("StoreLocked");
    };
    const done = retryWhileLocked(destroy, [10, 10, 10]);
    await vi.advanceTimersByTimeAsync(50);
    await done;
    expect(calls).toBe(3);

    calls = 0;
    const always = async () => {
      calls++;
      throw coreError("StoreLocked");
    };
    const failed = retryWhileLocked(always, [10]).catch((e) => e);
    await vi.advanceTimersByTimeAsync(50);
    expect(e2eeErrorCode(await failed)).toBe("StoreLocked");
    expect(calls).toBe(2);

    // other errors are not retried
    calls = 0;
    const other = retryWhileLocked(async () => {
      calls++;
      throw coreError("Store");
    }).catch((e) => e);
    expect(e2eeErrorCode(await other)).toBe("Store");
    expect(calls).toBe(1);
  });

  it("the adapter retries destroyStore and always terminates", async () => {
    let attempts = 0;
    const crypto = {
      close: vi.fn(async () => undefined),
      destroyStore: vi.fn(async () => {
        if (++attempts === 1) throw coreError("StoreLocked");
      }),
      terminate: vi.fn(),
    };
    const adapter = createStoatCryptoProvider(crypto as never, {
      userId: SELF,
      deviceId: "S",
      accountKey: "acc",
    });
    const done = adapter.destroy();
    await vi.advanceTimersByTimeAsync(200);
    await done;
    expect(crypto.destroyStore).toHaveBeenCalledTimes(2);
    expect(crypto.terminate).toHaveBeenCalledTimes(1);
  });
});
