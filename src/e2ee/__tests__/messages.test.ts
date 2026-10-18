import { ulid } from "ulid";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MessageSendError } from "../outbox.js";
import { E2eeSendPreparationError } from "../requests.js";

import {
  FakeProvider,
  OTHER,
  SELF,
  emit,
  encryptedDm,
  fakeEnvelope,
  fakeServer,
  makeClient,
  settle,
  unb64,
} from "./fakes.js";

const payload = (content: string, extra: object = {}) => ({
  v: 1,
  content,
  client_nonce: ulid(),
  edit_seq: 0,
  ts: 1,
  ...extra,
});

const incoming = (channel: string, body: object, extra: object = {}) => ({
  type: "Message",
  _id: ulid(),
  channel,
  author: OTHER,
  content: "🔒 Encrypted message. Update the app.",
  encrypted: fakeEnvelope(channel, body),
  ...extra,
});

async function installed(options: { syncUnreads?: boolean } = {}) {
  const client = makeClient(options);
  const provider = new FakeProvider();
  await client.e2ee.install(provider, { sync: { safetyIntervalMs: 0 } });
  return { client, provider };
}

describe("receive (WEB-05)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("inserts pending at once without the placeholder, then the plaintext", async () => {
    const { client, provider } = await installed();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const created: string[] = [];
    client.on("messageCreate", (m) => created.push(m.content));

    const event = incoming(dm.id, payload("hello <@" + SELF + ">"));
    await emit(client, event);

    const message = client.messages.get(event._id)!;
    expect(created).toEqual([""]);
    expect(message.e2ee?.state).toBe("pending");
    expect(message.content).toBe("");

    await settle();
    expect(message.e2ee?.state).toBe("ok");
    expect(message.e2ee?.verification).toBe("Unverified");
    expect(message.content).toBe(`hello <@${SELF}>`);
    // mentions are computed locally (C10)
    expect(message.mentioned).toBe(true);
    expect(provider.decryptCalls).toBe(1);
  });

  it("decrypts a burst in one batch and keeps the order", async () => {
    const { client, provider } = await installed();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);

    const events = Array.from({ length: 5 }, (_, i) =>
      incoming(dm.id, payload(`m${i}`)),
    );
    for (const event of events) await emit(client, event);
    await settle();

    expect(provider.decryptCalls).toBe(1);
    expect(events.map((e) => client.messages.get(e._id)!.content)).toEqual([
      "m0",
      "m1",
      "m2",
      "m3",
      "m4",
    ]);
  });

  it("waits for a missing key and decrypts when it arrives", async () => {
    const { client, provider } = await installed();
    provider.missing.add("S7");
    fakeServer((r) =>
      r.path.startsWith("/e2ee/to_device?")
        ? {
            status: 200,
            body: {
              messages: [
                {
                  id: "K",
                  sender: "x",
                  sender_device: "d",
                  type: "m.room_key",
                  content: { channel: "C", session: "S7" },
                },
              ],
            },
          }
        : { status: 204 },
    );
    const dm = encryptedDm(client);
    const event = {
      ...incoming(dm.id, {}),
      encrypted: fakeEnvelope(dm.id, payload("late"), "S7"),
    };

    await emit(client, event);
    await settle();
    const message = client.messages.get(event._id)!;
    expect(message.e2ee?.state).toBe("missing_key");
    expect(message.content).toBe("");

    await emit(client, {
      type: "E2eeToDevice",
      id: "K",
      recipient_device: "x",
      sender: "x",
      sender_device: "d",
      event_type: "m.room.encrypted",
    });
    await settle(100);
    expect(message.e2ee?.state).toBe("ok");
    expect(message.content).toBe("late");
  });

  it("never shows a suspicious message as text", async () => {
    const { client, provider } = await installed();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const event = incoming(dm.id, payload("forged"));
    provider.suspicious.add(event._id);

    await emit(client, event);
    await settle();
    const message = client.messages.get(event._id)!;
    expect(message.e2ee?.state).toBe("suspicious");
    expect(message.content).toBe("");
  });

  it("stays pending without a core and decrypts once one is installed", async () => {
    const client = makeClient();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const event = incoming(dm.id, payload("queued"));
    await emit(client, event);
    await settle();
    expect(client.messages.get(event._id)!.e2ee?.state).toBe("pending");

    await client.e2ee.install(new FakeProvider(), {
      sync: { safetyIntervalMs: 0 },
    });
    await settle();
    expect(client.messages.get(event._id)!.content).toBe("queued");
  });

  it("says why when encryption is active in another window", async () => {
    const client = makeClient();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const event = incoming(dm.id, payload("x"));
    await emit(client, event);
    client.e2ee.setStatus("locked");
    await settle();
    expect(client.messages.get(event._id)!.e2ee).toEqual({
      state: "failed",
      reason: "locked",
    });
  });

  it("resolves whenDecrypted for notifications", async () => {
    const { client } = await installed();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const event = incoming(dm.id, payload("notify"));
    await emit(client, event);
    const message = client.messages.get(event._id)!;

    let done = false;
    void message.whenDecrypted().then(() => (done = true));
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toBe(false);
    await settle();
    expect(done).toBe(true);
    expect(message.content).toBe("notify");
  });

  it("applies an edit, keeps the shown text meanwhile, and ignores a stale replay", async () => {
    const { client, provider } = await installed();
    fakeServer(() => undefined);
    const dm = encryptedDm(client);
    const event = incoming(dm.id, payload("v0"));
    await emit(client, event);
    await settle();

    const edit = fakeEnvelope(
      dm.id,
      payload("v1", { edit_of: event._id, edit_seq: 1 }),
    );
    await emit(client, {
      type: "MessageUpdate",
      id: event._id,
      channel: dm.id,
      data: { encrypted: edit, content: "🔒 placeholder", edited: "now" },
    });

    const message = client.messages.get(event._id)!;
    expect(message.content).toBe("v0");
    await settle();
    expect(message.content).toBe("v1");

    // the server replays the original: the core says stale, the edit stays
    const decryptMany = provider.decryptMany.bind(provider);
    provider.decryptMany = async (m) =>
      (await decryptMany(m)).map((r) =>
        r.type === "Decrypted"
          ? { ...r, message: { ...r.message, staleEdit: true } }
          : r,
      );
    await emit(client, {
      type: "MessageUpdate",
      id: event._id,
      channel: dm.id,
      data: { encrypted: event.encrypted },
    });
    await settle();
    expect(message.content).toBe("v1");

    // reactions and pins change nothing encrypted
    await emit(client, {
      type: "MessageUpdate",
      id: event._id,
      channel: dm.id,
      data: { pinned: true },
    });
    expect(message.content).toBe("v1");
    expect(message.pinned).toBe(true);
  });
});

describe("send and edit (WEB-05)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("runs prepareSend, retries RoomKeyNotShared, sends only the envelope", async () => {
    const { client, provider } = await installed();
    const dm = encryptedDm(client);
    provider.prepare = [
      {
        id: "claim",
        kind: "KeysClaim",
        method: "POST",
        path: "/e2ee/keys/claim",
        body: "{}",
      },
    ];
    provider.notSharedOnce = 1;

    const requests = fakeServer((r) => {
      if (r.path === "/e2ee/keys/claim") return { status: 200, body: {} };
      if (r.method === "POST" && r.path === `/channels/${dm.id}/messages`) {
        const body = JSON.parse(r.body!);
        return {
          status: 200,
          body: {
            _id: ulid(),
            channel: dm.id,
            author: SELF,
            nonce: body.nonce,
            content: "🔒 placeholder",
            encrypted: body.encrypted,
          },
        };
      }
    });

    const sending = dm.sendMessage(
      { content: "@silent secret", replies: [{ id: "R", mention: false }] },
      "NONCE1",
    );
    await settle();
    const message = await sending;

    const post = requests.find((r) => r.path.endsWith("/messages"))!;
    const body = JSON.parse(post.body!);
    expect(post.headers["Idempotency-Key"]).toBe("NONCE1");
    expect(body.nonce).toBe("NONCE1");
    expect(body.content).toBeUndefined();
    expect(body.flags).toBe(1);
    expect(body.replies).toEqual([{ id: "R", mention: false }]);
    expect(Object.keys(body.encrypted).sort()).toEqual([
      "algorithm",
      "ciphertext",
      "device_id",
      "session_id",
      "v",
    ]);
    expect(JSON.stringify(body)).not.toContain("secret");
    expect(provider.sent.map((s) => s.id)).toEqual(["claim"]);
    expect(provider.members.get(dm.id)).toEqual([SELF, OTHER]);

    // the plaintext payload: @silent parsed before encryption, nonce inside
    const inner = JSON.parse(
      JSON.parse(unb64(body.encrypted.ciphertext)).payload,
    );
    expect(inner).toMatchObject({
      v: 1,
      content: "secret",
      client_nonce: "NONCE1",
      in_reply_to: ["R"],
      edit_seq: 0,
    });

    // own message: shown from the local payload, no round trip to the core
    await settle();
    expect(message.content).toBe("secret");
    expect(message.e2ee?.state).toBe("ok");
    expect(provider.decryptCalls).toBe(0);
  });

  it("retries the same body and key, then finds a probably-sent message by nonce", async () => {
    const { client, provider } = await installed();
    const dm = encryptedDm(client);
    const posts: { body: string; key: string }[] = [];
    let stored: object | undefined;

    fakeServer((r) => {
      if (r.method === "POST" && r.path === `/channels/${dm.id}/messages`) {
        posts.push({ body: r.body!, key: r.headers["Idempotency-Key"] });
        if (posts.length === 1) {
          // stored, but the answer is lost
          const body = JSON.parse(r.body!);
          stored = {
            _id: ulid(),
            channel: dm.id,
            author: SELF,
            nonce: body.nonce,
            encrypted: body.encrypted,
          };
          return "network";
        }

        return { status: 409, body: { type: "InvalidOperation" } };
      }

      if (
        r.method === "GET" &&
        r.path.startsWith(`/channels/${dm.id}/messages?`)
      )
        return { status: 200, body: [stored] };
    });

    const sending = dm.sendMessage("once", "NONCE2");
    await vi.advanceTimersByTimeAsync(5_000);
    const message = await sending;

    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual(posts[0]);
    expect(posts[0].key).toBe("NONCE2");
    expect(provider.encrypted).toHaveLength(1);
    expect(message.nonce).toBe("NONCE2");
  });

  it("gives up on a refusal without retrying", async () => {
    const { client } = await installed();
    const dm = encryptedDm(client);
    let posts = 0;
    fakeServer(() => {
      posts++;
      return { status: 400, body: { type: "EncryptedChannelViolation" } };
    });

    const sending = dm.sendMessage("no", "NONCE3");
    const result = expect(sending).rejects.toBeInstanceOf(MessageSendError);
    await settle();
    await result;
    expect(posts).toBe(1);
  });

  it("does not send when keys could not be shared", async () => {
    const { client, provider } = await installed();
    const dm = encryptedDm(client);
    provider.prepare = [
      {
        id: "claim",
        kind: "KeysClaim",
        method: "POST",
        path: "/e2ee/keys/claim",
        body: "{}",
      },
    ];
    const requests = fakeServer(() => ({ status: 503 }));

    const sending = dm.sendMessage("x", "NONCE4");
    const result = expect(sending).rejects.toBeInstanceOf(
      E2eeSendPreparationError,
    );
    await settle();
    await result;
    expect(requests.some((r) => r.path.endsWith("/messages"))).toBe(false);
  });

  it("refuses a DM partner without any E2EE device", async () => {
    const { client, provider } = await installed();
    const dm = encryptedDm(client);
    provider.devicesOf[OTHER] = [];
    fakeServer(() => undefined);

    await expect(dm.sendMessage("x", "N5")).rejects.toMatchObject({
      code: "NoRecipientDevices",
    });
  });

  it("encrypts an edit with the next edit_seq and the same attachments", async () => {
    const { client, provider } = await installed();
    const dm = encryptedDm(client);
    const original = {
      _id: ulid(),
      channel: dm.id,
      author: SELF,
      encrypted: fakeEnvelope(
        dm.id,
        payload("before", {
          edit_seq: 2,
          in_reply_to: ["R"],
          attachments: [
            {
              id: "F",
              name: "a.txt",
              content_type: "text/plain",
              size: 1,
              metadata: { type: "Text" },
              file: { v: "v2" },
            },
          ],
        }),
      ),
      replies: ["R"],
    };
    client.messages.getOrCreate(original._id, original as never);
    await settle();
    const message = client.messages.get(original._id)!;
    expect(message.attachments?.[0].filename).toBe("a.txt");
    expect(message.attachments?.[0].e2ee).toBe(true);
    expect(message.attachments?.[0].previewUrl).toBeUndefined();

    const requests = fakeServer((r) =>
      r.method === "PATCH"
        ? {
            status: 200,
            body: { ...original, encrypted: JSON.parse(r.body!).encrypted },
          }
        : undefined,
    );
    const editing = message.edit({ content: "after" });
    await settle();
    await editing;

    const patch = requests.find((r) => r.method === "PATCH")!;
    expect(patch.path).toBe(`/channels/${dm.id}/messages/${original._id}`);
    const body = JSON.parse(patch.body!);
    expect(Object.keys(body)).toEqual(["encrypted"]);
    const inner = JSON.parse(
      JSON.parse(unb64(body.encrypted.ciphertext)).payload,
    );
    expect(inner).toMatchObject({
      content: "after",
      edit_of: original._id,
      edit_seq: 3,
      in_reply_to: ["R"],
    });
    expect(inner.attachments[0].id).toBe("F");
    expect(provider.encrypted).toHaveLength(1);
  });

  it("blocks search with a query in an encrypted channel", async () => {
    const { client } = await installed();
    const dm = encryptedDm(client);
    fakeServer(() => undefined);
    await expect(dm.search({ query: "x" })).rejects.toMatchObject({
      code: "SearchUnavailableInEncryptedChannel",
    });
  });
});

describe("encrypted channel pinning (T18)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("pins, never unpins, warns on a downgrade and never sends plaintext", async () => {
    const client = makeClient();
    const pins: string[] = [];
    client.e2ee.channels.setStore({
      load: () => [],
      pin: (id) => pins.push(id),
    });

    const dm = encryptedDm(client);
    expect(dm.isEncrypted).toBe(true);
    expect(pins).toEqual([dm.id]);

    // the server drops the flag
    client.channels.updateUnderlyingObject(dm.id, "encryption", undefined);
    await emit(client, {
      type: "Ready",
      channels: [
        {
          _id: dm.id,
          channel_type: "DirectMessage",
          active: true,
          recipients: [SELF, OTHER],
        },
      ],
    });
    expect(dm.encryption).toBeUndefined();
    expect(dm.isEncrypted).toBe(true);
    expect(dm.encryptionDowngraded).toBe(true);

    // without a core nothing goes out
    const requests = fakeServer(() => ({ status: 200, body: {} }));
    await expect(dm.sendMessage("plain?", "N")).rejects.toMatchObject({
      code: "Unavailable",
    });
    expect(requests).toHaveLength(0);
  });

  it("flags a downgrade seen before the pins were loaded", async () => {
    const client = makeClient();
    const id = ulid();
    const dm = encryptedDm(client, id, false);
    expect(dm.isEncrypted).toBe(false);
    client.e2ee.setPinStore({ load: () => [id], pin: () => {} });
    expect(dm.isEncrypted).toBe(true);
    expect(dm.encryptionDowngraded).toBe(true);
  });

  it("restores pins of the account before the server says anything", async () => {
    const client = makeClient();
    const id = ulid();
    client.e2ee.channels.setStore({ load: () => [id], pin: () => {} });
    const dm = encryptedDm(client, id, false);
    expect(dm.isEncrypted).toBe(true);
  });

  it("leaves server channels and plain DMs alone", async () => {
    const client = makeClient();
    const dm = encryptedDm(client, ulid(), false);
    expect(dm.isEncrypted).toBe(false);

    const requests = fakeServer((r) =>
      r.method === "POST"
        ? {
            status: 200,
            body: { _id: ulid(), channel: dm.id, author: SELF, content: "hi" },
          }
        : undefined,
    );
    await dm.sendMessage("hi", "N6");
    expect(JSON.parse(requests[0].body!)).toMatchObject({
      content: "hi",
      nonce: "N6",
    });
  });

  it("sends member changes of an encrypted group to the core", async () => {
    const { client, provider } = await installed();
    fakeServer(() => ({ status: 200, body: { _id: OTHER, username: "o" } }));
    const id = ulid();
    client.channels.getOrCreate(id, {
      _id: id,
      channel_type: "Group",
      name: "g",
      owner: SELF,
      recipients: [SELF],
    } as never);

    await emit(client, {
      type: "ChannelUpdate",
      id,
      data: {
        encryption: {
          algorithm: "m.megolm.v1.aes-sha2",
          enabled_at: "x",
          enabled_by: SELF,
        },
      },
    });
    await settle();
    expect(provider.members.get(id)).toEqual([SELF]);

    await emit(client, { type: "ChannelGroupJoin", id, user: OTHER });
    await settle();
    expect(provider.members.get(id)).toEqual([SELF, OTHER]);
  });

  it("shows the encryption_enabled system message", async () => {
    const client = makeClient();
    const dm = encryptedDm(client);
    const id = ulid();
    await emit(client, {
      type: "Message",
      _id: id,
      channel: dm.id,
      author: "00000000000000000000000000",
      system: { type: "encryption_enabled", by: OTHER },
    });
    const sm = client.messages.get(id)!.systemMessage!;
    expect(sm.type).toBe("encryption_enabled");
    expect((sm as unknown as { byId: string }).byId).toBe(OTHER);
  });

  it("closes the core on uninstall and destroys it on logout", async () => {
    const { client, provider } = await installed();
    fakeServer(() => ({ status: 204 }));
    await client.logout();
    expect(provider.destroyed).toBe(true);
    expect(client.e2ee.status()).toBe("off");
  });
});
