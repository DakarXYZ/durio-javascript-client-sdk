import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { E2eeSync, type E2eeSyncEvent } from "../requests.js";

import {
  FakeProvider,
  coreError,
  fakeServer,
  makeClient,
  settle,
} from "./fakes.js";

const toDevice = (n: number, offset = 0) => ({
  messages: Array.from({ length: n }, (_, i) => ({
    id: `M${offset + i}`,
    sender: "@x:stoat.invalid",
    sender_device: "D",
    type: "m.room.encrypted",
    content: {},
  })),
});

function setup(safetyIntervalMs = 0) {
  const client = makeClient();
  const provider = new FakeProvider();
  const sync = new E2eeSync(client, provider, { safetyIntervalMs });
  const events: E2eeSyncEvent[] = [];
  sync.onEvent((e) => events.push(e));
  return { client, provider, sync, events };
}

describe("E2eeSync (WEB-04)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("runs a request pass and marks it sent with the response body", async () => {
    const { provider, sync } = setup();
    provider.outgoing = [
      {
        id: "r1",
        kind: "KeysUpload",
        method: "POST",
        path: "/e2ee/keys/upload",
        body: "{}",
      },
    ];
    const requests = fakeServer((r) =>
      r.path === "/e2ee/keys/upload"
        ? { status: 200, body: { one_time_key_counts: {} } }
        : undefined,
    );

    sync.start();
    await settle();

    expect(requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      "POST /e2ee/keys/upload",
    ]);
    expect(requests[0].headers["X-Session-Token"]).toBe("token");
    expect(provider.sent).toEqual([
      { id: "r1", kind: "KeysUpload", body: '{"one_time_key_counts":{}}' },
    ]);
    sync.stop();
  });

  it("marks failures with the real status (0 without an answer) and backs off", async () => {
    const { provider, sync } = setup();
    provider.outgoing = [
      {
        id: "q1",
        kind: "KeysQuery",
        method: "POST",
        path: "/e2ee/keys/query",
        body: "{}",
      },
    ];

    let answer: "network" | number = "network";
    const requests = fakeServer(() =>
      answer === "network"
        ? "network"
        : { status: answer, body: answer === 429 ? { retry_after: 5000 } : {} },
    );

    sync.start();
    await settle();
    expect(provider.failed).toEqual([
      { id: "q1", kind: "KeysQuery", status: 0 },
    ]);
    expect(sync.state).toBe("backingOff");

    // backoff: 1 s, then 2 s; nothing in between
    answer = 503;
    await vi.advanceTimersByTimeAsync(900);
    expect(requests).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(provider.failed.at(-1)).toEqual({
      id: "q1",
      kind: "KeysQuery",
      status: 503,
    });

    // 429: waits for retry_after
    answer = 429;
    await vi.advanceTimersByTimeAsync(2_000);
    expect(provider.failed.at(-1)?.status).toBe(429);
    answer = 200;
    await vi.advanceTimersByTimeAsync(4_900);
    expect(provider.sent).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(200);
    expect(provider.sent).toHaveLength(1);
    sync.stop();
  });

  it("does not start a request twice while it is in flight", async () => {
    const { provider, sync } = setup();
    const request = {
      id: "c1",
      kind: "KeysClaim" as const,
      method: "POST",
      path: "/e2ee/keys/claim",
      body: "{}",
    };
    provider.outgoing = [request];
    provider.prepare = [request];

    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    fakeServer(() => {
      calls++;
      return { status: 200, body: {} };
    });
    const original = globalThis.fetch;
    vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
      await gate;
      return original(...args);
    });

    sync.start();
    const send = sync.prepareSend("C", ["A"]);
    await settle();
    release();
    await settle();
    await send;
    expect(calls).toBe(1);
    sync.stop();
  });

  it("reads the mailbox page by page, acks in chunks of 100, then stops", async () => {
    const { provider, sync } = setup();
    let page = 0;
    const requests = fakeServer((r) => {
      if (r.path.startsWith("/e2ee/to_device?"))
        return {
          status: 200,
          body: page++ === 0 ? toDevice(100) : toDevice(3, 100),
        };
      if (r.path === "/e2ee/to_device/ack") return { status: 204 };
      if (r.path === "/e2ee/keys/count")
        return { status: 200, body: { one_time_key_counts: {} } };
    });

    sync.start();
    sync.onToDevice();
    await settle();

    const acks = requests.filter((r) => r.path === "/e2ee/to_device/ack");
    expect(acks.map((r) => JSON.parse(r.body!).ids.length)).toEqual([100, 3]);
    expect(provider.acked).toHaveLength(103);
    expect(
      requests.filter((r) => r.path.startsWith("/e2ee/to_device?limit=100")),
    ).toHaveLength(2);
    sync.stop();
  });

  it("does not ack when the page could not be processed", async () => {
    const { provider, sync } = setup();
    provider.receiveToDevice = async () => {
      throw coreError("InvalidResponse");
    };
    const requests = fakeServer((r) =>
      r.path.startsWith("/e2ee/to_device?")
        ? { status: 200, body: toDevice(2) }
        : { status: 204 },
    );

    sync.start();
    sync.onToDevice();
    await settle();
    expect(requests.some((r) => r.path === "/e2ee/to_device/ack")).toBe(false);
    expect(sync.state).toBe("backingOff");
    sync.stop();
  });

  it("on Ready: reconnect, then always the mailbox and key counts (contract step 2)", async () => {
    const { provider, sync } = setup();
    const requests = fakeServer((r) =>
      r.path.startsWith("/e2ee/to_device?")
        ? { status: 200, body: toDevice(0) }
        : { status: 200, body: { one_time_key_counts: {} } },
    );

    sync.start();
    sync.onReady();
    await settle();

    expect(provider.calls).toEqual([
      "receiveReconnect",
      "receiveToDevice",
      "receiveOtkCounts",
    ]);
    expect(requests.map((r) => r.path)).toEqual([
      "/e2ee/to_device?limit=100",
      "/e2ee/keys/count",
    ]);
    sync.stop();
  });

  it("emits room keys from the mailbox", async () => {
    const { sync, events } = setup();
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
                  content: { channel: "C", session: "S9" },
                },
              ],
            },
          }
        : { status: 204 },
    );

    sync.start();
    sync.onToDevice();
    await settle();
    expect(events).toContainEqual({
      type: "roomKeys",
      keys: [{ channelId: "C", sessionId: "S9" }],
    });
    sync.stop();
  });

  it("reports a request the core dropped for good, and a 401", async () => {
    const { provider, sync, events } = setup();
    provider.outgoing = [
      {
        id: "t1",
        kind: "ToDevice",
        method: "PUT",
        path: "/e2ee/to_device/t1",
        body: "{}",
      },
    ];
    provider.failThrows = { t1: "RequestRejected" };
    let status = 400;
    fakeServer(() => ({ status, body: { type: "InvalidOperation" } }));

    sync.start();
    await settle();
    expect(events).toContainEqual({ type: "syncProblem", kind: "ToDevice" });

    status = 401;
    provider.outgoing = [
      {
        id: "u1",
        kind: "KeysUpload",
        method: "POST",
        path: "/e2ee/keys/upload",
        body: "{}",
      },
    ];
    sync.requestPass();
    await settle();
    expect(events).toContainEqual({ type: "unauthorized" });
    expect(sync.state).toBe("unauthorized");
  });

  it("runs the safety mailbox pass every 60 s", async () => {
    const { sync } = setup(60_000);
    const requests = fakeServer((r) =>
      r.path.startsWith("/e2ee/to_device?")
        ? { status: 200, body: toDevice(0) }
        : undefined,
    );

    sync.start();
    await settle();
    expect(requests).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(requests).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(requests).toHaveLength(2);
    sync.stop();
  });

  it("stops on a lost core (Panic)", async () => {
    const { provider, sync, events } = setup();
    provider.outgoingRequests = async () => {
      throw coreError("Panic");
    };
    fakeServer(() => undefined);

    sync.start();
    await settle();
    expect(events).toContainEqual({ type: "fatal", code: "Panic" });
    expect(sync.state).toBe("stopped");
  });
});
