import { ulid } from "ulid";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MFATicket } from "../../classes/MFA.js";
import { OTHER, fakeServer, makeClient } from "../../e2ee/__tests__/fakes.js";
import { AdminRequestError } from "../Admin.js";

const error = (status: number, type: string) => ({ status, body: { type } });

describe("instance admin calls (dur.io)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads the admin status with the session token", async () => {
    const client = makeClient();
    const requests = fakeServer((r) =>
      r.path === "/admin/@me"
        ? { status: 200, body: { admin: true } }
        : undefined,
    );

    expect(await client.admin.status()).toEqual({
      admin: true,
      elevatedUntil: undefined,
    });
    const [key, value] = client.authenticationHeader;
    expect(requests[0].headers[key]).toBe(value);
  });

  it("is not an admin on a server without the routes, or when refused", async () => {
    const client = makeClient();
    fakeServer(() => undefined);
    expect(await client.admin.status()).toEqual({ admin: false });

    fakeServer(() => error(403, "NotPrivileged"));
    expect(await client.admin.status()).toEqual({ admin: false });

    fakeServer(() => ({ status: 200, body: { admin: false } }));
    expect((await client.admin.status()).admin).toBe(false);

    fakeServer(() => "network");
    await expect(client.admin.status()).rejects.toMatchObject({ status: 0 });
  });

  it("finds a user by name#discriminator, encoded; none is undefined", async () => {
    const client = makeClient();
    const user = { _id: OTHER, username: "Bob", discriminator: "0001" };
    const requests = fakeServer((r) =>
      r.path === "/admin/users?query=%40bob%230001"
        ? { status: 200, body: user }
        : error(404, "NotFound"),
    );

    expect(await client.admin.findUser(" @bob#0001 ")).toEqual(user);
    expect(await client.admin.findUser("nobody")).toBeUndefined();
    expect(await client.admin.findUser("  ")).toBeUndefined();
    expect(requests).toHaveLength(2);
  });

  it("does not hide a refusal behind 'not found'", async () => {
    const client = makeClient();
    fakeServer(() => error(403, "NotPrivileged"));
    const failure = await client.admin.findUser("bob#0001").catch((e) => e);
    expect(failure).toBeInstanceOf(AdminRequestError);
    expect(failure).toMatchObject({ status: 403, type: "NotPrivileged" });
  });

  it("lists sessions newest first with their last activity", async () => {
    const client = makeClient();
    const older = ulid(Date.UTC(2026, 0, 1));
    const newer = ulid(Date.UTC(2026, 5, 1));
    fakeServer((r) =>
      r.method === "GET" && r.path === `/admin/users/${OTHER}/sessions`
        ? {
            status: 200,
            body: [
              { _id: older, name: "Phone", last_seen: "2026-10-01T10:00:00Z" },
              { _id: newer, name: "Desktop" },
            ],
          }
        : undefined,
    );

    const sessions = await client.admin.sessions(OTHER);
    expect(sessions.map((s) => s.name)).toEqual(["Desktop", "Phone"]);
    expect(sessions[0].lastSeen).toBeUndefined();
    expect(sessions[1].lastSeen?.toISOString()).toBe(
      "2026-10-01T10:00:00.000Z",
    );
    expect(sessions[1].createdAt.getTime()).toBe(Date.UTC(2026, 0, 1));
  });

  it("passes the server's error type on (bots have no sessions)", async () => {
    const client = makeClient();
    fakeServer(() => error(400, "IsBot"));
    await expect(client.admin.sessions(OTHER)).rejects.toMatchObject({
      status: 400,
      type: "IsBot",
    });
  });

  it("ends one session or all of them", async () => {
    const client = makeClient();
    const requests = fakeServer((r) =>
      r.method === "DELETE" ? { status: 204 } : undefined,
    );

    await client.admin.endSession(OTHER, "S1");
    await client.admin.endAllSessions(OTHER);
    expect(requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      `DELETE /admin/users/${OTHER}/sessions/S1`,
      `DELETE /admin/users/${OTHER}/sessions`,
    ]);

    fakeServer(() => error(404, "NotFound"));
    await expect(client.admin.endSession(OTHER, "S2")).rejects.toMatchObject({
      status: 404,
    });
  });

  it("reads admin mode; an elapsed one is off", async () => {
    const client = makeClient();
    const later = new Date(Date.now() + 30 * 60e3).toISOString();
    fakeServer(() => ({
      status: 200,
      body: { admin: true, elevated_until: later },
    }));
    expect((await client.admin.status()).elevatedUntil?.toISOString()).toBe(
      later,
    );

    fakeServer(() => ({
      status: 200,
      body: { admin: true, elevated_until: "2020-01-01T00:00:00Z" },
    }));
    expect((await client.admin.status()).elevatedUntil).toBeUndefined();
  });

  it("turns admin mode on with an MFA ticket, once per ticket, and off", async () => {
    const client = makeClient();
    const requests = fakeServer((r) =>
      r.path === "/admin/elevate"
        ? r.method === "POST"
          ? { status: 200, body: { expires_at: "2026-10-19T13:00:00Z" } }
          : { status: 204 }
        : undefined,
    );
    const ticket = new MFATicket(
      client,
      {
        _id: "T",
        account_id: "A",
        token: "TOKEN",
        validated: true,
        authorised: false,
      } as never,
      (() => undefined) as never,
    );

    expect((await client.admin.elevate(ticket)).toISOString()).toBe(
      "2026-10-19T13:00:00.000Z",
    );
    expect(requests[0].headers["X-MFA-Ticket"]).toBe("TOKEN");
    await expect(client.admin.elevate(ticket)).rejects.toBeDefined();

    await client.admin.endElevation();
    expect(requests.map((r) => r.method)).toEqual(["POST", "DELETE"]);
  });

  it("says why admin mode is needed or refused", async () => {
    const client = makeClient();
    fakeServer(() => error(403, "AdminElevationRequired"));
    await expect(client.admin.findUser("bob#0001")).rejects.toMatchObject({
      status: 403,
      type: "AdminElevationRequired",
    });
  });
});
