// Instance administration from the client (dur.io fork): an admin finds a user and ends
// their sessions, e.g. after a lost phone. The server decides who is an admin
// (`[api.admins] users` or `privileged`) and checks it on every call; this only wraps the
// `/admin` routes. Raw requests: the typed `API` throws a failed body without its status,
// and an older server without these routes answers 404 to all of them.
import type { AdminUser, SessionInfo } from "stoat-api";
import { decodeTime } from "ulid";

import type { Client } from "../Client.js";
import { errorType, isSuccess, rawRequest } from "../e2ee/http.js";

/** A failed admin call: HTTP status (0 = no response) and Stoat error type */
export class AdminRequestError extends Error {
  readonly status: number;
  readonly type: string | undefined;

  /**
   * Construct error
   * @param status HTTP status, 0 without a response
   * @param type `type` of the error body (`NotFound`, `NotPrivileged`, `IsBot` …)
   */
  constructor(status: number, type?: string) {
    super(
      status === 0
        ? "the server did not answer"
        : `admin request failed: ${status}${type ? ` ${type}` : ""}`,
    );
    this.name = "AdminRequestError";
    this.status = status;
    this.type = type;
  }
}

/** A session of a user as an admin sees it (no token) */
export interface AdminSession {
  id: string;
  name: string;
  /** Last activity, if the server knows it */
  lastSeen?: Date;
  createdAt: Date;
}

/**
 * Admin calls of the logged in account
 */
export class Admin {
  readonly #client: Client;

  /**
   * Construct the admin helper
   * @param client Client whose session runs the requests
   */
  constructor(client: Client) {
    this.#client = client;
  }

  /**
   * Whether the account is an admin of this instance; `false` on a server without the
   * admin routes (404) and when the account is not one
   * @throws AdminRequestError when the server failed or did not answer
   */
  async status(): Promise<boolean> {
    try {
      const body = await this.#request("GET", "/admin/@me");
      return (JSON.parse(body) as { admin?: unknown }).admin === true;
    } catch (e) {
      if (
        e instanceof AdminRequestError &&
        (e.status === 404 || e.status === 403)
      )
        return false;
      throw e;
    }
  }

  /**
   * Find a user by id or `username#discriminator` (a leading `@` is fine, case does not
   * matter)
   * @param query Id or username with discriminator
   * @returns The user, or `undefined` when there is none (404)
   */
  async findUser(query: string): Promise<AdminUser | undefined> {
    const trimmed = query.trim();
    if (!trimmed) return;

    try {
      return JSON.parse(
        await this.#request(
          "GET",
          `/admin/users?query=${encodeURIComponent(trimmed)}`,
        ),
      ) as AdminUser;
    } catch (e) {
      if (e instanceof AdminRequestError && e.status === 404) return;
      throw e;
    }
  }

  /**
   * Sessions of a user, newest first
   * @param userId User id
   * @throws AdminRequestError: 404 unknown user, 400 `IsBot`, 403 not an admin
   */
  async sessions(userId: string): Promise<AdminSession[]> {
    const list = JSON.parse(
      await this.#request(
        "GET",
        `/admin/users/${encodeURIComponent(userId)}/sessions`,
      ),
    ) as SessionInfo[];

    return list
      .map((session) => ({
        id: session._id,
        name: session.name,
        lastSeen: session.last_seen ? new Date(session.last_seen) : undefined,
        createdAt: createdAt(session._id),
      }))
      .sort((a, b) => +b.createdAt - +a.createdAt);
  }

  /**
   * End one session of a user: its E2EE device is removed and it is logged out
   * @param userId User id
   * @param sessionId Session id
   */
  async endSession(userId: string, sessionId: string): Promise<void> {
    await this.#request(
      "DELETE",
      `/admin/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`,
    );
  }

  /**
   * End every session of a user
   * @param userId User id
   */
  async endAllSessions(userId: string): Promise<void> {
    await this.#request(
      "DELETE",
      `/admin/users/${encodeURIComponent(userId)}/sessions`,
    );
  }

  async #request(method: string, path: string): Promise<string> {
    let response;
    try {
      response = await rawRequest(this.#client, method, path);
    } catch {
      throw new AdminRequestError(0);
    }

    if (!isSuccess(response.status))
      throw new AdminRequestError(response.status, errorType(response.body));
    return response.body;
  }
}

/**
 * Creation time encoded in a session id (a ULID)
 * @param id Session id
 */
function createdAt(id: string): Date {
  try {
    return new Date(decodeTime(id));
  } catch {
    return new Date(0);
  }
}
