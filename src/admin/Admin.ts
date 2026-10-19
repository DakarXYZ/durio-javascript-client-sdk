// Instance administration from the client (dur.io fork): an admin finds a user and ends
// their sessions, e.g. after a lost phone. The server decides who is an admin
// (`[api.admins] users` or `privileged`) and checks it on every call; this only wraps the
// `/admin` routes. Raw requests: the typed `API` throws a failed body without its status,
// and an older server without these routes answers 404 to all of them.
//
// Admin mode: every admin action needs an elevation of the current session, made with a
// validated MFA ticket (the account must have an authenticator app) and valid for about an
// hour. Without one the server answers 403 `AdminElevationRequired`.
import type {
  AdminInvite as APIAdminInvite,
  AdminUser,
  SessionInfo,
} from "stoat-api";
import { decodeTime } from "ulid";

import type { Client } from "../Client.js";
import type { MFATicket } from "../classes/MFA.js";
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

/** Error type: the session has no admin mode (or it ran out); elevate and retry */
export const ADMIN_ELEVATION_REQUIRED = "AdminElevationRequired";
/** Error type: admin mode needs an authenticator app (TOTP) on the account */
export const ADMIN_TOTP_REQUIRED = "TotpRequired";

/** Admin status of the logged in account */
export interface AdminStatus {
  admin: boolean;
  /** Admin mode of this session is on until then */
  elevatedUntil?: Date;
}

/** Lifetimes an invite link can have, in hours */
export const ADMIN_INVITE_TTL_HOURS = [1, 4, 12, 24] as const;

/** An account invite made by an admin, shared as `https://<domain>/join/<code>` */
export interface AdminInvite {
  code: string;
  expiresAt: Date;
  createdAt: Date;
  /** Works for any number of accounts until it expires, otherwise once */
  multiUse: boolean;
  /** Accounts created with it */
  uses: number;
  /** Id of the admin who made it */
  createdBy: string;
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
   * Whether the account is an admin of this instance and until when the admin mode of
   * this session lasts; not an admin on a server without the admin routes (404)
   * @throws AdminRequestError when the server failed or did not answer
   */
  async status(): Promise<AdminStatus> {
    let body;
    try {
      body = JSON.parse(await this.#request("GET", "/admin/@me")) as {
        admin?: unknown;
        elevated_until?: unknown;
      };
    } catch (e) {
      if (
        e instanceof AdminRequestError &&
        (e.status === 404 || e.status === 403)
      )
        return { admin: false };
      throw e;
    }

    const until =
      typeof body.elevated_until === "string"
        ? new Date(body.elevated_until)
        : undefined;
    return {
      admin: body.admin === true,
      elevatedUntil:
        until && !isNaN(+until) && +until > Date.now() ? until : undefined,
    };
  }

  /**
   * Turn admin mode on for this session (about an hour)
   * @param ticket Validated MFA ticket (consumed here)
   * @returns When admin mode ends
   * @throws AdminRequestError: 403 `TotpRequired` without an authenticator app
   */
  async elevate(ticket: MFATicket): Promise<Date> {
    ticket._consume();
    const body = JSON.parse(
      await this.#request("POST", "/admin/elevate", {
        "X-MFA-Ticket": ticket.token,
      }),
    ) as { expires_at?: unknown };

    const until = new Date(String(body.expires_at));
    return isNaN(+until) ? new Date(Date.now() + 60 * 60e3) : until;
  }

  /** End admin mode of this session */
  async endElevation(): Promise<void> {
    await this.#request("DELETE", "/admin/elevate");
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

  /**
   * Make an invite link for new accounts (needs admin mode)
   * @param ttlHours How long it works: 1, 4, 12 or 24 hours
   * @param multiUse Works for any number of accounts until it expires, otherwise once
   */
  async createInvite(
    ttlHours: (typeof ADMIN_INVITE_TTL_HOURS)[number],
    multiUse: boolean,
  ): Promise<AdminInvite> {
    return invite(
      JSON.parse(
        await this.#request("POST", "/admin/invites", undefined, {
          ttl_hours: ttlHours,
          multi_use: multiUse,
        }),
      ) as APIAdminInvite,
    );
  }

  /** Active invites made in the app, newest first */
  async invites(): Promise<AdminInvite[]> {
    return (
      JSON.parse(
        await this.#request("GET", "/admin/invites"),
      ) as APIAdminInvite[]
    ).map(invite);
  }

  /**
   * Revoke an invite
   * @param code Invite code
   * @throws AdminRequestError: 404 when it is gone already
   */
  async revokeInvite(code: string): Promise<void> {
    await this.#request("DELETE", `/admin/invites/${encodeURIComponent(code)}`);
  }

  async #request(
    method: string,
    path: string,
    headers?: Record<string, string>,
    body?: unknown,
  ): Promise<string> {
    let response;
    try {
      response = await rawRequest(
        this.#client,
        method,
        path,
        body === undefined ? undefined : JSON.stringify(body),
        headers,
      );
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

/**
 * An invite of the API with dates
 * @param data Invite
 */
function invite(data: APIAdminInvite): AdminInvite {
  return {
    code: data._id,
    expiresAt: new Date(data.expires_at),
    createdAt: new Date(data.created_at),
    multiUse: data.multi_use,
    uses: data.uses,
    createdBy: data.created_by,
  };
}
