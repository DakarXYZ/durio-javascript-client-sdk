// Payload v1 — what is inside the Megolm ciphertext (C7, C8, CR-19; schema in
// `stoat-crypto-proto/src/payload.rs`, fixtures in `stoat-crypto/fixtures/payload`). The
// core adds `type`/`room_id` around it and the padding, and checks it on decryption.
//
// Plaintext: nothing here may reach a log.

/** `EncryptedFile` v2 (key, IV, hash): secret, kept in memory only */
export type E2eeEncryptedFile = Record<string, unknown> & { v: string };

/** A thumbnail of an encrypted attachment: its own blob and key (C9) */
export interface E2eePayloadThumbnail {
  id: string;
  width: number;
  height: number;
  file: E2eeEncryptedFile;
}

/** An encrypted attachment (C8): the open message only names the autumn blob */
export interface E2eePayloadAttachment {
  /** autumn id of the encrypted blob */
  id: string;
  name: string;
  content_type: string;
  /** Plaintext size in bytes */
  size: number;
  /** Stoat file metadata (`{"type":"Image","width":…,"height":…}`) */
  metadata: Record<string, unknown>;
  spoiler?: boolean;
  file: E2eeEncryptedFile;
  thumbnail?: E2eePayloadThumbnail;
}

export interface E2eePayload {
  v: 1;
  content?: string;
  attachments?: E2eePayloadAttachment[];
  /** = the `nonce` of the send request (CR-19) */
  client_nonce: string;
  /** Id of the edited message, only in edits */
  edit_of?: string;
  /** 0 for the original, +1 for every edit (CR-19) */
  edit_seq: number;
  /** Replied message ids, the same as the open `replies` of the request */
  in_reply_to?: string[];
  /** Sender clock, ms (display only) */
  ts: number;
}

/**
 * Payload of a new message
 * @param content Text (Markdown)
 * @param nonce The send request's nonce
 * @param replies Open `replies` ids
 * @param attachments Encrypted attachments
 * @param ts Sender clock
 */
export function messagePayload(
  content: string | undefined,
  nonce: string,
  replies: string[] = [],
  attachments: E2eePayloadAttachment[] = [],
  ts = Date.now(),
): E2eePayload {
  return {
    v: 1,
    ...(content ? { content } : {}),
    ...(attachments.length ? { attachments } : {}),
    client_nonce: nonce,
    edit_seq: 0,
    ...(replies.length ? { in_reply_to: replies } : {}),
    ts,
  };
}

/**
 * Payload of an edit: the next `edit_seq` after the version shown, the same replies and
 * attachments (the server keeps the open ones; CR-19)
 * @param messageId Edited message
 * @param content New text
 * @param nonce Fresh nonce
 * @param previousEditSeq `edit_seq` of the version shown
 * @param replies Open `replies` of the message
 * @param attachments Attachments of the version shown
 * @param ts Sender clock
 */
export function editPayload(
  messageId: string,
  content: string,
  nonce: string,
  previousEditSeq: number,
  replies: string[] = [],
  attachments: E2eePayloadAttachment[] = [],
  ts = Date.now(),
): E2eePayload {
  return {
    ...messagePayload(content, nonce, replies, attachments, ts),
    edit_of: messageId,
    edit_seq: previousEditSeq + 1,
  };
}

/**
 * autumn ids for the open `attachments` of the request: files **and** thumbnails (C9)
 * @param payload Payload
 */
export function payloadFileIds(payload: E2eePayload): string[] {
  return (payload.attachments ?? []).flatMap((a) =>
    a.thumbnail ? [a.id, a.thumbnail.id] : [a.id],
  );
}

/**
 * Parse a decrypted payload (the core checked its version and files)
 * @param json Payload JSON
 * @returns Payload, or undefined when malformed
 */
export function parsePayload(json: string): E2eePayload | undefined {
  try {
    const value = JSON.parse(json) as E2eePayload;
    if (typeof value !== "object" || value === null) return;
    if (value.content !== undefined && typeof value.content !== "string")
      return;
    if (value.attachments !== undefined && !Array.isArray(value.attachments))
      return;
    if (typeof value.edit_seq !== "number") value.edit_seq = 0;
    return value;
  } catch {
    return;
  }
}

const RE_MENTION = /<@([0-9A-HJKMNP-TV-Z]{26})>/g;

/**
 * Users mentioned in a text: the server does not know who is mentioned in an encrypted
 * message (C10, Q16)
 * @param content Text
 */
export function mentionedUsers(content: string | undefined): string[] {
  if (!content) return [];
  return [...new Set(Array.from(content.matchAll(RE_MENTION), (m) => m[1]))];
}
