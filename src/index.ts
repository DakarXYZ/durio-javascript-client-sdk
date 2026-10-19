export * as API from "stoat-api";
export { Client } from "./Client.js";
export type { ClientOptions, Session as PrivateSession } from "./Client.js";
export * from "./classes/index.js";
export * from "./collections/index.js";
export { ConnectionState, EventClient } from "./events/EventClient.js";
export { ProtocolV1 } from "./events/v1.js";
export { BotFlags } from "./hydration/bot.js";
export { ServerFlags } from "./hydration/server.js";
export { UserBadges, UserFlags } from "./hydration/user.js";
export * from "./lib/regex.js";
export * from "./permissions/definitions.js";
export { E2ee } from "./e2ee/E2ee.js";
export type { E2eeEvent, E2eeSasAction, E2eeStatus } from "./e2ee/E2ee.js";
export { E2eeBackup, MFA_TICKET_HEADER } from "./e2ee/backup.js";
export { E2eeRequestError } from "./e2ee/requests.js";
export type {
  E2eeFailureReason,
  E2eeMessageState,
  MessageE2ee,
} from "./e2ee/decryptor.js";
export type { E2eePinStore } from "./e2ee/channels.js";
export type {
  E2eeEncryptedFile,
  E2eePayloadAttachment,
  E2eePayloadThumbnail,
} from "./e2ee/payload.js";
export { MessageSendError } from "./e2ee/outbox.js";
export * from "./e2ee/provider.js";
export {
  ADMIN_ELEVATION_REQUIRED,
  ADMIN_TOTP_REQUIRED,
  Admin,
  AdminRequestError,
} from "./admin/Admin.js";
export type { AdminSession, AdminStatus } from "./admin/Admin.js";
