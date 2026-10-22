import { ReactiveSet } from "@solid-primitives/set";
import type {
  Channel as APIChannel,
  ChannelEncryption,
  ThreadInfo,
} from "stoat-api";

import type { Client } from "../Client.js";
import { File } from "../classes/File.js";
import type { Merge } from "../lib/merge.js";

import type { Hydrate } from "./index.js";

export type HydratedChannel = {
  id: string;
  channelType: APIChannel["channel_type"];

  name: string;
  description?: string;
  icon?: File;

  active: boolean;
  typingIds: ReactiveSet<string>;
  recipientIds: ReactiveSet<string>;

  userId?: string;
  ownerId?: string;
  serverId?: string;

  permissions?: bigint;
  defaultPermissions?: { a: bigint; d: bigint };
  rolePermissions?: Record<string, { a: bigint; d: bigint }>;
  nsfw: boolean;
  slowmode: number;

  lastMessageId?: string;

  voice?: { maxUsers?: number };

  /** Encryption of a DM or group (dur.io); irreversible */
  encryption?: ChannelEncryption;

  /** Set when the channel is a thread of another one (dur.io) */
  thread?: ThreadInfo;

  /** Days without a message after which threads of the channel are deleted (dur.io) */
  threadAutoDelete?: number;
};

export const channelHydration: Hydrate<Merge<APIChannel>, HydratedChannel> = {
  keyMapping: {
    _id: "id",
    channel_type: "channelType",
    recipients: "recipientIds",
    user: "userId",
    owner: "ownerId",
    server: "serverId",
    default_permissions: "defaultPermissions",
    role_permissions: "rolePermissions",
    last_message_id: "lastMessageId",
    slowmode: "slowmode",
    thread_auto_delete: "threadAutoDelete",
  },
  functions: {
    id: (channel) => channel._id,
    channelType: (channel) => channel.channel_type,
    name: (channel) => channel.name,
    description: (channel) => channel.description!,
    icon: (channel, ctx) => new File(ctx as Client, channel.icon!),
    active: (channel) => channel.active || false,
    typingIds: () => new ReactiveSet(),
    recipientIds: (channel) => new ReactiveSet(channel.recipients),
    userId: (channel) => channel.user,
    ownerId: (channel) => channel.owner,
    serverId: (channel) => channel.server,
    permissions: (channel) => BigInt(channel.permissions!),
    defaultPermissions: (channel) => ({
      a: BigInt(channel.default_permissions?.a ?? 0),
      d: BigInt(channel.default_permissions?.d ?? 0),
    }),
    rolePermissions: (channel) =>
      Object.fromEntries(
        Object.entries(channel.role_permissions ?? {}).map(([k, v]) => [
          k,
          {
            a: BigInt(v.a),
            d: BigInt(v.d),
          },
        ]),
      ),
    nsfw: (channel) => channel.nsfw || false,
    lastMessageId: (channel) => channel.last_message_id!,
    slowmode: (channel) => channel.slowmode ?? 0,
    voice: (channel) =>
      !!channel.voice ||
      channel.channel_type === "DirectMessage" ||
      channel.channel_type === "Group"
        ? {
            maxUsers: channel.voice?.max_users || undefined,
          }
        : undefined,
    encryption: (channel) => channel.encryption ?? undefined,
    thread: (channel) => channel.thread ?? undefined!,
    threadAutoDelete: (channel) => channel.thread_auto_delete ?? undefined!,
  },
  initialHydration: () => ({
    typingIds: new ReactiveSet(),
    recipientIds: new ReactiveSet(),
  }),
};
