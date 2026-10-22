import { Accessor, Setter, batch, createSignal } from "solid-js";

import { ReactiveMap } from "@solid-primitives/map";
import type { ReactiveSet } from "@solid-primitives/set";
import type {
  Channel as APIChannel,
  Member as APIMember,
  Message as APIMessage,
  User as APIUser,
  ChannelEncryption,
  DataCreateInvite,
  DataEditChannel,
  DataEditThread,
  DataMessageSearch,
  DataMessageSend,
  Invite,
  Override,
  ThreadInfo,
} from "stoat-api";
import type { APIRoutes } from "stoat-api";
import { decodeTime, ulid } from "ulid";

import { ChannelCollection } from "../collections/index.js";
import { sendWithRetry } from "../e2ee/outbox.js";
import type { E2eePayloadAttachment } from "../e2ee/payload.js";
import { E2eeError } from "../e2ee/provider.js";
import { UserSlowmodes } from "../events/v1.js";
import { hydrate } from "../hydration/index.js";
import {
  bitwiseAndEq,
  calculatePermission,
} from "../permissions/calculator.js";
import { Permission } from "../permissions/definitions.js";

import type { ChannelWebhook } from "./ChannelWebhook.js";
import type { File } from "./File.js";
import type { Message } from "./Message.js";
import type { Server } from "./Server.js";
import type { ServerMember } from "./ServerMember.js";
import type { User } from "./User.js";
import { VoiceParticipant, VoiceStatus } from "./VoiceParticipant.js";

/**
 * A thread nothing was said in for this long counts as archived (dur.io)
 */
export const THREAD_ARCHIVE_AFTER = 7 * 24 * 60 * 60 * 1000;

/**
 * Channel Class
 */
export class Channel {
  readonly #collection: ChannelCollection;
  readonly id: string;

  _typingTimers: Record<string, number> = {};

  voiceParticipants = new ReactiveMap<string, VoiceParticipant>();

  readonly userSlowmode: Accessor<UserSlowmodes | undefined>;
  readonly #setUserSlowmode: Setter<UserSlowmodes | undefined>;
  #slowmodeTimeout: NodeJS.Timeout | undefined;

  /**
   * Construct Channel
   * @param collection Collection
   * @param id Channel Id
   */
  constructor(collection: ChannelCollection, id: string) {
    this.#collection = collection;
    this.id = id;

    const [slowmode, setSlowmode] = createSignal<UserSlowmodes | undefined>();
    this.userSlowmode = slowmode;
    this.#setUserSlowmode = setSlowmode;
  }

  /**
   * Write to string as a channel mention
   * @returns Formatted String
   */
  toString(): string {
    return `<#${this.id}>`;
  }

  /**
   * Whether this object exists
   */
  get $exists(): boolean {
    return !!this.#collection.getUnderlyingObject(this.id).id;
  }

  /**
   * Time when this server was created
   */
  get createdAt(): Date {
    return new Date(decodeTime(this.id));
  }

  /**
   * Channel type
   */
  get type(): APIChannel["channel_type"] {
    return this.#collection.getUnderlyingObject(this.id).channelType;
  }

  /**
   * Absolute pathname to this channel in the client
   */
  get path(): string {
    if (this.serverId) {
      return `/server/${this.serverId}/channel/${this.id}`;
    } else {
      return `/channel/${this.id}`;
    }
  }

  /**
   * URL to this channel
   */
  get url(): string {
    return this.#collection.client.configuration?.app + this.path;
  }

  /**
   * Channel name
   */
  get name(): string {
    return this.#collection.getUnderlyingObject(this.id).name;
  }

  /**
   * Display name
   */
  get displayName(): string | undefined {
    return this.type === "SavedMessages"
      ? this.user?.username
      : this.type === "DirectMessage"
        ? this.recipient?.username
        : this.name;
  }

  /**
   * Channel description
   */
  get description(): string | undefined {
    return this.#collection.getUnderlyingObject(this.id).description;
  }

  /**
   * Channel icon
   */
  get icon(): File | undefined {
    return this.#collection.getUnderlyingObject(this.id).icon;
  }

  /**
   * Whether the conversation is active
   */
  get active(): boolean {
    return this.#collection.getUnderlyingObject(this.id).active;
  }

  /**
   * User ids of people currently typing in channel
   */
  get typingIds(): ReactiveSet<string> {
    return this.#collection.getUnderlyingObject(this.id).typingIds;
  }

  /**
   * Users currently trying in channel
   */
  get typing(): User[] {
    return [...this.typingIds.values()].map(
      (id) => this.#collection.client.users.get(id)!,
    );
  }

  /**
   * User ids of recipients of the group
   */
  get recipientIds(): ReactiveSet<string> {
    return this.#collection.getUnderlyingObject(this.id).recipientIds;
  }

  /**
   * Recipients of the group
   */
  get recipients(): User[] {
    return [
      ...this.#collection.getUnderlyingObject(this.id).recipientIds.values(),
    ].map((id) => this.#collection.client.users.get(id)!);
  }

  /**
   * Find recipient of this DM
   */
  get recipient(): User | undefined {
    return this.type === "DirectMessage"
      ? this.recipients?.find(
          (user) => user?.id !== this.#collection.client.user!.id,
        )
      : undefined;
  }

  /**
   * User ID
   */
  get userId(): string {
    return this.#collection.getUnderlyingObject(this.id).userId!;
  }

  /**
   * User this channel belongs to
   */
  get user(): User | undefined {
    return this.#collection.client.users.get(
      this.#collection.getUnderlyingObject(this.id).userId!,
    );
  }

  /**
   * Owner ID
   */
  get ownerId(): string {
    return this.#collection.getUnderlyingObject(this.id).ownerId!;
  }

  /**
   * Owner of the group
   */
  get owner(): User | undefined {
    return this.#collection.client.users.get(
      this.#collection.getUnderlyingObject(this.id).ownerId!,
    );
  }

  /**
   * Server ID
   */
  get serverId(): string {
    return this.#collection.getUnderlyingObject(this.id).serverId!;
  }

  /**
   * Server this channel is in
   */
  get server(): Server | undefined {
    return this.#collection.client.servers.get(
      this.#collection.getUnderlyingObject(this.id).serverId!,
    );
  }

  /**
   * Permissions allowed for users in this group
   */
  get permissions(): bigint | undefined {
    return this.#collection.getUnderlyingObject(this.id).permissions;
  }

  /**
   * Default permissions for this server channel (a thread has its channel's)
   */
  get defaultPermissions(): { a: bigint; d: bigint } | undefined {
    const parent = this.parent;
    if (parent) return parent.defaultPermissions;
    return this.#collection.getUnderlyingObject(this.id).defaultPermissions;
  }

  /**
   * Role permissions for this server channel (a thread has its channel's)
   */
  get rolePermissions(): Record<string, { a: bigint; d: bigint }> | undefined {
    const parent = this.parent;
    if (parent) return parent.rolePermissions;
    return this.#collection.getUnderlyingObject(this.id).rolePermissions;
  }

  /**
   * What makes this channel a thread, if it is one (dur.io)
   */
  get threadInfo(): ThreadInfo | undefined {
    return this.#collection.getUnderlyingObject(this.id).thread;
  }

  /**
   * Whether this channel is a thread of another channel (dur.io)
   */
  get isThread(): boolean {
    return !!this.threadInfo;
  }

  /**
   * The channel this thread belongs to (dur.io)
   */
  get parent(): Channel | undefined {
    const parentId = this.threadInfo?.parent;
    return parentId ? this.#collection.get(parentId) : undefined;
  }

  /**
   * The message in the parent channel this thread hangs off (dur.io)
   */
  get threadMessage(): Message | undefined {
    const messageId = this.threadInfo?.message;
    return messageId
      ? this.#collection.client.messages.get(messageId)
      : undefined;
  }

  /**
   * Number of messages in this thread (dur.io)
   */
  get messageCount(): number {
    return this.threadInfo?.message_count ?? 0;
  }

  /**
   * Whether this thread is archived: by hand, or nothing was said in it for a
   * week; a new message brings it back (dur.io)
   */
  get archived(): boolean {
    if (!this.threadInfo) return false;
    if (this.threadInfo.archived) return true;
    return Date.now() - this.updatedAt.getTime() > THREAD_ARCHIVE_AFTER;
  }

  /**
   * Whether this thread was closed: only its starter or `ManageChannel` may
   * write in it or open it again (dur.io)
   */
  get locked(): boolean {
    return !!this.threadInfo?.locked;
  }

  /**
   * Whether the current user may close, open, rename or archive this thread (dur.io)
   */
  get canManageThread(): boolean {
    if (!this.threadInfo) return false;
    return (
      this.threadInfo.owner === this.#collection.client.user?.id ||
      this.havePermission("ManageChannel")
    );
  }

  /**
   * Whether the current user may write in this thread right now (dur.io)
   */
  get canWriteInThread(): boolean {
    return !this.locked || this.canManageThread;
  }

  /**
   * Days without a message after which this channel's threads are deleted;
   * undefined keeps them forever (dur.io)
   */
  get threadAutoDelete(): number | undefined {
    return this.#collection.getUnderlyingObject(this.id).threadAutoDelete;
  }

  /**
   * The threads of this channel, most recently active first (dur.io)
   */
  get threads(): Channel[] {
    return this.#collection
      .filter((channel) => channel.threadInfo?.parent === this.id)
      .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
  }

  /**
   * Start a thread in this channel (dur.io)
   * @param name Thread name
   * @param messageId Message of this channel to start it from; without one the
   *  thread hangs off a new system message
   * @returns The thread
   */
  async createThread(name: string, messageId?: string): Promise<Channel> {
    const thread = await this.#collection.client.api.post(
      `/channels/${this.id as ""}/threads`,
      { name, message: messageId },
    );

    return this.#collection.getOrCreate(thread._id, thread, true);
  }

  /**
   * Fetch the threads of this channel, archived ones too (dur.io)
   * @returns Threads
   */
  async fetchThreads(): Promise<Channel[]> {
    const threads = await this.#collection.client.api.get(
      `/channels/${this.id as ""}/threads`,
    );

    return threads.map((thread) =>
      this.#collection.getOrCreate(thread._id, thread),
    );
  }

  /**
   * Rename, archive or close this thread: its starter, or `ManageChannel` (dur.io)
   * @param data Changes
   */
  async editThread(data: DataEditThread): Promise<void> {
    const channel = await this.#collection.client.api.patch(
      `/channels/${this.id as ""}/thread`,
      data,
    );

    this.#collection.updateUnderlyingObject(
      this.id,
      hydrate("channel", channel, this.#collection.client, false),
    );
  }

  /**
   * Encryption of a DM or group as the server reports it (dur.io)
   */
  get encryption(): ChannelEncryption | undefined {
    return this.#collection.getUnderlyingObject(this.id).encryption;
  }

  /**
   * Whether messages here are end-to-end encrypted: the server says so, or this client
   * saw it encrypted before (pinned locally, never undone; T18)
   */
  get isEncrypted(): boolean {
    return this.#collection.client.e2ee.isEncrypted(this);
  }

  /**
   * Pinned as encrypted, but the server now sends it without encryption (a warning)
   */
  get encryptionDowngraded(): boolean {
    return this.#collection.client.e2ee.isDowngraded(this);
  }

  /**
   * Turn on end-to-end encryption: irreversible (requires `ManageChannel`)
   * @requires `DirectMessage`, `Group`
   */
  async enableEncryption(): Promise<void> {
    await this.#collection.client.e2ee.enableEncryption(this);
  }

  /**
   * Whether this channel is marked as mature
   */
  get mature(): boolean {
    return this.#collection.getUnderlyingObject(this.id).nsfw;
  }

  /**
   * ID of the last message sent in this channel
   */
  get lastMessageId(): string | undefined {
    return this.#collection.getUnderlyingObject(this.id).lastMessageId;
  }

  /**
   * Last message sent in this channel
   */
  get lastMessage(): Message | undefined {
    return this.#collection.client.messages.get(this.lastMessageId!);
  }

  /**
   * Time when the last message was sent
   */
  get lastMessageAt(): Date | undefined {
    return this.lastMessageId && this.lastMessageId.length === 26
      ? new Date(decodeTime(this.lastMessageId))
      : undefined;
  }

  /**
   * Time when the channel was last updated (either created or a message was sent)
   */
  get updatedAt(): Date {
    return this.lastMessageAt ?? this.createdAt;
  }

  /**
   * Whether this channel is unread
   */
  get unread(): boolean {
    if (
      !this.lastMessageId ||
      this.type === "SavedMessages" ||
      this.#collection.client.options.channelExclusiveMuted(this)
    )
      return false;

    const unread = this.#collection.client.channelUnreads.for(this);
    return (
      (unread.lastMessageId ?? "0").localeCompare(this.lastMessageId) === -1 ||
      unread.messageMentionIds.size > 0
    );
  }

  /**
   * Whether this channel is muted
   */
  get muted(): boolean {
    return this.#collection.client.options.channelIsMuted(this);
  }

  /**
   * Get mentions in this channel for user.
   */
  get mentions(): ReactiveSet<string> | undefined {
    if (this.type === "SavedMessages") return undefined;

    return this.#collection.client.channelUnreads.get(this.id)
      ?.messageMentionIds;
  }

  /**
   * Whether this is a 'voice chats v2' channel
   *
   * NB. subject to change as vc(2) goes to production
   */
  get isVoice(): boolean {
    return (
      this.type === "DirectMessage" ||
      this.type === "Group" ||
      typeof this.#collection.getUnderlyingObject(this.id).voice === "object"
    );
  }

  /**
   * URL to the channel icon
   */
  get iconURL(): string | undefined {
    return this.icon?.createFileURL() ?? this.recipient?.avatarURL;
  }

  /**
   * URL to the animated channel icon
   */
  get animatedIconURL(): string | undefined {
    return this.icon?.createFileURL(true) ?? this.recipient?.animatedAvatarURL;
  }

  /**
   * Whether this channel may be hidden to some users
   */
  get potentiallyRestrictedChannel(): string | boolean | undefined {
    if (!this.serverId) return false;
    return (
      bitwiseAndEq(this.defaultPermissions?.d ?? 0n, Permission.ViewChannel) ||
      !bitwiseAndEq(this.server!.defaultPermissions, Permission.ViewChannel) ||
      [...(this.server?.roles.keys() ?? [])].find(
        (role) =>
          bitwiseAndEq(
            this.rolePermissions?.[role]?.d ?? 0n,
            Permission.ViewChannel,
          ) ||
          bitwiseAndEq(
            this.server?.roles.get(role)?.permissions.d ?? 0n,
            Permission.ViewChannel,
          ),
      )
    );
  }

  /**
   * Permission the currently authenticated user has against this channel
   */
  get permission(): bigint {
    return calculatePermission(this.#collection.client, this);
  }

  /**
   * Check whether we have a given permission in a channel
   * @param permission Permission Names
   * @returns Whether we have this permission
   */
  havePermission(...permission: (keyof typeof Permission)[]): boolean {
    return bitwiseAndEq(
      this.permission,
      ...permission.map((x) => Permission[x]),
    );
  }

  /**
   * Check whether we have at least one of the given permissions in a channel
   * @param permission Permission Names
   * @returns Whether we have one of the permissions
   */
  orPermission(...permission: (keyof typeof Permission)[]): boolean {
    return (
      permission.findIndex((x) =>
        bitwiseAndEq(this.permission, Permission[x]),
      ) !== -1
    );
  }

  /**
   * Fetch a channel's members.
   * @requires `Group`
   * @returns An array of the channel's members.
   */
  async fetchMembers(): Promise<User[]> {
    const members = await this.#collection.client.api.get(
      `/channels/${this.id as ""}/members`,
    );

    return batch(() =>
      members.map((user) =>
        this.#collection.client.users.getOrCreate(user._id, user),
      ),
    );
  }

  /**
   * Create a webhook
   * @param name Webhook name
   * @returns The newly-created webhook
   */
  async createWebhook(name: string): Promise<ChannelWebhook> {
    const webhook = await this.#collection.client.api.post(
      `/channels/${this.id as ""}/webhooks`,
      {
        name,
      },
    );

    return this.#collection.client.channelWebhooks.getOrCreate(
      webhook.id,
      webhook,
    );
  }

  /**
   * Fetch a channel's webhooks
   * @requires `TextChannel`, `Group`
   * @returns Webhooks
   */
  async fetchWebhooks(): Promise<ChannelWebhook[]> {
    const webhooks = await this.#collection.client.api.get(
      `/channels/${this.id as ""}/webhooks`,
    );

    return batch(() =>
      webhooks.map((webhook) =>
        this.#collection.client.channelWebhooks.getOrCreate(
          webhook.id,
          webhook,
        ),
      ),
    );
  }

  /**
   * Edit a channel
   * @param data Changes
   */
  async edit(data: DataEditChannel) {
    const channel = await this.#collection.client.api.patch(
      `/channels/${this.id as ""}`,
      data,
    );

    this.#collection.updateUnderlyingObject(
      this.id,
      hydrate("channel", channel, this.#collection.client, false),
    );
  }

  /**
   * Delete or leave a channel
   * @param leaveSilently Whether to not send a message on leave
   * @requires `DirectMessage`, `Group`, `TextChannel`
   */
  async delete(leaveSilently?: boolean): Promise<void> {
    await this.#collection.client.api.delete(`/channels/${this.id as ""}`, {
      leave_silently: leaveSilently,
    });

    if (this.type === "DirectMessage") {
      this.#collection.updateUnderlyingObject(this.id, "active", false);
      return;
    }

    this.#collection.delete(this.id);
  }

  /**
   * Add a user to a group
   * @param user_id ID of the target user
   * @requires `Group`
   */
  async addMember(user_id: string): Promise<void> {
    return await this.#collection.client.api.put(
      `/channels/${this.id as ""}/recipients/${user_id as ""}`,
    );
  }

  /**
   * Remove a user from a group
   * @param user_id ID of the target user
   * @requires `Group`
   */
  async removeMember(user_id: string): Promise<void> {
    return await this.#collection.client.api.delete(
      `/channels/${this.id as ""}/recipients/${user_id as ""}`,
    );
  }

  /**
   * Send a message
   * @param data Either the message as a string or message sending route data
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Sent message
   */
  async sendMessage(
    data: string | DataMessageSend,
    idempotencyKey: string = ulid(),
    options: {
      /** Encrypted attachments of an encrypted channel (dur.io, WEB-06) */
      attachments?: E2eePayloadAttachment[];
      /** An earlier attempt already sent this key: a duplicate answer means "sent" */
      resend?: boolean;
    } = {},
  ): Promise<Message> {
    const msg: DataMessageSend =
      typeof data === "string" ? { content: data } : data;

    // Mark as silent message (flags stay open in encrypted channels)
    if (msg.content?.startsWith("@silent ")) {
      msg.content = msg.content.substring(8);
      msg.flags ||= 1;
      msg.flags |= 1;
    }

    const client = this.#collection.client;
    // dur.io: encrypted channels never get plaintext; every send goes through the
    // outbox (same nonce and Idempotency-Key on retries, lookup by nonce; block 5E)
    const message = client.e2ee.isEncrypted(this)
      ? await client.e2ee.sendMessage(this, msg, idempotencyKey, options)
      : (
          await sendWithRetry(
            client,
            this.id,
            { ...msg, nonce: msg.nonce ?? idempotencyKey },
            {
              nonce: msg.nonce ?? idempotencyKey,
              idempotencyKey,
              resend: options.resend,
              selfId: client.user?.id,
            },
          )
        ).message;

    return this.#collection.client.messages.getOrCreate(
      message._id,
      message,
      true,
    );
  }

  /**
   * Fetch a message by its ID
   * @param messageId ID of the target message
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Message
   */
  async fetchMessage(messageId: string): Promise<Message> {
    const message = await this.#collection.client.api.get(
      `/channels/${this.id as ""}/messages/${messageId as ""}`,
    );

    return this.#collection.client.messages.getOrCreate(message._id, message);
  }

  /**
   * Fetch multiple messages from a channel
   * @param params Message fetching route data
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Messages
   */
  async fetchMessages(
    params?: Omit<
      (APIRoutes & {
        method: "get";
        path: "/channels/{target}/messages";
      })["params"],
      "include_users"
    >,
  ): Promise<Message[]> {
    const messages = (await this.#collection.client.api.get(
      `/channels/${this.id as ""}/messages`,
      { ...params },
    )) as APIMessage[];

    return messages.map((message) =>
      this.#collection.client.messages.getOrCreate(message._id, message),
    );
  }

  /**
   * Fetch multiple messages from a channel including the users that sent them
   * @param params Message fetching route data
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Object including messages and users
   */
  async fetchMessagesWithUsers(
    params?: Omit<
      (APIRoutes & {
        method: "get";
        path: "/channels/{target}/messages";
      })["params"],
      "include_users"
    >,
  ): Promise<{
    messages: Message[];
    users: User[];
    members: ServerMember[] | undefined;
  }> {
    const data = (await this.#collection.client.api.get(
      `/channels/${this.id as ""}/messages`,
      { ...params, include_users: true },
    )) as { messages: APIMessage[]; users: APIUser[]; members?: APIMember[] };

    return batch(() => ({
      messages: data.messages.map((message) =>
        this.#collection.client.messages.getOrCreate(message._id, message),
      ),
      users: data.users.map((user) =>
        this.#collection.client.users.getOrCreate(user._id, user),
      ),
      members: data.members?.map((member) =>
        this.#collection.client.serverMembers.getOrCreate(member._id, member),
      ),
    }));
  }

  /**
   * The server cannot search encrypted text (pins still work, C18)
   * @param params Search parameters
   */
  #assertSearchable(params: Omit<DataMessageSearch, "include_users">) {
    if (params.query && this.isEncrypted) {
      throw new E2eeError(
        "SearchUnavailableInEncryptedChannel",
        "search is not available in encrypted channels",
      );
    }
  }

  /**
   * Search for messages
   * @param params Message searching route data
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Messages
   */
  async search(
    params: Omit<DataMessageSearch, "include_users">,
  ): Promise<Message[]> {
    this.#assertSearchable(params);
    const messages = (await this.#collection.client.api.post(
      `/channels/${this.id as ""}/search`,
      params,
    )) as APIMessage[];

    return batch(() =>
      messages.map((message) =>
        this.#collection.client.messages.getOrCreate(message._id, message),
      ),
    );
  }

  /**
   * Search for messages including the users that sent them
   * @param params Message searching route data
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   * @returns Object including messages and users
   */
  async searchWithUsers(
    params: Omit<DataMessageSearch, "include_users">,
  ): Promise<{
    messages: Message[];
    users: User[];
    members: ServerMember[] | undefined;
  }> {
    this.#assertSearchable(params);
    const data = (await this.#collection.client.api.post(
      `/channels/${this.id as ""}/search`,
      {
        ...params,
        include_users: true,
      },
    )) as { messages: APIMessage[]; users: APIUser[]; members?: APIMember[] };

    return batch(() => ({
      messages: data.messages.map((message) =>
        this.#collection.client.messages.getOrCreate(message._id, message),
      ),
      users: data.users.map((user) =>
        this.#collection.client.users.getOrCreate(user._id, user),
      ),
      members: data.members?.map((member) =>
        this.#collection.client.serverMembers.getOrCreate(member._id, member),
      ),
    }));
  }

  /**
   * Delete many messages by their IDs
   * @param ids List of message IDs
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   */
  async deleteMessages(ids: string[]): Promise<void> {
    await this.#collection.client.api.delete(
      `/channels/${this.id as ""}/messages/bulk`,
      {
        ids,
      },
    );
  }

  /**
   * Create an invite to the channel
   * @requires `TextChannel`
   * @param options Invite options (API 0.16: maximum uses, expiry)
   * @returns Newly created invite code
   */
  async createInvite(options: DataCreateInvite = {}): Promise<Invite> {
    return await this.#collection.client.api.post(
      `/channels/${this.id as ""}/invites`,
      options,
    );
  }

  #ackTimeout?: number;
  #ackLimit?: number;
  #manuallyMarked?: boolean;

  /**
   * Mark a channel as read
   * @param message Last read message or its ID
   * @param skipRateLimiter Whether to skip the internal rate limiter
   * @param skipRequest For internal updates only
   * @param skipNextMarking For internal usage only
   * @requires `SavedMessages`, `DirectMessage`, `Group`, `TextChannel`
   */
  async ack(
    message?: Message | string,
    skipRateLimiter?: boolean,
    skipRequest?: boolean,
    skipNextMarking?: boolean,
  ): Promise<void> {
    if (!message && this.#manuallyMarked) {
      this.#manuallyMarked = false;
      return;
    }
    // Skip the next unread marking
    else if (skipNextMarking) {
      this.#manuallyMarked = true;
    }

    const lastMessageId =
      (typeof message === "string" ? message : message?.id) ??
      this.lastMessageId ??
      ulid();

    const channelUnread = this.#collection.client.channelUnreads.for(this);

    batch(() => {
      this.#collection.client.channelUnreads.updateUnderlyingObject(
        this.id,
        "lastMessageId",
        lastMessageId,
      );

      if (channelUnread.messageMentionIds.size) {
        channelUnread.messageMentionIds.clear();
      }
    });

    // Skip request if not needed
    if (skipRequest) return;

    /**
     * Send the actual acknowledgement request
     */
    const performAck = (): void => {
      this.#ackLimit = undefined;
      this.#collection.client.api.put(
        `/channels/${this.id}/ack/${lastMessageId as ""}`,
      );
    };

    if (skipRateLimiter) return performAck();

    clearTimeout(this.#ackTimeout);
    if (this.#ackLimit && +new Date() > this.#ackLimit) {
      performAck();
    }

    this.#ackTimeout = setTimeout(performAck, 1500) as unknown as number;

    if (!this.#ackLimit) {
      this.#ackLimit = +new Date() + 4e3;
    }
  }

  /**
   * Set role permissions
   * @param role_id Role Id, set to 'default' to affect all users
   * @param permissions Permission value
   * @requires `Group`, `TextChannel`
   */
  async setPermissions(
    role_id = "default",
    permissions: Override | number,
  ): Promise<APIChannel> {
    return await this.#collection.client.api.put(
      `/channels/${this.id as ""}/permissions/${role_id as ""}`,
      { permissions: permissions as never },
    );
  }

  /**
   * Get slowmode value for the channel
   */
  get slowmode(): number {
    return this.#collection.getUnderlyingObject(this.id).slowmode ?? 0;
  }

  /**
   * Join a call
   * @param node Target node
   * @param forceDisconnect Whether to disconnect existing call
   * @param recipients Ring targets
   * @returns LiveKit URL and Token
   */
  async joinCall(
    node?: string,
    forceDisconnect = true,
    recipients?: (User | string)[],
  ) {
    return await this.#collection.client.api.post(
      `/channels/${this.id as ""}/join_call`,
      {
        node,
        recipients: recipients?.map((entry) =>
          typeof entry === "string" ? entry : entry.id,
        ),
        force_disconnect: forceDisconnect,
      },
    );
  }

  /**
   * Start typing in this channel
   * @requires `DirectMessage`, `Group`, `TextChannel`
   */
  startTyping(): void {
    this.#collection.client.events.send({
      type: "BeginTyping",
      channel: this.id,
    });
  }

  /**
   * Stop typing in this channel
   * @requires `DirectMessage`, `Group`, `TextChannel`
   */
  stopTyping(): void {
    this.#collection.client.events.send({
      type: "EndTyping",
      channel: this.id,
    });
  }

  /**
   * The voice status of a channel. Screenshare supersedes video, video
   * supersedes voice, and voice supersedes none. This getter takes the highest
   * priority status from all participants in the channel.
   */
  get voiceStatus(): VoiceStatus {
    if (!this.isVoice || this.voiceParticipants.size === 0) {
      return "none";
    }

    let highest: VoiceStatus = "voice";
    for (const participant of this.voiceParticipants.values()) {
      const status = participant.voiceStatus;
      if (status === "screenshare") {
        return "screenshare";
      }
      if (status === "video") {
        highest = "video";
      }
    }

    return highest;
  }

  setUserSlowmode(slowmode: UserSlowmodes) {
    if (this.#slowmodeTimeout) {
      clearTimeout(this.#slowmodeTimeout);
    }

    this.#setUserSlowmode({ ...slowmode, receivedAt: Date.now() });

    this.#slowmodeTimeout = setTimeout(() => {
      this.#setUserSlowmode();
      this.#slowmodeTimeout = undefined;
      this.#collection.client.emit("userSlowmodes");
    }, slowmode.retry_after * 1000);
  }
}
