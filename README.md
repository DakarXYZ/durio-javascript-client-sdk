# durio-javascript-client-sdk — SDK клиента dur.io

**English summary.** `stoat.js` for the **dur.io** messenger: the TypeScript SDK the dur.io Windows client is built
on (HTTP, WebSocket events, reactive collections with Solid.js signals). The fork adds end-to-end encryption (beta)
of DMs and groups through a pluggable crypto provider, instance admin helpers (admin mode with 2FA, ending
sessions, invite links) and per-account crypto stores for several servers and accounts. Licensed under MIT.

SDK мессенджера **dur.io** на TypeScript: HTTP, WebSocket-события, реактивные коллекции (сигналы Solid.js). На нём
построен Windows-клиент ([durio-for-web](https://github.com/DakarXYZ/durio-for-web), сабмодуль
`packages/stoat.js`). Автор и владелец форка — DakarX ([GitHub DakarXYZ](https://github.com/DakarXYZ)).

Основано на [stoatchat/javascript-client-sdk](https://github.com/stoatchat/javascript-client-sdk). dur.io —
независимый форк и не связан с проектом Stoat; название и логотип Stoat — товарные знаки их владельцев. Имя пакета
`stoat.js` оставлено как в оригинале: это совместимость, а не бренд. В npm форк не публикуется.

## Что добавляет форк

**Сквозное шифрование (E2EE, бета) личных сообщений и групп** — `src/e2ee/`, `client.e2ee`.

- SDK не зависит от крипто-ядра: приложение открывает ядро
  [`@durio/stoat-crypto`](https://github.com/DakarXYZ/durio-crypt) (wasm в Web Worker, одно на аккаунт), оборачивает
  его `createStoatCryptoProvider` из точки входа `stoat.js/e2ee` и передаёт в `client.e2ee.install(provider)`.
  Ядро в сеть не ходит: исходящие запросы `/e2ee/*` выполняет SDK.
- Отправка, правка и получение сообщений в зашифрованных каналах (`Channel.sendMessage`, `Message.edit`,
  гидрация входящих), очередь расшифровки, outbox с повтором по тому же `nonce`, зашифрованные вложения и
  миниатюры (`encryptFile`, `decryptFile`), необратимое включение шифрования канала (`enableEncryption`).
- Устройства и доверие, сверка по эмодзи (SAS), бэкап ключей с ключом восстановления и его выключение, экспорт и
  импорт ключей в файл, отчёт диагностики без секретов.
- `accountKey` — имя хранилища ядра конкретного аккаунта: при выходе SDK удаляет именно его
  (`uninstall({ destroy: true })`).

**Администрирование сервера** — `src/admin/`, `client.admin`.

- `status()`, `elevate(ticket)`, `endElevation()` — режим администратора: сеанс получает права примерно на час
  после MFA-тикета с кодом приложения-аутентификатора (без TOTP в аккаунте — ошибка `TotpRequired`).
- `findUser(query)` (id или `имя#1234`), `sessions(userId)`, `endSession`, `endAllSessions`.
- `createInvite(ttlHours, multiUse)` (1, 4, 12 или 24 часа, одно- или многоразовое), `invites()`,
  `revokeInvite(code)`; ссылка на регистрацию — `https://<домен>/join/<код>`.

**Несколько серверов и аккаунтов.** Один `Client` — один аккаунт на одном сервере (`baseURL` из discovery), у
каждого — своё хранилище ядра (`accountKey`); данные разных серверов в SDK не смешиваются.

**Типы API** — из `@durio/stoat-api` (генерируется из OpenAPI нашего бэкенда, в for-web —
`packages/stoat-api`), подключён под старым именем `stoat-api`. Новые поля сервера появляются в SDK после
перегенерации этого пакета.

## Использование

Node.js 22.15+ (ES-модули) или Deno 2.2+.

```javascript
import { Client } from "stoat.js";

const client = new Client({ baseURL: "https://<сервер>/api" });

client.on("ready", () => console.info(`Вошли как ${client.user.username}`));
client.on("messageCreate", (message) => {
  if (message.content === "hello") message.channel.sendMessage("world");
});

client.loginBot("<токен бота>");
```

Все объекты реактивны и сразу работают в Solid.js:

```tsx
function MyApp() {
  return <h1>Имя: {client.user?.username ?? "[вход...]"}</h1>;
}
```

Сырые типы API реэкспортируются как `API` (`import { API } from "stoat.js"`).

## Разработка

Единственная рабочая копия SDK — сабмодуль `packages/stoat.js` в for-web: правка SDK = коммит здесь (на ветке
`durio/<этап>`, как в for-web) и коммит в for-web, передвигающий сабмодуль. Порядок — в README for-web.

```bash
pnpm install                 # из корня for-web (pnpm-воркспейс)
pnpm --filter stoat.js build      # tsc → lib/
pnpm --filter stoat.js typecheck
pnpm --filter stoat.js lint
pnpm --filter stoat.js test       # vitest: сценарии E2EE и администрирования с поддельным ядром
```

Тесты с настоящим wasm-ядром — `test:unit` клиента в for-web.

Ошибки и предложения — [issues](https://github.com/DakarXYZ/durio-javascript-client-sdk/issues).

## Лицензия

[MIT](LICENSE), как у оригинала. Copyright © DakarX для изменений dur.io; исходный код оригинала — его авторов.
