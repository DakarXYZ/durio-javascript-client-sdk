import { describe, expect, it } from "vitest";

import { Client } from "../Client.js";

const config = (january: boolean) =>
  ({
    features: {
      autumn: { enabled: true, url: "https://chat.example/autumn" },
      january: { enabled: january, url: "https://chat.example/january" },
    },
  }) as never;

describe("proxyFile (dur.io)", () => {
  it("proxies the web through January", () => {
    const client = new Client({}, config(true));
    expect(client.proxyFile("https://news.example/a.jpg")).toBe(
      "https://chat.example/january/proxy?url=https%3A%2F%2Fnews.example%2Fa.jpg",
    );
  });

  it("loads this server's files as they are", () => {
    const client = new Client({}, config(true));
    const own =
      "https://chat.example/autumn/attachments/01ARZ3NDEKTSV4RRFFQ69G5FAV";
    expect(client.proxyFile(own)).toBe(own);
    // a lookalike address is not the server's
    expect(
      client
        .proxyFile("https://chat.example/autumnx/a.jpg")
        ?.startsWith("https://chat.example/january/"),
    ).toBe(true);
  });

  it("leaves addresses alone without January", () => {
    const client = new Client({}, config(false));
    expect(client.proxyFile("https://news.example/a.jpg")).toBe(
      "https://news.example/a.jpg",
    );
  });
});
