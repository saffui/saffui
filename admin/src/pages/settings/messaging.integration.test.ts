import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { writeMail, writeSms } = await import("@/services/settings");
const { mailWrite, smsWrite } = await import("./messaging");

afterEach(() => vi.unstubAllGlobals());

describe("message settings write path", () => {
  test("carries normalized mail and SMS forms through the authenticated API", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    await writeMail(
      "north/east",
      mailWrite({
        host: " smtp.example ",
        port: 587,
        from_address: " no-reply@example.test ",
        from_name: " IAM ",
        reply_to: " ",
        username: " relay ",
        password: "",
        implicit_tls: false,
      }),
    );
    await writeSms(
      "north/east",
      smsWrite({ url: " https://sms.example/send ", sender: " IAM ", token: "" }),
    );

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/mail",
      expect.objectContaining({
        method: "PUT",
        headers: expect.any(Headers),
        body: JSON.stringify({
          host: "smtp.example",
          port: 587,
          from_address: "no-reply@example.test",
          from_name: "IAM",
          reply_to: null,
          implicit_tls: false,
          username: "relay",
          password: null,
        }),
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/sms",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ url: "https://sms.example/send", sender: "IAM", token: null }),
      }),
    );

    for (const [, init] of fetch.mock.calls) {
      expect((init.headers as Headers).get("authorization")).toBe("Bearer admin-token");
      expect((init.headers as Headers).get("content-type")).toBe("application/json");
    }
  });
});
