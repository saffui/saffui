import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, test, vi } from "vitest";

const renew = vi.fn();

vi.mock("saffui-js", () => ({
  peek: () => ({ sub: "ada" }),
}));

vi.mock("@/services/auth", () => ({
  clientFor: () => ({ renew }),
  rememberRealm: vi.fn(),
  rememberedRealm: () => "main",
  returnUri: () => "/login/return",
}));

const { useSession } = await import("./session");

beforeEach(() => {
  setActivePinia(createPinia());
  renew.mockReset();
});

describe("session refresh", () => {
  test("shares one renewal between concurrent callers", async () => {
    let settle!: (tokens: Record<string, unknown>) => void;
    renew.mockReturnValue(new Promise((resolve) => (settle = resolve)));

    const session = useSession();
    session.adopt("main", {
      access_token: "old",
      refresh_token: "refresh",
      expires_in: 3600,
      token_type: "Bearer",
    });
    session.expiresAt = Date.now() - 1;

    const first = session.bearer();
    const second = session.bearer();
    settle({
      access_token: "new",
      refresh_token: "next",
      expires_in: 3600,
      token_type: "Bearer",
    });

    await expect(Promise.all([first, second])).resolves.toEqual(["new", "new"]);
    expect(renew).toHaveBeenCalledOnce();
    expect(renew).toHaveBeenCalledWith("refresh");
  });
});
