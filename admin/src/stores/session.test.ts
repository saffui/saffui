import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, test, vi } from "vitest";

const renew = vi.fn();
const login = vi.fn();
const logout = vi.fn();
const getUser = vi.fn();

vi.mock("@/services/users", () => ({ getUser }));

vi.mock("saffui-js", () => ({
  peek: (token: string) =>
    token === "identity" ? { sub: "person-id", preferred_username: "ada" } : { sub: "person-id" },
}));

vi.mock("@/services/auth", () => ({
  clientFor: () => ({ login, logout, renew }),
  rememberRealm: vi.fn(),
  rememberedRealm: () => "main",
  returnUri: () => "/login/return",
}));

const { useSession } = await import("./session");

beforeEach(() => {
  setActivePinia(createPinia());
  renew.mockReset();
  login.mockReset();
  logout.mockReset();
  getUser.mockReset();
});

describe("session identity", () => {
  test("resolves the account name when the ID token only names its ID", async () => {
    getUser.mockResolvedValue({ user_name: "admin" });
    const session = useSession();
    session.adopt("main", {
      access_token: "access",
      expires_in: 3600,
      token_type: "Bearer",
    });
    expect(session.displayName).toBe("");
    expect(session.userId).toBe("person-id");
    await vi.waitFor(() => expect(session.displayName).toBe("admin"));
    expect(getUser).toHaveBeenCalledWith("main", "person-id");
  });

  test("asks for and displays the username from the ID token", async () => {
    const session = useSession();
    await session.login("main");
    expect(login).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "openid profile admin",
        extra: {
          claims: JSON.stringify({
            id_token: { preferred_username: { essential: true } },
          }),
        },
      }),
    );

    session.adopt("main", {
      access_token: "access",
      id_token: "identity",
      expires_in: 3600,
      token_type: "Bearer",
    });
    expect(session.displayName).toBe("ada");
  });

  test("ends the server session before returning to sign-in", async () => {
    const session = useSession();
    session.adopt("main", {
      access_token: "access",
      id_token: "identity",
      expires_in: 3600,
      token_type: "Bearer",
    });
    await session.logout();
    expect(logout).toHaveBeenCalledWith("identity");
    expect(session.accessToken).toBe("");
  });

  test("keeps the displayed username when a renewal omits the ID token", async () => {
    const session = useSession();
    session.adopt("main", {
      access_token: "access",
      id_token: "identity",
      refresh_token: "refresh",
      expires_in: 3600,
      token_type: "Bearer",
    });
    session.adopt("main", {
      access_token: "renewed",
      refresh_token: "next",
      expires_in: 3600,
      token_type: "Bearer",
    });

    expect(session.idToken).toBe("identity");
    expect(session.displayName).toBe("ada");
  });
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
