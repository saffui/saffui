import { beforeEach, describe, expect, test, vi } from "vitest";

const held = vi.hoisted(() => ({ fresh: false, lost: [] as string[] }));

vi.mock("./session", () => ({
  readBearer: async () => "token-1",
  isFreshlyAdopted: () => held.fresh,
  loseSignIn: (why: string) => void held.lost.push(why),
}));

import { api, ApiError, StepUpNeeded } from "./http";

function stubFetch(answer: Response) {
  const fetched = vi.fn(async (_path: string, _init?: RequestInit) => answer);
  vi.stubGlobal("fetch", fetched);
  return fetched;
}

beforeEach(() => {
  vi.unstubAllGlobals();
  held.fresh = false;
  held.lost.length = 0;
});

describe("the account API door", () => {
  test("sends the bearer and reads JSON back", async () => {
    const fetched = stubFetch(Response.json({ preferred_username: "ada" }));
    await expect(api("/realms/main/account-api/v1/me")).resolves.toEqual({
      preferred_username: "ada",
    });
    const [path, init] = fetched.mock.calls[0];
    expect(path).toBe("/realms/main/account-api/v1/me");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer token-1");
  });

  test("sends a body as JSON, and reads nothing back from no content", async () => {
    const fetched = stubFetch(new Response(null, { status: 204 }));
    await expect(api("/x", { method: "PUT", json: { kept: 1 } })).resolves.toBeUndefined();
    const init = fetched.mock.calls[0][1];
    expect(new Headers(init?.headers).get("content-type")).toBe("application/json");
    expect(init?.body).toBe('{"kept":1}');
  });

  test("throws a refusal in the server's words and keeps the sign-in", async () => {
    stubFetch(
      Response.json(
        { error_code: "auth.session.not_found", message: "no such login" },
        { status: 404 },
      ),
    );
    await expect(api("/x")).rejects.toMatchObject({
      status: 404,
      code: "auth.session.not_found",
      message: "no such login",
    });
    expect(held.lost).toEqual([]);
  });

  test("loses a sign-in the server no longer takes, as ended", async () => {
    stubFetch(
      new Response(null, {
        status: 401,
        headers: { "www-authenticate": 'Bearer error="invalid_token"' },
      }),
    );
    await expect(api("/x")).rejects.toBeInstanceOf(ApiError);
    expect(held.lost).toEqual(["ended"]);
  });

  test("passes on the sign-in a change needs, and keeps the one held", async () => {
    stubFetch(
      new Response(null, {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer error="insufficient_user_authentication", error_description="sign in again, recently and as strongly as this account allows", acr_values="password", max_age="300"',
        },
      }),
    );
    const refused = await api("/x").catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(StepUpNeeded);
    expect((refused as StepUpNeeded).challenge).toMatchObject({ acrValues: "password", maxAge: 300 });
    expect(held.lost).toEqual([]);
  });

  test("loses a sign-in refused just after it was made, as refused", async () => {
    held.fresh = true;
    stubFetch(new Response(null, { status: 401 }));
    await expect(api("/x")).rejects.toMatchObject({ status: 401 });
    expect(held.lost).toEqual(["refused"]);
  });
});
