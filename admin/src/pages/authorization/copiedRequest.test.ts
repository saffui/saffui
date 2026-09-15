import { expect, it } from "vitest";
import { composeCopiedRequest } from "./copiedRequest";

it("copies a token question as the token preview the console itself sends", () => {
  expect(
    composeCopiedRequest("token", "main", { user_id: "ada", client_id: "app", scope: "openid" }),
  ).toBe(
    'POST /admin/realms/main/preview-token\n{\n  "user_id": "ada",\n  "client_id": "app",\n  "scope": "openid"\n}',
  );
});

it("copies every other question as an evaluation, under the realm's encoded name", () => {
  expect(composeCopiedRequest("permission", "a b", { subject: "ada" }).split("\n")[0]).toBe(
    "POST /admin/realms/a%20b/authz/evaluate",
  );
});
