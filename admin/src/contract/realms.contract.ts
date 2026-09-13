import { describe, expect, test } from "vitest";
import { createRealm, listRealms } from "@/services/realms";
import { keepAnswer, REALM } from "./answers";

describe("realms", () => {
  test("lists only the caller's own realm and creates another", async () => {
    const realms = await keepAnswer(listRealms);
    expect(realms.map((realm) => realm.realm_id)).toEqual([REALM]);
    await keepAnswer(createRealm, "contract-realm", "Contract realm", {
      userName: "contract-admin",
      email: "contract-admin@example.test",
    });
  });
});
