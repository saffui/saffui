import { describe, expect, test } from "vitest";
import { createRealm, importRealm, listRealms } from "@/services/realms";
import { exportRealm } from "@/services/settings";
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

  test("imports the realm's configuration beside it under another name", async () => {
    const configuration = await exportRealm(REALM, false);
    await keepAnswer(importRealm, configuration, { as: "contract-imported" });
  });
});
