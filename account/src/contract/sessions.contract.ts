import { describe, expect, test } from "vitest";
import { endLogin, endOtherLogins, listLogins, revokeGrant } from "@/services/sessions";
import { keepAnswer, REALM } from "./answers";

async function findLoginElsewhere() {
  const elsewhere = (await listLogins(REALM)).find((login) => !login.current);
  if (!elsewhere) throw new Error("the world holds no login elsewhere");
  return elsewhere;
}

describe("the person's logins", () => {
  test("lists the login the console rides, and one elsewhere with what an application holds", async () => {
    const logins = await keepAnswer(listLogins, REALM);
    expect(logins.filter((login) => login.current)).toHaveLength(1);
    expect((await findLoginElsewhere()).grants.length).toBeGreaterThan(0);
  });

  test("takes back what an application got elsewhere, then ends that login", async () => {
    const elsewhere = await findLoginElsewhere();
    const grant = elsewhere.grants[0];
    await revokeGrant(REALM, elsewhere.session_id, grant.client_id);
    await expect(
      revokeGrant(REALM, elsewhere.session_id, grant.client_id),
    ).rejects.toMatchObject({ status: 404, code: "auth.grant.not_found" });
    await endLogin(REALM, elsewhere.session_id);
    await expect(endLogin(REALM, elsewhere.session_id)).rejects.toMatchObject({
      status: 404,
      code: "auth.session.not_found",
    });
  });

  test("ends every other login and keeps the one it rides", async () => {
    const ended = await keepAnswer(endOtherLogins, REALM);
    expect(ended.ended_sessions).toBe(0);
    expect((await listLogins(REALM)).filter((login) => login.current)).toHaveLength(1);
  });
});
