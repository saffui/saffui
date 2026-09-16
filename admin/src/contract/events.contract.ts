import { describe, expect, test } from "vitest";
import { readEventHistory } from "@/services/events";
import { createUser, deleteUser } from "@/services/users";
import { keepAnswer, REALM } from "./answers";

/// The history is the realm's own, so its numbers keep moving while the rest of the
/// contract writes. Each read starts after the number the read before it answered.
async function readToTheEnd(): Promise<number> {
  let page = await keepAnswer(readEventHistory, REALM, 0, 500);
  let cursor = page.next_event_id ?? 0;
  for (let turned = 0; page.more && turned < 20; turned += 1) {
    page = await readEventHistory(REALM, cursor, 500);
    cursor = page.next_event_id ?? cursor;
  }
  return cursor;
}

describe("the realm's event history", () => {
  test("reads what happened after a number, and holds a person's creation", async () => {
    const cursor = await readToTheEnd();

    const born = await createUser(REALM, {
      user_name: "contract-history",
      email: "contract-history@example.test",
      enabled: true,
    });
    const after = await keepAnswer(readEventHistory, REALM, cursor, 500);

    expect(after.items.every((told) => told.event_id > cursor)).toBe(true);
    expect(
      after.items.some((told) => told.kind === "user.created" && told.user_id === born.user_id),
    ).toBe(true);

    await deleteUser(REALM, born.user_id);
  });
});
