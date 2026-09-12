import { describe, expect, test } from "vitest";
import { previewAnswer } from "./preview";

describe("preview answers", () => {
  test("keeps directory import reports distinct from realm imports", () => {
    expect(
      previewAnswer("/admin/realms/main/federations/corp-ldap/import", "POST"),
    ).toEqual({ imported: 14, refreshed: 82, walked: 96 });
  });

  test("reflects complete realm imports and connector redelivery modes", () => {
    expect(
      previewAnswer("/admin/realms/import?as=north&administrator=ada", "POST", {}),
    ).toEqual({
      realm_id: "north",
      administrator: { user_name: "ada", password: "preview-import-password" },
    });
    expect(
      previewAnswer("/admin/realms/main/events/replay", "POST", { dry_run: true }),
    ).toMatchObject({ dry_run: true, would_deliver: 32 });
    expect(
      previewAnswer("/admin/realms/main/events/replay", "POST", { dry_run: false }),
    ).toMatchObject({ dry_run: false, delivered: 31, failed: 1 });
  });
});
