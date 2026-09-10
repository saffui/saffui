import { describe, expect, test } from "vitest";
import { previewAnswer } from "./preview";

describe("preview answers", () => {
  test("keeps directory import reports distinct from realm imports", () => {
    expect(
      previewAnswer("/admin/realms/main/federations/corp-ldap/import", "POST"),
    ).toEqual({ imported: 14, refreshed: 82, walked: 96 });
  });
});
