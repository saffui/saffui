import { describe, expect, test } from "vitest";
import { previewAnswer } from "@/services/preview";
import type { TuplePage } from "@/models/authz";

describe("the realm's edges", () => {
  test("the preview world lists edges a page at a time", () => {
    const page = previewAnswer<TuplePage>("/admin/realms/main/rebac/tuples?first=0&max=25", "GET");
    expect(page.items.length).toBeGreaterThan(0);
    expect(page.items[0]).toHaveProperty("object_type");
    expect(page.first).toBe(0);
  });
});
