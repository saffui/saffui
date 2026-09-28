import { describe, expect, test } from "vitest";
import type { JournalEnvelope } from "@/models/journal";
import { readJournalLine } from "./journalLine";

describe("a journal line", () => {
  test("reads a request as its request line, its answer and its trace", () => {
    expect(
      readJournalLine({
        kind: "admin.write",
        occurred_at: 1_790_000_000,
        actor: "ada",
        party: "saffui-console",
        method: "PUT",
        pattern: "/admin/realms/{realm}/theme",
        path: "/admin/realms/main/theme",
        status: 204,
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
      }),
    ).toEqual({
      actor: "ada",
      what: "PUT /admin/realms/main/theme",
      detail: "/admin/realms/{realm}/theme",
      status: 204,
      trace: "4bf92f3577b34da6a3ce929d0e0e4736",
    });
  });

  test("says a closed campaign in words, with no actor, answer or trace", () => {
    const line = readJournalLine({
      kind: "governance.campaign.closed",
      occurred_at: 1_790_000_000,
      campaign: "0f8a4c31-6b2e-4d59-9c11-2a7f5e8d3b40",
      report_digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      items: 3,
    });
    expect(line).toMatchObject({
      actor: null,
      detail: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      status: null,
      trace: null,
    });
    expect(line.what).not.toBe("journal-campaign-closed");
    expect(line.what).toContain("0f8a4c31-6b2e-4d59-9c11-2a7f5e8d3b40");
    expect(line.what).toContain("3");
  });

  test("names a kind this build does not know by that kind", () => {
    const newer: unknown = { kind: "governance.campaign.reopened", occurred_at: 1_790_000_000 };
    expect(readJournalLine(newer as JournalEnvelope)).toEqual({
      actor: null,
      what: "governance.campaign.reopened",
      detail: "",
      status: null,
      trace: null,
    });
  });
});
