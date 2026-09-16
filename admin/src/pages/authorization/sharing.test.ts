import { describe, expect, test } from "vitest";
import type { ProtectedServer, ResourceRow } from "@/models/authz";
import { composeShare, emptyShareDraft, shareIsReady, whyShareClosed } from "./sharing";

const OPEN: ProtectedServer = {
  server_id: "console",
  enforcement_mode: "enforcing",
  decision_strategy: "affirmative",
  remote_resource_management: false,
  user_managed_access: true,
};

const RESOURCE: ResourceRow = {
  resource_id: "r-1",
  name: "Folder",
  resource_type: "folder",
  resource_uris: [],
  resource_owner: "ada",
  user_managed_access: true,
};

describe("the share a resource is written with", () => {
  test("carries the relation and the subject as typed, without their spaces", () => {
    expect(
      composeShare({
        relation: " viewer ",
        subject_type: " user ",
        subject_id: " ada ",
        subject_relation: " member ",
      }),
    ).toEqual({
      relation: "viewer",
      subject_type: "user",
      subject_id: "ada",
      subject_relation: "member",
    });
  });

  test("leaves the subject relation empty where nothing is typed", () => {
    expect(composeShare({ ...emptyShareDraft(), relation: "viewer", subject_id: "ada" })).toEqual({
      relation: "viewer",
      subject_type: "user",
      subject_id: "ada",
      subject_relation: "",
    });
  });

  test("is ready only once it names a relation and a subject", () => {
    expect(shareIsReady({ ...emptyShareDraft(), relation: "viewer", subject_id: "ada" })).toBe(true);
    expect(shareIsReady({ ...emptyShareDraft(), relation: "viewer" })).toBe(false);
    expect(shareIsReady({ ...emptyShareDraft(), subject_id: "ada" })).toBe(false);
    expect(shareIsReady({ ...emptyShareDraft(), relation: "  ", subject_id: "ada" })).toBe(false);
  });
});

describe("why sharing is closed", () => {
  test("says the server first, since it is the ceiling", () => {
    expect(whyShareClosed({ ...OPEN, user_managed_access: false }, RESOURCE)).toBe(
      "authz-share-server-closed",
    );
    expect(whyShareClosed(null, RESOURCE)).toBe("authz-share-server-closed");
  });

  test("says the resource where the server is open and the resource is not", () => {
    expect(whyShareClosed(OPEN, { ...RESOURCE, user_managed_access: false })).toBe(
      "authz-share-resource-closed",
    );
    expect(whyShareClosed(OPEN, { ...RESOURCE, user_managed_access: undefined })).toBe(
      "authz-share-resource-closed",
    );
  });

  test("says nothing where both are open", () => {
    expect(whyShareClosed(OPEN, RESOURCE)).toBeNull();
  });
});
