import { describe, expect, test } from "vitest";
import type { DirectoryRow } from "@/models/federation";
import {
  directoryDraft,
  directoryIsWritable,
  directoryMutation,
  emptyDirectoryDraft,
} from "./directoryForms";

describe("directory federation forms", () => {
  test("reads defaults and never echoes a hidden bind secret", () => {
    const draft = directoryDraft({
      alias: "corp",
      enabled: true,
      priority: 10,
      configs: {
        url: { Str: "ldaps://directory.example" },
        bind_dn: { Str: "cn=reader,dc=example" },
        users_dn: { Str: "ou=people,dc=example" },
      },
    } as DirectoryRow);
    expect(draft.bindPassword).toBe("");
    expect(draft.userFilter).toBe("(uid={username})");
    expect(directoryMutation(draft).configs).not.toHaveProperty("bind_password");
  });

  test("sends a replacement secret only when one was typed", () => {
    const draft = emptyDirectoryDraft();
    draft.bindPassword = " replacement with spaces ";
    expect(directoryMutation(draft).configs.bind_password).toEqual({
      Str: " replacement with spaces ",
    });
  });

  test("requires an explicit plaintext acknowledgement and a username mark", () => {
    const draft = emptyDirectoryDraft();
    draft.url = "ldap://directory.example";
    expect(directoryIsWritable(draft)).toBe(false);
    draft.dangerPlaintext = true;
    expect(directoryIsWritable(draft)).toBe(true);
    draft.userFilter = "(uid=somebody)";
    expect(directoryIsWritable(draft)).toBe(false);
  });
});
