import { describe, expect, test } from "vitest";
import {
  clientMapperPickerRows,
  compositeRolePickerRows,
  organizationMemberPickerRows,
} from "./adminActionPickers";

describe("admin action pickers", () => {
  test("shows organization usernames and marks existing members", () => {
    const rows = organizationMemberPickerRows(
      [
        { user_id: "u-1", user_name: "ada" },
        { user_id: "u-2", user_name: "grace" },
      ],
      [{ user_id: "u-2" }],
    );

    expect(rows).toEqual([
      { id: "u-1", label: "ada", held: false },
      { id: "u-2", label: "grace", held: true },
    ]);
  });

  test("excludes the parent and direct composite children", () => {
    const roles = [
      { role_id: "r-parent", name: "admin", display_name: "Admin" },
      { role_id: "r-child", name: "reader", display_name: "Reader" },
      { role_id: "r-free", name: "writer", display_name: "Writer" },
    ];

    expect(compositeRolePickerRows(roles, "r-parent", [roles[1]])).toEqual([
      { id: "r-free", label: "Writer", held: false },
    ]);
  });

  test("excludes mappers already attached to the client", () => {
    const mappers = [
      { mapper_id: "m-1", name: "email" },
      { mapper_id: "m-2", name: "groups" },
    ];

    expect(clientMapperPickerRows(mappers, [mappers[0]])).toEqual([
      { id: "m-2", label: "groups", held: false },
    ]);
  });
});
