import { expect, it, vi } from "vitest";

const { listUsers } = vi.hoisted(() => ({ listUsers: vi.fn() }));
vi.mock("@/services/users", () => ({ listUsers }));

const { userSubjects } = await import("./userSubjects");

it("searches realm users by typed username without loading the full directory", async () => {
  const alice = { user_id: "user-1", user_name: "alice" };
  listUsers.mockResolvedValueOnce({ items: [alice] });

  expect(await userSubjects("main", "  ali ")).toEqual([alice]);
  expect(listUsers).toHaveBeenCalledWith("main", 0, 25, { search: "ali" });
});
