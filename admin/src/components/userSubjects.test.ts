import { expect, it, vi } from "vitest";

const { listUsers } = vi.hoisted(() => ({ listUsers: vi.fn() }));
vi.mock("@/services/users", () => ({ listUsers }));

const { stepSuggestion, suggestionList, userSubjects, userSubjectValue } = await import(
  "./userSubjects"
);

function brief(user_name: string) {
  return {
    user_id: `id-${user_name}`,
    user_name,
    enabled: true,
    email: "",
    email_verified: false,
    given_name: null,
    family_name: null,
    phone_number: null,
    required_actions: [],
    created_at: null,
    origin: "local",
  };
}

it("searches realm users by typed username without loading the full directory", async () => {
  const alice = { user_id: "user-1", user_name: "alice" };
  listUsers.mockResolvedValueOnce({ items: [alice] });

  expect(await userSubjects("main", "  ali ")).toEqual([alice]);
  expect(listUsers).toHaveBeenCalledWith("main", 0, 25, { search: "ali" });
});

it("returns the subject shape expected by each endpoint", () => {
  const alice = { user_id: "user-1", user_name: "alice" };

  expect(userSubjectValue(alice, false)).toBe("alice");
  expect(userSubjectValue(alice, true)).toBe("user-1");
});

it("lands Down on the first suggestion and Up on the last when none is highlighted", () => {
  expect(stepSuggestion(-1, 1, 3)).toBe(0);
  expect(stepSuggestion(-1, -1, 3)).toBe(2);
  expect(stepSuggestion(2, 1, 3)).toBe(0);
  expect(stepSuggestion(0, -1, 3)).toBe(2);
  expect(stepSuggestion(-1, 1, 0)).toBe(-1);
});

it("drops the highlight when the suggestions are replaced", () => {
  const list = suggestionList();
  const [ada, bob, eve] = [brief("ada"), brief("bob"), brief("eve")];
  list.show([ada, bob, eve]);
  list.step(1);
  list.step(1);
  expect(list.highlighted()).toBe(bob);

  list.show([eve, ada]);
  expect(list.highlighted()).toBeUndefined();
  list.step(-1);
  expect(list.highlighted()).toBe(ada);
});
