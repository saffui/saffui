import { describe, expect, test } from "vitest";
import { composeProfileChange } from "./profileChange";

const ADA = {
  user_name: " ada ",
  email: "",
  given_name: "Ada",
  family_name: "",
  phone_number: "",
  enabled: false,
};

describe("the profile the overview saves", () => {
  test("writes the fields as typed, a blank one left out", () => {
    expect(composeProfileChange(ADA)).toEqual({
      user_name: "ada",
      email: undefined,
      given_name: "Ada",
      family_name: undefined,
      phone_number: undefined,
      enabled: false,
    });
    expect(composeProfileChange({ ...ADA, user_name: "  " }).user_name).toBeUndefined();
  });

  test("never carries the person's required actions", () => {
    expect("required_actions" in composeProfileChange(ADA)).toBe(false);
  });
});
