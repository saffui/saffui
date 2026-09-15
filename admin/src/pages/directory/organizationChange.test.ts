import { expect, it } from "vitest";
import type { OrganizationRow } from "@/models/directory";
import { composeOrganizationChange } from "./organizationChange";

const ACME: OrganizationRow = {
  org_id: "org-1",
  name: "acme",
  display_name: "Acme",
  description: "",
  enabled: false,
  domains: [],
  redirect_url: "https://acme.example/welcome",
  attributes: { region: { ListStr: ["west"] } },
};

it("writes what the drawer edits over everything it does not", () => {
  expect(
    composeOrganizationChange(ACME, {
      name: "acme-corp",
      display_name: " Acme Corp ",
      description: "Makers",
    }),
  ).toEqual({
    name: "acme-corp",
    display_name: "Acme Corp",
    description: "Makers",
    enabled: false,
    redirect_url: "https://acme.example/welcome",
    attributes: { region: { ListStr: ["west"] } },
  });
});

it("keeps the slug when its field is left blank", () => {
  expect(composeOrganizationChange(ACME, { name: "  ", display_name: "Acme", description: "" }).name).toBe(
    "acme",
  );
});
