import { describe, expect, test } from "vitest";
import { spnegoDraft, spnegoIsWritable, spnegoMutation } from "./spnegoForms";

describe("SPNEGO settings", () => {
  test("reads only the public service principal", () => {
    const draft = spnegoDraft({
      realm_id: "main",
      enabled: true,
      configs: { service_principal: { Str: "HTTP/id.example@EXAMPLE.ORG" } },
    });
    expect(draft.servicePrincipal).toBe("HTTP/id.example@EXAMPLE.ORG");
  });

  test("requires the backend's whole service/host@realm shape", () => {
    const draft = spnegoDraft(null);
    draft.servicePrincipal = "HTTP/id.example";
    expect(spnegoIsWritable(draft)).toBe(false);
    draft.servicePrincipal = "HTTP/id.example@EXAMPLE.ORG";
    expect(spnegoIsWritable(draft)).toBe(true);
    expect(spnegoMutation(draft).configs.service_principal).toEqual({
      Str: "HTTP/id.example@EXAMPLE.ORG",
    });
  });
});
