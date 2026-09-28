import { describe, expect, it } from "vitest";
import { mapperFieldKey, mapperKindKey } from "./mapperLabels";

describe("mapper labels", () => {
  it("gives known mapper kinds readable labels", () => {
    expect(mapperKindKey("oidc-usermodel-attribute-mapper")).toBe(
      "mapper-kind-user-attribute",
    );
    expect(mapperKindKey("oidc-audience-mapper")).toBe("mapper-kind-audience");
    expect(mapperKindKey("user-property")).toBe("mapper-kind-user-property");
  });

  it("keeps unknown server extensions visible", () => {
    expect(mapperKindKey("vendor-mapper")).toBe("mapper-kind-custom");
    expect(mapperFieldKey("vendor.option")).toBe("mapper-field-custom");
  });
});
