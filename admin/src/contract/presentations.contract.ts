import { describe, expect, test } from "vitest";
import { askPresentation, readPresentation } from "@/services/presentations";
import { rotateKey } from "@/services/settings";
import { keepAnswer, REALM } from "./answers";

describe("presentations", () => {
  // A request is signed with the realm's EdDSA key, which the planted world
  // does not hold.
  test("asks a wallet for a presentation, and reads where the request stands", async () => {
    await rotateKey(REALM, "EdDSA");
    const made = await keepAnswer(askPresentation, REALM, {
      credentials: [
        {
          id: "credential",
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1"] },
          claims: [{ path: ["given_name"] }],
        },
      ],
    });
    expect(made.uri.startsWith("openid4vp://authorize?")).toBe(true);
    expect(made.qr?.includes("<svg")).toBe(true);
    const standing = await keepAnswer(readPresentation, REALM, made.id);
    expect(standing.status).toBe("pending");
  });
});
