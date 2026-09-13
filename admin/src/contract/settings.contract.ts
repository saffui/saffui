import { describe, expect, test } from "vitest";
import {
  disableRealmKey,
  exportRealm,
  forgetMail,
  forgetRealmTheme,
  forgetRegistrationSecret,
  forgetSms,
  forgetUssd,
  getMail,
  getRealmKeys,
  getRealmSettings,
  getRealmTheme,
  getSms,
  getUssd,
  listFeatures,
  listPageKeys,
  listRealmFeatures,
  listSignInEvents,
  previewPartialImport,
  readRelayRefusals,
  readSmsToday,
  reshapeRealm,
  rotateKey,
  rotateRegistrationSecret,
  writeMail,
  writeRealmTheme,
  writeSms,
  writeUssd,
} from "@/services/settings";
import { keepAnswer, REALM } from "./answers";

describe("realm settings", () => {
  test("reads the settings and takes a reshape", async () => {
    await keepAnswer(getRealmSettings, REALM);
    const reshaped = await keepAnswer(
      reshapeRealm,
      REALM,
      { display_name: "Main under contract" },
      "realm",
    );
    expect(reshaped.display_name).toBe("Main under contract");
  });

  test("rotates a key twice and disables the one taken out of service", async () => {
    await rotateKey(REALM, "RS256");
    await rotateKey(REALM, "RS256");
    const keys = await keepAnswer(getRealmKeys, REALM);
    const retired = keys.signing.find((key) => key.algorithm === "RS256" && key.status !== "active");
    if (!retired) throw new Error("the second rotation left no RS256 key out of service");
    await disableRealmKey(REALM, retired.kid);
  });

  test("keeps a theme and forgets it", async () => {
    await writeRealmTheme(REALM, { light: { bg: "#ffffff" } });
    const theme = await keepAnswer(getRealmTheme, REALM);
    expect(theme?.light?.bg).toBe("#ffffff");
    await forgetRealmTheme(REALM);
  });

  test("keeps a mail relay and forgets it", async () => {
    await writeMail(REALM, {
      host: "smtp.example.test",
      port: 587,
      from_address: "noreply@example.test",
      from_name: "Saffui",
      reply_to: null,
      implicit_tls: false,
      username: null,
      password: null,
    });
    const mail = await keepAnswer(getMail, REALM);
    expect(mail).not.toBeNull();
    await keepAnswer(readRelayRefusals, REALM);
    await forgetMail(REALM);
  });

  test("keeps an SMS relay and a USSD secret, then forgets them", async () => {
    await writeSms(REALM, {
      url: "https://sms.example.test/send",
      sender: "Saffui",
      token: "a-relay-token",
    });
    await keepAnswer(getSms, REALM);
    await keepAnswer(readSmsToday, REALM);
    await forgetSms(REALM);
    await writeUssd(REALM, "a-ussd-secret-of-decent-length");
    await keepAnswer(getUssd, REALM);
    await forgetUssd(REALM);
  });

  test("lists features, page keys and sign-in events", async () => {
    const features = await keepAnswer(listFeatures);
    expect(features.length).toBeGreaterThan(0);
    const realmFeatures = await keepAnswer(listRealmFeatures, REALM);
    expect(realmFeatures.length).toBeGreaterThan(0);
    await keepAnswer(listPageKeys, REALM);
    await keepAnswer(listSignInEvents, REALM, 0, 20);
  });

  test("exports the realm and previews importing it back", async () => {
    const exported = await keepAnswer(exportRealm, REALM, false);
    await keepAnswer(previewPartialImport, REALM, exported, "skip");
  });

  test("rotates the registration secret and forgets it", async () => {
    await keepAnswer(rotateRegistrationSecret, REALM);
    await forgetRegistrationSecret(REALM);
  });
});
