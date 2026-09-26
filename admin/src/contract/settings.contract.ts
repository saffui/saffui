import { describe, expect, test } from "vitest";
import {
  disableRealmKey,
  exportRealm,
  forgetMail,
  forgetRealmTheme,
  forgetRegistrationSecret,
  forgetSms,
  forgetUssd,
  forgetSimSwap,
  forgetWhatsApp,
  getMail,
  getRealmKeys,
  getRealmSettings,
  getRealmTheme,
  getSms,
  getUssd,
  getSimSwap,
  getWhatsApp,
  importPartialRealm,
  keepFeatureWish,
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
  writeSimSwap,
  writeWhatsApp,
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

  test("keeps a WhatsApp business number, then forgets it", async () => {
    await writeWhatsApp(REALM, {
      phone_number_id: "106540352242922",
      template: "sign_in_code",
      languages: ["en_US", "fr"],
      token: "a-system-user-token",
    });
    const held = await keepAnswer(getWhatsApp, REALM);
    expect(held.languages).toEqual(["en_US", "fr"]);
    await forgetWhatsApp(REALM);
  });

  test("keeps a carrier to ask about SIM changes, then forgets it", async () => {
    await writeSimSwap(REALM, {
      client_id: "saffui-at-the-carrier",
      authorize_url: "https://carrier.example/bc-authorize",
      token_url: "https://carrier.example/token",
      check_url: "https://carrier.example/sim-swap/v2/check",
      max_age_hours: null,
      when_unanswered: "send",
    });
    const held = await keepAnswer(getSimSwap, REALM);
    expect(held.max_age_hours).toBe(72);
    expect(held.public_jwk).not.toHaveProperty("d");
    await forgetSimSwap(REALM);
  });

  test("lists features, page keys and sign-in events", async () => {
    const features = await keepAnswer(listFeatures);
    expect(features.length).toBeGreaterThan(0);
    const realmFeatures = await keepAnswer(listRealmFeatures, REALM);
    const switchable = realmFeatures.find((feature) => feature.reach === "realm");
    if (!switchable) throw new Error("no feature is the realm's to switch");
    await keepFeatureWish(REALM, switchable.slug, switchable.asked);
    await keepAnswer(listPageKeys, REALM);
    await keepAnswer(listSignInEvents, REALM, 0, 20);
  });

  test("exports the realm, previews importing it back, and imports it", async () => {
    const exported = await keepAnswer(exportRealm, REALM, false);
    await keepAnswer(previewPartialImport, REALM, exported, "skip");
    await keepAnswer(importPartialRealm, REALM, exported, "skip");
  });

  test("rotates the registration secret and forgets it", async () => {
    await keepAnswer(rotateRegistrationSecret, REALM);
    await forgetRegistrationSecret(REALM);
  });
});
