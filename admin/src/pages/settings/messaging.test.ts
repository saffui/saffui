import { describe, expect, test } from "vitest";
import {
  mailWrite,
  previewSms,
  simSwapWrite,
  smsTemplateIsValid,
  smsWrite,
  whatsAppWrite,
} from "./messaging";

describe("message gateway forms", () => {
  test("normalizes addresses without rewriting secrets", () => {
    expect(
      mailWrite({
        host: " smtp.example ",
        port: 587,
        from_address: " no-reply@example.test ",
        from_name: " Saffui ",
        reply_to: " ",
        username: " relay-user ",
        password: " secret with spaces ",
        implicit_tls: false,
      }),
    ).toEqual({
      host: "smtp.example",
      port: 587,
      from_address: "no-reply@example.test",
      from_name: "Saffui",
      reply_to: null,
      username: "relay-user",
      password: " secret with spaces ",
      implicit_tls: false,
    });

    expect(smsWrite({ url: " https://sms.example/send ", sender: " IAM ", token: " a b " })).toEqual({
      url: "https://sms.example/send",
      sender: "IAM",
      token: " a b ",
    });
  });

  test("leaves an existing credential alone when its field stays blank", () => {
    expect(
      mailWrite({
        host: "smtp.example",
        port: 465,
        from_address: "no-reply@example.test",
        from_name: "",
        reply_to: "",
        username: "relay-user",
        password: "",
        implicit_tls: true,
      }).password,
    ).toBeNull();
    expect(smsWrite({ url: "https://sms.example", sender: "IAM", token: "" }).token).toBeNull();
  });
});

describe("WhatsApp settings form", () => {
  test("keeps each language once in the order typed, and a blank token keeps the held one", () => {
    expect(
      whatsAppWrite({
        phone_number_id: " 106540352242922 ",
        template: " sign_in_code ",
        languages: " en_US, fr  en_US\npt_BR ",
        token: "",
      }),
    ).toEqual({
      phone_number_id: "106540352242922",
      template: "sign_in_code",
      languages: ["en_US", "fr", "pt_BR"],
      token: null,
    });
    expect(
      whatsAppWrite({ phone_number_id: "1", template: "t", languages: "fr", token: " a b " }).token,
    ).toBe(" a b ");
  });
});

describe("SIM swap settings form", () => {
  test("trims the endpoints and leaves a blank window to the server", () => {
    expect(
      simSwapWrite({
        client_id: " saffui ",
        authorize_url: " https://carrier.example/bc-authorize ",
        token_url: "https://carrier.example/token",
        check_url: "https://carrier.example/check ",
        max_age_hours: " ",
        when_unanswered: "hold",
      }),
    ).toEqual({
      client_id: "saffui",
      authorize_url: "https://carrier.example/bc-authorize",
      token_url: "https://carrier.example/token",
      check_url: "https://carrier.example/check",
      max_age_hours: null,
      when_unanswered: "hold",
    });
    expect(
      simSwapWrite({
        client_id: "c",
        authorize_url: "a",
        token_url: "t",
        check_url: "k",
        max_age_hours: 24,
        when_unanswered: "send",
      }).max_age_hours,
    ).toBe(24);
  });
});

describe("SMS wording", () => {
  test("requires the value consumed by each backend template kind", () => {
    expect(smsTemplateIsValid("sms_otp", "Code: {{code}}")).toBe(true);
    expect(smsTemplateIsValid("verify_phone", "No value")).toBe(false);
    expect(smsTemplateIsValid("ciba_doorbell", "Open {{link}}")).toBe(true);
    expect(smsTemplateIsValid("ciba_doorbell", "Open {{code}}")).toBe(false);
  });

  test("previews codes and doorbell links without touching other words", () => {
    expect(previewSms("sms_otp", "Code {{code}} for {{realm}}")).toBe(
      "Code 419 302 for {{realm}}",
    );
    expect(previewSms("ciba_doorbell", "Open {{link}}")).toContain("https://id.example/ciba/");
  });
});
