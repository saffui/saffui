import { describe, expect, test } from "vitest";
import { mailWrite, previewSms, smsTemplateIsValid, smsWrite } from "./messaging";

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
