import type { MailWrite } from "@/models/mail";
import type { SmsWrite } from "@/models/sms";

export interface MailDraft {
  host: string;
  port: number;
  from_address: string;
  from_name: string;
  reply_to: string;
  username: string;
  password: string;
  implicit_tls: boolean;
}

export interface SmsDraft {
  url: string;
  sender: string;
  token: string;
}

export type SmsTemplateKind = "sms_otp" | "verify_phone" | "ciba_doorbell";

export function mailWrite(draft: MailDraft): MailWrite {
  return {
    host: draft.host.trim(),
    port: draft.port,
    from_address: draft.from_address.trim(),
    from_name: draft.from_name.trim(),
    reply_to: draft.reply_to.trim() || null,
    implicit_tls: draft.implicit_tls,
    username: draft.username.trim() || null,
    password: draft.password || null,
  };
}

export function smsWrite(draft: SmsDraft): SmsWrite {
  return {
    url: draft.url.trim(),
    sender: draft.sender.trim(),
    token: draft.token || null,
  };
}

export function smsPlaceholder(kind: SmsTemplateKind): "{{code}}" | "{{link}}" {
  return kind === "ciba_doorbell" ? "{{link}}" : "{{code}}";
}

export function smsTemplateIsValid(kind: SmsTemplateKind, body: string): boolean {
  return body.trim() === "" || body.includes(smsPlaceholder(kind));
}

export function previewSms(kind: SmsTemplateKind, body: string): string {
  return body
    .replaceAll("{{code}}", "419 302")
    .replaceAll("{{link}}", "https://id.example/ciba/7f2a");
}
