<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import PageTabs from "@/components/PageTabs.vue";
import AppIcon from "@/components/AppIcon.vue";
import DangerDialog from "@/components/DangerDialog.vue";
import AppToggle from "@/components/AppToggle.vue";
import { useRouter } from "vue-router";
import {
  forgetMail,
  forgetSms,
  forgetUssd,
  forgetRegistrationSecret,
  getMail,
  getSms,
  getUssd,
  getRealmSettings,
  exportRealm,
  importPartialRealm,
  previewPartialImport,
  keepFeatureWish,
  listRealmFeatures,
  lookAtRelay,
  readSmsToday,
  readRelayRefusals,
  reshapeRealm,
  rotateRegistrationSecret,
  sendTestMail,
  sendTestSms,
  writeMail,
  writeSms,
  writeUssd,
} from "@/services/settings";
import type { ImportCollisionPolicy, PartialImportReport } from "@/services/settings";
import { deleteRealm } from "@/services/realms";
import { countOf } from "@/services/overview";
import { toastOk } from "@/services/toasts";
import { useSession } from "@/stores/session";
import type { RealmFeature } from "@/models/feature";
import { ApiError } from "@/services/http";
import type { MailBrief, MailRefusal, RelayReport } from "@/models/mail";
import type { SmsBrief, SmsToday } from "@/models/sms";
import { OTP_DEFAULTS, OWASP_HASHING } from "@/models/realm";
import type { MailTemplate, PasswordPolicy, RealmSettings, RealmUpdate } from "@/models/realm";
import { JURISDICTIONS } from "@/services/compliance";
import {
  mailWrite,
  previewSms,
  smsPlaceholder,
  smsTemplateIsValid,
  smsWrite,
} from "./messaging";
import { localeMutation, localeSelection, toggleLocale } from "./localizationForm";
import { sessionSettingsChanges, tokenSettingsChanges } from "./realmSettingsChanges";

/// The deck's boards, in the deck's order. "User profile" is drawn there too
/// and is not here: a declarative user profile is a server feature this build
/// does not carry, and a tab that writes nowhere is worse than a missing one.
const GROUPS = [
  "general",
  "login",
  "sessions",
  "tokens",
  "security",
  "credentials",
  "localization",
  "email",
  "phone",
  "features",
] as const;

/// What the build's hosted pages speak; mirrors `i18n::TONGUES` in
/// crates/server. The realm narrows this list, never widens it.
const TONGUES = ["en", "fr"] as const;
type Group = (typeof GROUPS)[number];

/// The third member says whether the engine reads the flag today. A switch
/// the server stores but nothing enforces yet wears it plainly, instead of
/// promising behaviour the build does not have.
const LOGIN_TOGGLES = [
  ["registration_allowed", "settings-self-registration"],
  ["register_email_as_username", "settings-email-as-username"],
  ["verify_email", "settings-verify-email"],
  ["login_with_email_allowed", "settings-login-with-email"],
  ["duplicated_email_allowed", "settings-duplicated-email"],
  ["edit_user_name_allowed", "settings-edit-username"],
  ["reset_password_allowed", "settings-reset-password"],
] as const;

const route = useRoute();
const router = useRouter();
const session = useSession();
const realm = computed(() => String(route.params.realm));
/// The realm this session's own token was minted by; the one realm that
/// cannot be deleted from here.
const home = computed(() => session.realm);
const group = ref<Group>("general");
/// Which groups hold edits the server has not seen. Cleared on adopt, since
/// adopting resets every draft to what the server kept.
const dirtyGroups = ref<Record<string, boolean>>({});
function markDirty() {
  dirtyGroups.value = { ...dirtyGroups.value, [group.value]: true };
}
const settings = ref<RealmSettings | null>(null);
const mail = ref<MailBrief | null>(null);
const sms = ref<SmsBrief | null>(null);
const ussdHeld = ref(false);
const failed = ref("");
const exporting = ref(false);
const importing = ref(false);
const applyingImport = ref(false);
const importFileName = ref("");
const importDocument = ref<Record<string, unknown> | null>(null);
const importReport = ref<PartialImportReport | null>(null);
const importError = ref("");
const importCollision = ref<ImportCollisionPolicy>("fail");
let importPreviewSequence = 0;

/// The editable copy the forms bind to; adopting a settings document resets
/// it, so a save reflects what the server actually kept.
const draft = ref({
  display_name: "",
  enabled: true,
  agent_exchange_enabled: false,
  registration_allowed: false,
  events_enabled: false,
  register_email_as_username: false,
  verify_email: false,
  login_with_email_allowed: false,
  duplicated_email_allowed: false,
  edit_user_name_allowed: false,
  reset_password_allowed: false,
  remember_me: false,
  client_registration: "disabled" as "disabled" | "open" | "protected",
  bounds_max_clients: "" as string | number,
  bounds_requires_consent: false,
  bounds_trusted_hosts: "",
  access_token_lifespan: "" as string | number,
  refresh_token_lifespan: "" as string | number,
  session_max_lifespan: 0 as string | number,
  access_code_lifespan: "" as string | number,
  access_code_lifespan_login: "" as string | number,
  access_code_lifespan_user_action: "" as string | number,
  action_tokens_lifespan: "" as string | number,
  not_before: "" as string | number,
  device_code_lifespan: "" as string | number,
  device_poll_interval: "" as string | number,
  ciba_expiry: "" as string | number,
  ciba_interval: "" as string | number,
  dsar_jurisdiction: "",
  dsar_response_days: "" as string | number,
  revoke_refresh_token: false,
  refresh_token_max_reuse: "" as string | number,
  offline_session_lifespan: "" as string | number,
  offline_session_max_lifespan: 0,
  max_offline_grants: 0,
  require_pushed_authorization_requests: false,
  ssl_enforcement: "" as "" | "none" | "all" | "external",
  bf_protected: false,
  bf_max_failures: 10,
  bf_lockout_seconds: 60,
  bf_max_lockout_seconds: 900,
  bf_reset_seconds: 900,
});

/// Assurance levels and free attributes, edited as rows.
const acrRows = ref<{ context: string; level: string | number }[]>([]);
const attrRows = ref<{ name: string; value: string }[]>([]);

/// The realm's cut of the built tongues, and the silence answer.
const offeredTongues = ref<string[]>([]);
const defaultTongue = ref("");
const effectiveDefaultTongue = computed(
  () => defaultTongue.value || offeredTongues.value[0] || TONGUES[0],
);
const allTonguesOffered = computed(() => offeredTongues.value.length === TONGUES.length);

function setTongue(tongue: string, enabled: boolean) {
  const next = toggleLocale(
    { offered: offeredTongues.value, fallback: defaultTongue.value },
    tongue,
    enabled,
    TONGUES,
  );
  offeredTongues.value = next.offered;
  defaultTongue.value = next.fallback;
}

const POLICY_NUMBERS = [
  ["min_length", "policy-min-length"],
  ["max_length", "policy-max-length"],
  ["min_digits", "policy-min-digits"],
  ["min_upper_case", "policy-min-upper"],
  ["min_lower_case", "policy-min-lower"],
  ["min_special_chars", "policy-min-special"],
  ["expires_after_days", "policy-expiry"],
  ["history_look_back", "policy-history"],
] as const;
const POLICY_CHECKS = [
  ["not_email", "policy-not-email"],
  ["not_username", "policy-not-username"],
  ["not_birthdate", "policy-not-birthdate"],
] as const;

/// What a fresh authenticator app enrolment is set up with, plus the one
/// live knob over enrolled codes: the drift window.
const otp = ref({ ...OTP_DEFAULTS });

/// The key ceremony's face: shown name, subdomain reach.
const webauthn = ref({ rp_name: "", allow_subdomains: false });
const passwordless = ref(false);

/// The password policy, spread into fields; the hashing block rides along
/// untouched because the server requires it whole.
const policy = ref({
  min_length: "" as string | number,
  max_length: "" as string | number,
  min_digits: "" as string | number,
  min_upper_case: "" as string | number,
  min_lower_case: "" as string | number,
  min_special_chars: "" as string | number,
  not_email: false,
  not_username: false,
  not_birthdate: false,
  blacklisted: "",
  regex_pattern: "",
  expires_after_days: "" as string | number,
  history_look_back: "" as string | number,
  hashing: { ...OWASP_HASHING },
});

function adopt(held: RealmSettings) {
  dirtyGroups.value = {};
  settings.value = held;
  draft.value = {
    display_name: held.display_name,
    enabled: held.enabled,
    agent_exchange_enabled: held.agent_exchange_enabled ?? false,
    registration_allowed: held.registration_allowed ?? false,
    events_enabled: held.events_enabled ?? false,
    register_email_as_username: held.register_email_as_username ?? false,
    verify_email: held.verify_email ?? false,
    login_with_email_allowed: held.login_with_email_allowed ?? false,
    duplicated_email_allowed: held.duplicated_email_allowed ?? false,
    edit_user_name_allowed: held.edit_user_name_allowed ?? false,
    reset_password_allowed: held.reset_password_allowed ?? false,
    remember_me: held.remember_me ?? false,
    client_registration: held.client_registration,
    bounds_max_clients: held.registration_bounds.max_clients ?? "",
    bounds_requires_consent: held.registration_bounds.requires_consent,
    bounds_trusted_hosts: held.registration_bounds.trusted_hosts.join("\n"),
    access_token_lifespan: held.access_token_lifespan ?? "",
    refresh_token_lifespan: held.refresh_token_lifespan ?? "",
    session_max_lifespan: held.session_max_lifespan,
    access_code_lifespan: held.access_code_lifespan ?? "",
    access_code_lifespan_login: held.access_code_lifespan_login ?? "",
    access_code_lifespan_user_action: held.access_code_lifespan_user_action ?? "",
    action_tokens_lifespan: held.action_tokens_lifespan ?? "",
    not_before: held.not_before ?? "",
    device_code_lifespan: held.device_code_lifespan ?? "",
    device_poll_interval: held.device_poll_interval ?? "",
    ciba_expiry: held.ciba_expiry ?? "",
    ciba_interval: held.ciba_interval ?? "",
    dsar_jurisdiction: held.dsar_jurisdiction ?? "",
    dsar_response_days: held.dsar_response_days ?? "",
    revoke_refresh_token: held.revoke_refresh_token ?? false,
    refresh_token_max_reuse: held.refresh_token_max_reuse ?? "",
    offline_session_lifespan: held.offline_session_lifespan ?? "",
    offline_session_max_lifespan: held.offline_session_max_lifespan,
    max_offline_grants: held.max_offline_grants,
    require_pushed_authorization_requests: held.require_pushed_authorization_requests,
    ssl_enforcement: (held.ssl_enforcement ?? "") as typeof draft.value.ssl_enforcement,
    bf_protected: held.brute_force.protected,
    bf_max_failures: held.brute_force.max_failures,
    bf_lockout_seconds: held.brute_force.lockout_seconds,
    bf_max_lockout_seconds: held.brute_force.max_lockout_seconds,
    bf_reset_seconds: held.brute_force.reset_seconds,
  };
  acrRows.value = Object.entries(held.acr_loa_map ?? {}).map(([context, level]) => ({
    context,
    level,
  }));
  attrRows.value = Object.entries(held.attributes ?? {}).map(([name, value]) => ({
    name,
    value: typeof value === "string" ? value : JSON.stringify(value),
  }));
  const locales = localeSelection(held.supported_locales, held.default_locale, TONGUES);
  offeredTongues.value = locales.offered;
  templates.value = JSON.parse(JSON.stringify(held.mail_templates ?? {}));
  smsTemplates.value = JSON.parse(JSON.stringify(held.sms_templates ?? {}));
  adoptSmsTemplate();
  smsBrakes.value = {
    daily: held.sms_daily_cap ?? "",
    perNumber: held.sms_per_number_cap ?? "",
    prefixes: (held.sms_blocked_prefixes ?? []).join("\n"),
  };
  defaultTongue.value = locales.fallback;
  otp.value = { ...(held.otp_policy ?? OTP_DEFAULTS) };
  webauthn.value = {
    rp_name: held.webauthn_policy?.rp_name ?? "",
    allow_subdomains: held.webauthn_policy?.allow_subdomains ?? false,

  };
  passwordless.value = held.webauthn_passwordless ?? false;
  const rules = held.password_policy;
  policy.value = {
    min_length: rules?.min_length ?? "",
    max_length: rules?.max_length ?? "",
    min_digits: rules?.min_digits ?? "",
    min_upper_case: rules?.min_upper_case ?? "",
    min_lower_case: rules?.min_lower_case ?? "",
    min_special_chars: rules?.min_special_chars ?? "",
    not_email: rules?.not_email ?? false,
    not_username: rules?.not_username ?? false,
    not_birthdate: rules?.not_birthdate ?? false,
    blacklisted: (rules?.blacklisted ?? []).join("\n"),
    regex_pattern: rules?.regex_pattern ?? "",
    expires_after_days: rules?.expires_after_days ?? "",
    history_look_back: rules?.history_look_back ?? "",
    hashing: rules?.hashing ?? { ...OWASP_HASHING },
  };
}

onMounted(async () => {
  try {
    adopt(await getRealmSettings(realm.value));
    try {
      mail.value = await getMail(realm.value);
      mailForm.value = {
        host: mail.value.host,
        port: mail.value.port,
        from_address: mail.value.from_address,
        from_name: mail.value.from_name ?? "",
        reply_to: mail.value.reply_to ?? "",
        username: mail.value.username ?? "",
        password: "",
        implicit_tls: mail.value.implicit_tls,
      };
    } catch (refused) {
      if (!(refused instanceof ApiError && refused.status < 500)) throw refused;
    }
    try {
      ussdHeld.value = (await getUssd(realm.value)).has_secret;
    } catch (refused) {
      if (!(refused instanceof ApiError && refused.status < 500)) throw refused;
    }
    try {
      smsToday.value = await readSmsToday(realm.value);
    } catch (refused) {
      if (!(refused instanceof ApiError && refused.status < 500)) throw refused;
    }
    try {
      sms.value = await getSms(realm.value);
      smsForm.value = {
        url: sms.value.url,
        sender: sms.value.sender,
        token: "",
      };
    } catch (refused) {
      if (!(refused instanceof ApiError && refused.status < 500)) throw refused;
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

function whole(value: string | number): number | undefined {
  if (value === "" || value === null) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

/// What each group sends: only its own switches, so a save here never
/// rewrites a setting another group shows.
function changesOf(which: Group): RealmUpdate {
  const held = draft.value;
  if (which === "general") {
    const attributes: Record<string, string> = {};
    for (const row of attrRows.value) {
      if (row.name.trim()) attributes[row.name.trim()] = row.value;
    }
    return {
      display_name: held.display_name,
      enabled: held.enabled,
      not_before: whole(held.not_before) ?? 0,
      attributes,
    };
  }
  if (which === "login") {
    return {
      registration_allowed: held.registration_allowed,
      register_email_as_username: held.register_email_as_username,
      verify_email: held.verify_email,
      login_with_email_allowed: held.login_with_email_allowed,
      duplicated_email_allowed: held.duplicated_email_allowed,
      edit_user_name_allowed: held.edit_user_name_allowed,
      reset_password_allowed: held.reset_password_allowed,
      client_registration: held.client_registration,
      registration_bounds: {
        max_clients: whole(held.bounds_max_clients) ?? null,
        requires_consent: held.bounds_requires_consent,
        trusted_hosts: held.bounds_trusted_hosts
          .split(/[\n,]/)
          .map((host) => host.trim())
          .filter(Boolean),
      },
    };
  }
  if (which === "sessions") {
    return sessionSettingsChanges(held);
  }
  if (which === "tokens") {
    return tokenSettingsChanges(held);
  }
  if (which === "localization") {
    return localeMutation(
      { offered: offeredTongues.value, fallback: defaultTongue.value },
      TONGUES,
    );
  }
  if (which === "security") {
    const changes: RealmUpdate = {
      events_enabled: held.events_enabled,
      agent_exchange_enabled: held.agent_exchange_enabled,
      brute_force: {
        protected: held.bf_protected,
        max_failures: whole(held.bf_max_failures) ?? 10,
        lockout_seconds: whole(held.bf_lockout_seconds) ?? 60,
        max_lockout_seconds: whole(held.bf_max_lockout_seconds) ?? 900,
        reset_seconds: whole(held.bf_reset_seconds) ?? 900,
      },
    };
    if (held.ssl_enforcement) changes.ssl_enforcement = held.ssl_enforcement;
    changes.dsar_jurisdiction = held.dsar_jurisdiction;
    changes.dsar_response_days = whole(held.dsar_response_days) ?? 0;
    const map: Record<string, number> = {};
    for (const row of acrRows.value) {
      const level = Number(row.level);
      if (row.context.trim() && Number.isFinite(level)) map[row.context.trim()] = level;
    }
    changes.acr_loa_map = map;
    return changes;
  }
  const changes: RealmUpdate = {};
  const rules = policy.value;
  const written: PasswordPolicy = {
    min_length: whole(rules.min_length) ?? null,
    max_length: whole(rules.max_length) ?? null,
    min_digits: whole(rules.min_digits) ?? null,
    min_upper_case: whole(rules.min_upper_case) ?? null,
    min_lower_case: whole(rules.min_lower_case) ?? null,
    min_special_chars: whole(rules.min_special_chars) ?? null,
    not_email: rules.not_email,
    not_username: rules.not_username,
    not_birthdate: rules.not_birthdate,
    blacklisted: rules.blacklisted
      .split(/[\n,]/)
      .map((held) => held.trim())
      .filter(Boolean),
    regex_pattern: rules.regex_pattern.trim() || null,
    expires_after_days: whole(rules.expires_after_days) ?? null,
    history_look_back: whole(rules.history_look_back) ?? null,
    hashing: rules.hashing,
  };
  changes.password_policy = written;
  changes.otp_policy = { ...otp.value };
  changes.webauthn_passwordless = passwordless.value;
  changes.webauthn_policy = {
    rp_name: webauthn.value.rp_name.trim() || null,
    allow_subdomains: webauthn.value.allow_subdomains,
  };
  return changes;
}

async function saveGroup() {
  failed.value = "";
  try {
    adopt(
      await reshapeRealm(
        realm.value,
        changesOf(group.value),
        say(`settings-group-${group.value}`),
      ),
    );
    } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function downloadRealmExport() {
  failed.value = "";
  exporting.value = true;
  try {
    const exported = await exportRealm(realm.value, false);
    const content = JSON.stringify(exported, null, 2);
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${realm.value}-configuration.json`;
    link.click();
    URL.revokeObjectURL(url);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    exporting.value = false;
  }
}

async function inspectPartialImport(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  importError.value = "";
  importReport.value = null;
  importDocument.value = null;
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    importError.value = say("settings-partial-import-too-large");
    return;
  }
  try {
    const parsed: unknown = JSON.parse(await file.text());
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(say("settings-partial-import-invalid"));
    }
    importFileName.value = file.name;
    importDocument.value = parsed as Record<string, unknown>;
    await refreshPartialImportPreview();
  } catch (refused) {
    importError.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function refreshPartialImportPreview() {
  if (!importDocument.value) return;
  const sequence = ++importPreviewSequence;
  importing.value = true;
  importError.value = "";
  try {
    const report = await previewPartialImport(
      realm.value,
      importDocument.value,
      importCollision.value,
    );
    if (sequence === importPreviewSequence) importReport.value = report;
  } catch (refused) {
    if (sequence === importPreviewSequence) {
      importError.value = refused instanceof Error ? refused.message : String(refused);
    }
  } finally {
    if (sequence === importPreviewSequence) importing.value = false;
  }
}

watch(importCollision, () => {
  if (importDocument.value) void refreshPartialImportPreview();
});

async function applyPartialImport() {
  if (!importDocument.value || !importReport.value) return;
  if (!window.confirm(say("settings-partial-import-confirm"))) return;
  importError.value = "";
  applyingImport.value = true;
  try {
    importReport.value = await importPartialRealm(
      realm.value,
      importDocument.value,
      importCollision.value,
    );
    adopt(await getRealmSettings(realm.value));
    toastOk(say("settings-partial-import-done"));
  } catch (refused) {
    importError.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    applyingImport.value = false;
  }
}

/// The secret protected registration is opened with, shown exactly once.
const drawnSecret = ref("");
async function drawRegistrationSecret() {
  failed.value = "";
  try {
    drawnSecret.value = await rotateRegistrationSecret(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
async function dropRegistrationSecret() {
  failed.value = "";
  drawnSecret.value = "";
  try {
    await forgetRegistrationSecret(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
async function copySecret() {
  try {
    await navigator.clipboard.writeText(drawnSecret.value);
  } catch {
    // The box stays selectable; copying by hand still works.
  }
}

/// Taking the realm away. Only this session's own, which is the only one the
/// boundary leaves reachable, and only through a dialog that counts what goes
/// and asks for the name back.
const dooming = ref(false);
/// What goes with the row, counted when the dialog opens rather than kept
/// fresh: a number read a moment before the deletion is the number the
/// person is deciding on.
const doomed = ref<{ value: string; label: string }[]>([]);
async function openDooming() {
  dooming.value = true;
  doomed.value = [];
  const asked = ["users", "clients", "organizations", "sessions"] as const;
  const held = await Promise.all(
    asked.map((leaf) => countOf(realm.value, leaf).catch(() => null)),
  );
  doomed.value = asked.map((leaf, at) => ({
    value: held[at] === null ? "?" : String(held[at]),
    label: say(`settings-delete-count-${leaf}`),
  }));
}
async function dropRealm() {
  failed.value = "";
  try {
    await deleteRealm(realm.value);
    toastOk(say("toast-realm-deleted", { realm: realm.value }));
    router.push(`/${home.value}/overview`);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

const features = ref<RealmFeature[]>([]);
const LIFECYCLES = ["stable", "preview", "experimental", "deprecated"] as const;

function featuresAt(stage: string) {
  return features.value.filter((held) => held.lifecycle === stage);
}

/// A capability whose closing takes a protection away, waiting to be
/// confirmed. An administrator closing one to harden a realm would be doing
/// the opposite, so this one asks.
const closingWeakens = ref<RealmFeature | null>(null);

async function switchFeature(held: RealmFeature, enabled: boolean) {
  if (!enabled && held.closing === "weakens") {
    closingWeakens.value = held;
    return;
  }
  await keepWish(held, enabled);
}

/// Say what this realm wants of one capability, then re-read. The answer is
/// the process's set narrowed by the wish, and only the server holds both.
async function keepWish(held: RealmFeature, enabled: boolean) {
  try {
    await keepFeatureWish(realm.value, held.slug, enabled);
    features.value = await listRealmFeatures(realm.value);
  } catch {
    // The toast already said.
  }
}

async function loadFeatures() {
  try {
    features.value = await listRealmFeatures(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
/// A board is a place, not a panel: it lives in the address, so a link to one
/// opens it and the back button walks between them.
function boardAt(leaf: string): string {
  return `/${realm.value}/settings?group=${leaf}`;
}

watch(
  () => route.query.group,
  (asked) => {
    const named = String(asked ?? "general");
    group.value = (GROUPS as readonly string[]).includes(named)
      ? (named as Group)
      : "general";
    if (group.value === "features" && !features.value.length) void loadFeatures();
  },
  { immediate: true },
);

/// The realm's rewording of its mails, kept whole and saved whole.
const MAIL_KINDS = ["magic_link", "verify_email", "reset_password", "subject_request"] as const;
const templates = ref<Record<string, Record<string, MailTemplate>>>({});
const templateKind = ref<string>("magic_link");
const templateTongue = ref("en");
const templateDraft = ref({ subject: "", body: "" });

function adoptTemplate() {
  const held = templates.value[templateKind.value]?.[templateTongue.value];
  templateDraft.value = { subject: held?.subject ?? "", body: held?.body ?? "" };
}
watch([templateKind, templateTongue], adoptTemplate);

async function saveTemplate() {
  const next = JSON.parse(JSON.stringify(templates.value)) as typeof templates.value;
  if (templateDraft.value.subject.trim() || templateDraft.value.body.trim()) {
    next[templateKind.value] = {
      ...next[templateKind.value],
      [templateTongue.value]: { ...templateDraft.value },
    };
  } else {
    delete next[templateKind.value]?.[templateTongue.value];
    if (next[templateKind.value] && !Object.keys(next[templateKind.value]).length) {
      delete next[templateKind.value];
    }
  }
  try {
    const kept = await reshapeRealm(
      realm.value,
      { mail_templates: next },
      say("mail-templates-title"),
    );
    adopt(kept);
    adoptTemplate();
  } catch {
    // The toast already said.
  }
}

const mailForm = ref({
  host: "",
  port: 587,
  from_address: "",
  from_name: "",
  reply_to: "",
  username: "",
  password: "",
  implicit_tls: false,
});

/// What the relay said when last asked, and what it could not deliver.
const relayReport = ref<RelayReport | null>(null);
const refusals = ref<MailRefusal[]>([]);
const refusalHours = ref(24);

/// A stored instant, as this browser writes one.
function stamp(at: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(at));
}

/// Only what the relay actually answered. A row nobody has a reading for is
/// left out rather than filled with a placeholder.
const relayFacts = computed(() => {
  const held = relayReport.value;
  if (!held) return [];
  const facts: { label: string; value: string }[] = [];
  const add = (label: string, value: string | null | undefined) => {
    if (value) facts.push({ label, value });
  };
  add(say("mail-probe-reached"), held.reached_in_millis === null ? null : `${held.reached_in_millis} ms`);
  add(say("mail-probe-tls"), held.tls_version);
  add(say("mail-probe-cipher"), held.cipher);
  add(say("mail-probe-certificate"), held.certificate_until);
  add(say("mail-probe-issuer"), held.certificate_issuer);
  add(
    say("mail-probe-max"),
    held.max_message_bytes === null
      ? null
      : `${Math.round(held.max_message_bytes / 1_048_576)} MB`,
  );
  add(say("mail-probe-auth"), held.auth_offered.length ? held.auth_offered.join(", ") : null);
  return facts;
});

async function askTheRelay() {
  try {
    relayReport.value = await lookAtRelay(realm.value);
    const told = await readRelayRefusals(realm.value);
    refusals.value = told.items;
    refusalHours.value = told.hours;
  } catch {
    // The toast already said.
  }
}

async function saveMail() {
  await writeMail(realm.value, mailWrite(mailForm.value));
  mail.value = await getMail(realm.value);
}

/// One real mail through the relay: connect, TLS, auth, delivery. Green
/// means the settings on screen actually carry mail.
const testTo = ref("");
const testPassed = ref(false);
async function testMail() {
  testPassed.value = false;
  try {
    await sendTestMail(realm.value, testTo.value.trim());
    testPassed.value = true;
  } catch {
    // The toast carries the server's refusal.
  }
}

async function removeMail() {
  await forgetMail(realm.value);
  mail.value = null;
}

const smsForm = ref({ url: "", sender: "", token: "" });

async function saveSms() {
  await writeSms(realm.value, smsWrite(smsForm.value));
  sms.value = await getSms(realm.value);
}

/// One real text through the gateway. Green means the settings on screen
/// actually carry texts.
const smsTestTo = ref("");
const smsTestPassed = ref(false);
async function testSms() {
  smsTestPassed.value = false;
  try {
    await sendTestSms(realm.value, smsTestTo.value.trim());
    smsTestPassed.value = true;
  } catch {
    // The toast carries the server's refusal.
  }
}

async function removeSms() {
  await forgetSms(realm.value);
  sms.value = null;
}

const ussdSecret = ref("");

async function saveUssd() {
  await writeUssd(realm.value, ussdSecret.value);
  ussdSecret.value = "";
  ussdHeld.value = true;
}

async function removeUssd() {
  await forgetUssd(realm.value);
  ussdHeld.value = false;
}

/// Where the realm's gateway posts its callbacks, spelled for copying.
const ussdCallback = computed(
  () => `${window.location.origin}/realms/${encodeURIComponent(realm.value)}/ussd/callback`,
);

/// The realm's brakes on texting. A cap left blank keeps whatever is held;
/// returning to the built default means typing it.
const smsBrakes = ref({ daily: "" as string | number, perNumber: "" as string | number, prefixes: "" });

/// What the day has cost so far, read once with the rest of the screen.
const smsToday = ref<SmsToday | null>(null);

/// The four the design puts on this board. A cap the realm has not named is
/// shown as the count alone rather than against the engine's own, which is
/// not this realm's setting to display.
const todayCounts = computed(() => {
  const held = smsToday.value;
  if (!held) return [];
  return [
    {
      label: say("sms-today-sent"),
      value: held.cap === null ? String(held.sent) : `${held.sent} / ${held.cap}`,
    },
    { label: say("sms-today-velocity"), value: String(held.number_velocity) },
    { label: say("sms-today-prefix"), value: String(held.blocked_prefix) },
    { label: say("sms-today-budget"), value: String(held.day_budget) },
  ];
});

async function saveSmsBrakes() {
  const changes: RealmUpdate = {
    sms_blocked_prefixes: smsBrakes.value.prefixes
      .split(/[\n,]/)
      .map((held) => held.trim())
      .filter(Boolean),
  };
  const daily = whole(smsBrakes.value.daily);
  if (daily !== undefined && daily !== null) changes.sms_daily_cap = daily;
  const perNumber = whole(smsBrakes.value.perNumber);
  if (perNumber !== undefined && perNumber !== null) changes.sms_per_number_cap = perNumber;
  try {
    adopt(await reshapeRealm(realm.value, changes, say("sms-brakes-title")));
  } catch {
    // The toast already said.
  }
}

const SMS_KINDS = ["sms_otp", "verify_phone", "ciba_doorbell"] as const;
const smsTemplates = ref<Record<string, Record<string, string>>>({});
const smsTplKind = ref<(typeof SMS_KINDS)[number]>("sms_otp");
const smsTplTongue = ref("en");
const smsTplBody = ref("");
const smsTplValid = computed(() => smsTemplateIsValid(smsTplKind.value, smsTplBody.value));
const smsTplPreview = computed(() => previewSms(smsTplKind.value, smsTplBody.value));

function adoptSmsTemplate() {
  smsTplBody.value = smsTemplates.value[smsTplKind.value]?.[smsTplTongue.value] ?? "";
}
watch([smsTplKind, smsTplTongue], adoptSmsTemplate);

async function saveSmsTemplate() {
  if (!smsTplValid.value) return;
  const next = JSON.parse(JSON.stringify(smsTemplates.value)) as typeof smsTemplates.value;
  if (smsTplBody.value.trim()) {
    next[smsTplKind.value] = {
      ...next[smsTplKind.value],
      [smsTplTongue.value]: smsTplBody.value,
    };
  } else {
    delete next[smsTplKind.value]?.[smsTplTongue.value];
    if (next[smsTplKind.value] && !Object.keys(next[smsTplKind.value]).length) {
      delete next[smsTplKind.value];
    }
  }
  try {
    adopt(await reshapeRealm(realm.value, { sms_templates: next }, say("sms-templates-title")));
    adoptSmsTemplate();
  } catch {
    // The toast already said.
  }
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("settings-title") }}</h1>
    <p class="mt-1 text-[11.5px] text-faint">
      {{ say("settings-under", { realm, about: say(`settings-group-${group}-desc`) }) }}
    </p>

    <PageTabs
      :leaves="[...GROUPS]"
      :at="group"
      :to="boardAt"
      :marked="GROUPS.filter((held) => dirtyGroups[held])"
      saying="settings-group"
      class="mt-3"
    />

    <div class="min-w-0">
      <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

      <template v-if="settings">
        <form
          v-if="group !== 'email' && group !== 'phone' && group !== 'features'"
          class="mt-4 flex w-full max-w-6xl flex-col gap-4 text-xs"
          @submit.prevent="saveGroup"
          @input="markDirty"
          @change="markDirty"
        >
          <template v-if="group === 'general'">
            <div class="grid grid-cols-1 items-center gap-y-2.5 sm:grid-cols-[220px_1fr]">
              <span class="text-muted"
                >{{ say("settings-name") }} <AppHint name="settings-name-fixed"
              /></span>
              <span class="font-mono text-[11.5px]">{{ settings.name }}</span>
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("directory-col-display") }} <AppHint name="settings-display-help" />
              <input
                v-model="draft.display_name"
                class="sf-field mt-1"
              />
            </label>
            <AppToggle v-model="draft.enabled">
              {{ say("users-active") }} <AppHint name="settings-enabled-help" />
            </AppToggle>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("settings-not-before") }} <AppHint name="settings-not-before-help" />
              <input
                v-model="draft.not_before"
                type="number"
                min="0"
                placeholder="0"
                class="sf-field mt-1 font-mono"
              />
            </label>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-attributes") }} <AppHint name="settings-attributes-help" />
            </div>
            <div
              v-for="(row, at) in attrRows"
              :key="at"
              class="grid grid-cols-[1fr_1fr_28px] gap-2"
            >
              <input
                v-model="row.name"
                :placeholder="say('settings-attr-name')"
                class="sf-field font-mono"
                spellcheck="false"
              />
              <input
                v-model="row.value"
                :placeholder="say('settings-attr-value')"
                class="sf-field font-mono"
                spellcheck="false"
              />
              <button
                type="button"
                class="rounded border border-border text-xs text-muted hover:text-danger"
                :aria-label="say('action-remove')"
                @click="attrRows.splice(at, 1)"
              >
                &times;
              </button>
            </div>
            <button
              type="button"
              class="w-fit rounded-md border border-border px-2 py-1 text-[11px] text-muted hover:bg-surface-2"
              @click="attrRows.push({ name: '', value: '' })"
            >
              {{ say("settings-attr-add") }}
            </button>

            <section class="mt-3 border-t border-border pt-4">
              <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("settings-operations") }}
              </div>
              <div class="mt-2 rounded-lg border border-border bg-surface px-3 py-3">
                <div class="flex flex-wrap items-center gap-3">
                  <div class="min-w-0 flex-1">
                    <div class="text-xs font-medium text-ink">{{ say("settings-export") }}</div>
                    <p class="mt-1 text-[11px] leading-relaxed text-muted">
                      {{ say("settings-export-lede") }}
                    </p>
                  </div>
                  <button
                    type="button"
                    class="sf-button sf-button-secondary shrink-0 disabled:opacity-50"
                    :disabled="exporting"
                    @click="downloadRealmExport"
                  >
                    {{ say(exporting ? "settings-exporting" : "settings-export-action") }}
                  </button>
                </div>
                <p class="mt-2 text-[10.5px] leading-relaxed text-faint">
                  {{ say("settings-export-note") }}
                </p>
              </div>
              <div class="mt-2 rounded-lg border border-warn/40 bg-warn/5 px-3 py-3">
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div class="min-w-0">
                    <div class="text-xs font-medium text-ink">{{ say("settings-partial-import") }}</div>
                    <p class="mt-1 text-[11px] leading-relaxed text-muted">
                      {{ say("settings-partial-import-lede") }}
                    </p>
                  </div>
                  <label class="sf-button sf-button-secondary shrink-0 cursor-pointer">
                    {{ say("settings-partial-import-select") }}
                    <input
                      type="file"
                      accept="application/json,.json"
                      class="sr-only"
                      @change="inspectPartialImport"
                    />
                  </label>
                </div>
                <div v-if="importFileName" class="mt-3 border-t border-warn/20 pt-3">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <code class="min-w-0 truncate font-mono text-[10.5px] text-muted">{{ importFileName }}</code>
                    <select v-model="importCollision" class="sf-field w-auto py-1 text-[11px]">
                      <option value="fail">{{ say("settings-partial-import-fail") }}</option>
                      <option value="skip">{{ say("settings-partial-import-skip") }}</option>
                      <option value="overwrite">{{ say("settings-partial-import-overwrite") }}</option>
                    </select>
                  </div>
                  <div v-if="importing" class="mt-2 text-[11px] text-muted">
                    {{ say("settings-partial-import-previewing") }}
                  </div>
                  <div v-else-if="importReport" class="mt-2 space-y-2">
                    <div class="grid grid-cols-1 gap-2 text-center text-[10.5px] sm:grid-cols-3">
                      <div class="rounded border border-border px-2 py-1"><div class="font-mono text-ink">{{ Object.values(importReport.new).reduce((sum, value) => sum + value, 0) }}</div>{{ say("settings-partial-import-new") }}</div>
                      <div class="rounded border border-border px-2 py-1"><div class="font-mono text-ink">{{ Object.values(importReport.overwritten).reduce((sum, value) => sum + value, 0) }}</div>{{ say("settings-partial-import-overwritten") }}</div>
                      <div class="rounded border border-border px-2 py-1"><div class="font-mono text-ink">{{ importReport.collision_count }}</div>{{ say("settings-partial-import-collisions") }}</div>
                    </div>
                    <p v-if="importReport.collision_count" class="text-[10.5px] text-warn">
                      {{ say("settings-partial-import-collision-warning") }}
                    </p>
                    <p v-if="importReport.collisions_truncated" class="text-[10.5px] text-warn">
                      {{ say("settings-partial-import-collision-truncated") }}
                    </p>
                    <button
                      type="button"
                      class="sf-button sf-button-primary disabled:opacity-50"
                      :disabled="applyingImport || (importCollision === 'fail' && importReport.collision_count > 0)"
                      @click="applyPartialImport"
                    >
                      {{ say(applyingImport ? "settings-partial-import-applying" : "settings-partial-import-apply") }}
                    </button>
                  </div>
                  <p v-if="importError" class="mt-2 text-[10.5px] text-danger">{{ importError }}</p>
                </div>
              </div>
            </section>

            <div class="mt-4 rounded-lg border border-danger-line p-3">
              <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
                {{ say("settings-danger") }}
              </div>
              <p class="mt-1 text-[11px] text-muted">
                {{
                  realm === home
                    ? say("settings-delete-lede", { realm })
                    : say("settings-delete-elsewhere", { realm })
                }}
                <AppHint name="settings-delete-help" />
              </p>
              <button
                v-if="realm === home"
                type="button"
                class="sf-button sf-button-danger mt-2"
                @click="openDooming"
              >
                <AppIcon name="remove" :size="13" />
                {{ say("settings-delete-realm") }}
              </button>
            </div>
          </template>

          <template v-if="group === 'login'">
            <AppToggle v-for="held in LOGIN_TOGGLES" :key="held[0]" v-model="draft[held[0]]">
              {{ say(held[1]) }} <AppHint :name="held[1] + '-help'" />
            </AppToggle>

            <label class="mt-2 block text-[11px] font-medium text-muted">
              {{ say("settings-client-registration") }} <AppHint name="settings-client-registration-help" />
              <select
                v-model="draft.client_registration"
                class="sf-field mt-1"
              >
                <option value="disabled">disabled</option>
                <option value="open">open</option>
                <option value="protected">protected</option>
              </select>
            </label>
            <div v-if="draft.client_registration !== 'disabled'" class="flex flex-col gap-3">
              <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("settings-max-clients") }} <AppHint name="settings-max-clients-help" />
                  <input
                    v-model="draft.bounds_max_clients"
                    type="number"
                    min="0"
                    :placeholder="say('settings-unbounded-plain')"
                    class="sf-field mt-1 font-mono"
                  />
                </label>
                <div class="flex items-end pb-1.5">
                  <AppToggle v-model="draft.bounds_requires_consent">
                    {{ say("settings-requires-consent") }}
                    <AppHint name="settings-requires-consent-help" />
                  </AppToggle>
                </div>
              </div>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-trusted-hosts") }} <AppHint name="settings-trusted-hosts-help" />
                <textarea
                  v-model="draft.bounds_trusted_hosts"
                  rows="3"
                  :placeholder="say('settings-trusted-hosts-hint')"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                ></textarea>
              </label>
              <p
                v-if="draft.client_registration === 'open' && !draft.bounds_trusted_hosts.trim()"
                class="rounded border border-warn/40 px-2 py-1 text-[11px] text-warn"
              >
                {{ say("settings-unbounded") }}
              </p>
            </div>
          </template>

          <template v-if="group === 'sessions'">
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-session-ceiling") }}
                <AppHint name="settings-session-ceiling-help" />
                <input
                  v-model="draft.session_max_lifespan"
                  type="number"
                  min="0"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-sliding") }} <AppHint name="settings-offline-sliding-help" />
                <input
                  v-model="draft.offline_session_lifespan"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-ceiling") }} <AppHint name="settings-offline-ceiling-help" />
                <input
                  v-model="draft.offline_session_max_lifespan"
                  type="number"
                  min="0"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-grants") }} <AppHint name="settings-offline-grants-help" />
                <input
                  v-model="draft.max_offline_grants"
                  type="number"
                  min="0"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-login-window") }} <AppHint name="settings-login-window-help" />
                <input
                  v-model="draft.access_code_lifespan_login"
                  type="number"
                  min="1"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-action-window") }} <AppHint name="settings-action-window-help" />
                <input
                  v-model="draft.access_code_lifespan_user_action"
                  type="number"
                  min="1"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>
            <p class="text-[10.5px] text-faint">{{ say("settings-zero-unbounded") }}</p>
            <AppToggle v-model="draft.remember_me">
              {{ say("settings-remember-me") }} <AppHint name="settings-remember-me-help" />
            </AppToggle>
          </template>
          <template v-if="group === 'tokens'">
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-access-lifespan") }} <AppHint name="settings-access-lifespan-help" />
                <input
                  v-model="draft.access_token_lifespan"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-refresh-sliding") }}
                <AppHint name="settings-refresh-sliding-help" />
                <input
                  v-model="draft.refresh_token_lifespan"
                  type="number"
                  min="1"
                  placeholder="1800"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-refresh-reuse") }} <AppHint name="settings-refresh-reuse-help" />
                <input
                  v-model="draft.refresh_token_max_reuse"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-code-lifespan") }} <AppHint name="settings-code-lifespan-help" />
                <input
                  v-model="draft.access_code_lifespan"
                  type="number"
                  min="1"
                  placeholder="60"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-action-tokens") }} <AppHint name="settings-action-tokens-help" />
                <input
                  v-model="draft.action_tokens_lifespan"
                  type="number"
                  min="1"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("device-lifespan") }} <AppHint name="device-lifespan-help" />
                <input
                  v-model="draft.device_code_lifespan"
                  type="number"
                  min="60"
                  max="3600"
                  placeholder="600"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("device-interval") }} <AppHint name="device-interval-help" />
                <input
                  v-model="draft.device_poll_interval"
                  type="number"
                  min="1"
                  max="60"
                  placeholder="5"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("ciba-expiry") }} <AppHint name="ciba-expiry-help" />
                <input
                  v-model="draft.ciba_expiry"
                  type="number"
                  min="30"
                  max="600"
                  placeholder="300"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("ciba-interval") }} <AppHint name="ciba-interval-help" />
                <input
                  v-model="draft.ciba_interval"
                  type="number"
                  min="1"
                  max="60"
                  placeholder="5"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>
            <p class="text-[10.5px] text-faint">{{ say("settings-zero-unbounded") }}</p>
            <AppToggle v-model="draft.revoke_refresh_token">
              {{ say("settings-refresh-rotation") }}
              <AppHint name="settings-refresh-rotation-help" />
            </AppToggle>
            <AppToggle v-model="draft.require_pushed_authorization_requests">
              {{ say("settings-require-par") }} <AppHint name="settings-require-par-help" />
            </AppToggle>
          </template>

          <template v-if="group === 'security'">
            <AppToggle v-model="draft.agent_exchange_enabled">
              {{ say("settings-agents") }} <AppHint name="settings-agents-help" />
            </AppToggle>
            <label class="mt-2 block text-[11px] font-medium text-muted">
              {{ say("settings-ssl") }} <AppHint name="settings-ssl-help" />
              <select
                v-model="draft.ssl_enforcement"
                class="sf-field mt-1"
              >
                <option value="">{{ say("settings-unset") }}</option>
                <option value="none">none</option>
                <option value="external">external</option>
                <option value="all">all</option>
              </select>
            </label>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-brute-force") }}
            </div>
            <AppToggle v-model="draft.bf_protected">
              {{ say("settings-lockout-protected") }}
              <AppHint name="settings-lockout-protected-help" />
            </AppToggle>
            <div v-if="draft.bf_protected" class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-failures") }} <AppHint name="settings-lockout-failures-help" />
                <input
                  v-model="draft.bf_max_failures"
                  type="number"
                  min="1"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-first") }} <AppHint name="settings-lockout-first-help" />
                <input
                  v-model="draft.bf_lockout_seconds"
                  type="number"
                  min="1"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-ceiling") }} <AppHint name="settings-lockout-ceiling-help" />
                <input
                  v-model="draft.bf_max_lockout_seconds"
                  type="number"
                  min="1"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-reset") }} <AppHint name="settings-lockout-reset-help" />
                <input
                  v-model="draft.bf_reset_seconds"
                  type="number"
                  min="1"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("signin-events-title") }} <AppHint name="signin-events-title-help" />
            </div>
            <AppToggle v-model="draft.events_enabled">
              {{ say("signin-events-toggle") }} <AppHint name="signin-events-toggle-help" />
            </AppToggle>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-privacy-door") }} <AppHint name="settings-privacy-door-help" />
            </div>
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-dsar-jurisdiction") }}
                <select
                  v-model="draft.dsar_jurisdiction"
                  class="sf-field mt-1"
                >
                  <option value="">{{ say("settings-dsar-closed") }}</option>
                  <option v-for="held in JURISDICTIONS" :key="held" :value="held">{{ held }}</option>
                </select>
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-dsar-days") }} <AppHint name="settings-dsar-days-help" />
                <input
                  v-model="draft.dsar_response_days"
                  type="number"
                  min="0"
                  max="3650"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-assurance") }} <AppHint name="settings-assurance-help" />
            </div>
            <div v-for="(row, at) in acrRows" :key="at" class="grid grid-cols-[1fr_110px_28px] gap-2">
              <input
                v-model="row.context"
                :placeholder="say('settings-assurance-context')"
                class="sf-field font-mono"
                spellcheck="false"
              />
              <input
                v-model="row.level"
                type="number"
                min="0"
                :placeholder="say('settings-assurance-level')"
                class="sf-field font-mono"
              />
              <button
                type="button"
                class="rounded border border-border text-xs text-muted hover:text-danger"
                :aria-label="say('action-remove')"
                @click="acrRows.splice(at, 1)"
              >
                &times;
              </button>
            </div>
            <button
              type="button"
              class="w-fit rounded-md border border-border px-2 py-1 text-[11px] text-muted hover:bg-surface-2"
              @click="acrRows.push({ context: '', level: 1 })"
            >
              {{ say("settings-assurance-add") }}
            </button>

            <template v-if="draft.client_registration === 'protected'">
              <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("settings-registration-secret") }}
                <AppHint name="settings-registration-secret-help" />
              </div>
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
                  @click="drawRegistrationSecret"
                >
                  {{ say("settings-secret-draw") }}
                </button>
                <button
                  type="button"
                  class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2"
                  @click="dropRegistrationSecret"
                >
                  {{ say("settings-secret-forget") }}
                </button>
              </div>
              <div
                v-if="drawnSecret"
                class="flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2"
              >
                <code class="min-w-0 flex-1 truncate font-mono text-[11px]">{{ drawnSecret }}</code>
                <button
                  type="button"
                  class="rounded border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-3"
                  @click="copySecret"
                >
                  {{ say("action-copy") }}
                </button>
              </div>
              <p v-if="drawnSecret" class="text-[10.5px] text-warn">
                {{ say("settings-secret-once") }}
              </p>
            </template>

          </template>

          <template v-if="group === 'credentials'">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("otp-title") }} <AppHint name="otp-title-help" />
            </div>
            <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("otp-digits") }} <AppHint name="otp-digits-help" />
                <select
                  v-model.number="otp.digits"
                  class="sf-field mt-1 font-mono"
                >
                  <option :value="6">6</option>
                  <option :value="7">7</option>
                  <option :value="8">8</option>
                </select>
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("otp-period") }} <AppHint name="otp-period-help" />
                <input
                  v-model.number="otp.period"
                  type="number"
                  min="15"
                  max="300"
                  class="sf-field mt-1 font-mono"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("otp-algorithm") }} <AppHint name="otp-algorithm-help" />
                <select
                  v-model="otp.algorithm"
                  class="sf-field mt-1 font-mono"
                >
                  <option value="SHA1">SHA1</option>
                  <option value="SHA256">SHA256</option>
                  <option value="SHA512">SHA512</option>
                </select>
                <span v-if="otp.algorithm !== 'SHA1'" class="mt-1 block text-[10.5px] text-warn">
                  {{ say("otp-algorithm-warn") }}
                </span>
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("otp-window") }} <AppHint name="otp-window-help" />
                <input
                  v-model.number="otp.window"
                  type="number"
                  min="0"
                  max="4"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("webauthn-title") }} <AppHint name="webauthn-title-help" />
            </div>
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("webauthn-rp-name") }} <AppHint name="webauthn-rp-name-help" />
                <input
                  v-model="webauthn.rp_name"
                  maxlength="64"
                  :placeholder="settings.name"
                  class="sf-field mt-1"
                />
              </label>
              <div class="flex items-end pb-1.5">
                <AppToggle v-model="webauthn.allow_subdomains">
                  {{ say("webauthn-subdomains") }} <AppHint name="webauthn-subdomains-help" />
                </AppToggle>
              </div>
            </div>
            <p class="text-[10.5px] text-faint">{{ say("webauthn-fixed-line") }}</p>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("passwordless-title") }} <AppHint name="passwordless-title-help" />
            </div>
            <AppToggle v-model="passwordless">
              {{ say("passwordless-enable") }} <AppHint name="passwordless-enable-help" />
            </AppToggle>
            <p class="text-[10.5px] text-faint">{{ say("passwordless-fixed-line") }}</p>

            <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-password-policy") }} <AppHint name="settings-password-policy-help" />
            </div>
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <label
                v-for="held in POLICY_NUMBERS"
                :key="held[0]"
                class="block text-[11px] font-medium text-muted"
              >
                {{ say(held[1]) }} <AppHint :name="held[1] + '-help'" />
                <input
                  v-model="policy[held[0]]"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>
            <AppToggle v-for="held in POLICY_CHECKS" :key="held[0]" v-model="policy[held[0]]">
              {{ say(held[1]) }} <AppHint :name="held[1] + '-help'" />
            </AppToggle>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("policy-regex") }} <AppHint name="policy-regex-help" />
              <input
                v-model="policy.regex_pattern"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
              />
            </label>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("policy-blacklist") }} <AppHint name="policy-blacklist-help" />
              <textarea
                v-model="policy.blacklisted"
                rows="3"
                :placeholder="say('policy-blacklist-hint')"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
              ></textarea>
            </label>
            <p class="text-[10.5px] text-faint">
              {{
                say("policy-hashing-line", {
                  memory: policy.hashing.m_cost,
                  passes: policy.hashing.t_cost,
                  lanes: policy.hashing.p_cost,
                })
              }}
              <AppHint name="policy-hashing-help" />
            </p>
          </template>

          <template v-if="group === 'localization'">
            <p class="max-w-3xl text-[11px] leading-5 text-muted">{{ say("locales-lede") }}</p>
            <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
              <section class="min-w-0 rounded-lg border border-border bg-surface p-4">
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                      {{ say("locales-offered") }} <AppHint name="locales-offered-help" />
                    </div>
                    <p class="mt-1 text-[10.5px] leading-4 text-muted">
                      {{ say("locales-build-count", { count: TONGUES.length }) }}
                    </p>
                  </div>
                  <span class="rounded border border-border px-2 py-1 font-mono text-[10.5px] text-muted">
                    {{ offeredTongues.length }}/{{ TONGUES.length }}
                  </span>
                </div>

                <div class="mt-4 grid gap-2 sm:grid-cols-2">
                  <div
                    v-for="tongue in TONGUES"
                    :key="tongue"
                    class="rounded-md border p-3"
                    :class="offeredTongues.includes(tongue) ? 'border-accent/50 bg-accent-tint' : 'border-border bg-surface-2'"
                  >
                    <AppToggle
                      :model-value="offeredTongues.includes(tongue)"
                      @update:model-value="setTongue(tongue, $event)"
                    >
                      <span class="font-medium text-ink">{{ say(`locale-${tongue}`) }}</span>
                      <span class="ml-auto font-mono text-[10.5px] text-faint">{{ tongue }}</span>
                    </AppToggle>
                  </div>
                </div>

                <p v-if="!offeredTongues.length" class="mt-3 rounded border border-warn/40 bg-warn/5 px-3 py-2 text-[11px] text-warn">
                  {{ say("locales-none-warning") }}
                </p>
              </section>

              <aside class="rounded-lg border border-border bg-surface p-4">
                <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                  {{ say("locales-negotiation") }}
                </div>
                <ol class="mt-3 space-y-2 text-[11px] text-muted">
                  <li class="flex gap-2"><span class="font-mono text-accent">01</span>{{ say("locales-order-request") }}</li>
                  <li class="flex gap-2"><span class="font-mono text-accent">02</span>{{ say("locales-order-browser") }}</li>
                  <li class="flex gap-2"><span class="font-mono text-accent">03</span>{{ say("locales-order-fallback") }}</li>
                </ol>
                <label class="mt-4 block border-t border-border pt-4 text-[11px] font-medium text-muted">
                  {{ say("locales-default") }} <AppHint name="locales-default-help" />
                  <select v-model="defaultTongue" class="sf-field mt-1" :disabled="!offeredTongues.length">
                    <option value="">{{ say("locales-default-first") }}</option>
                    <option v-for="tongue in offeredTongues" :key="tongue" :value="tongue">
                      {{ tongue }} · {{ say(`locale-${tongue}`) }}
                    </option>
                  </select>
                </label>
                <dl class="mt-3 grid grid-cols-[1fr_auto] gap-2 text-[10.5px]">
                  <dt class="text-faint">{{ say("locales-effective") }}</dt>
                  <dd class="font-mono text-ink">{{ effectiveDefaultTongue }}</dd>
                  <dt class="text-faint">{{ say("locales-restriction") }}</dt>
                  <dd class="text-right text-ink">{{ say(allTonguesOffered ? "locales-all" : "locales-subset") }}</dd>
                </dl>
              </aside>
            </div>
          </template>

          <div class="mt-1 flex items-center gap-2">
            <button
              type="submit"
              class="sf-button sf-button-primary disabled:cursor-not-allowed disabled:opacity-50"
              :disabled="group === 'localization' && !offeredTongues.length"
            >
              {{ say("settings-save") }}
            </button>
            <span v-if="dirtyGroups[group]" class="text-[11px] text-warn">{{
              say("settings-unsaved")
            }}</span>
          </div>
        </form>

        <div
          v-if="group === 'email'"
          class="mt-6 w-full max-w-6xl rounded-lg border border-border bg-surface p-4"
        >
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("mail-templates-title") }} <AppHint name="mail-templates-title-help" />
          </div>
          <form class="mt-2 flex flex-col gap-3 text-xs" @submit.prevent="saveTemplate">
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-templates-kind") }}
                <select
                  v-model="templateKind"
                  class="sf-field mt-1 font-mono"
                >
                  <option v-for="kind in MAIL_KINDS" :key="kind" :value="kind">
                    {{ say(`mail-kind-${kind}`) }}
                  </option>
                </select>
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("locales-default") }}
                <select
                  v-model="templateTongue"
                  class="sf-field mt-1 font-mono"
                >
                  <option v-for="tongue in offeredTongues" :key="tongue" :value="tongue">
                    {{ tongue }} · {{ say(`locale-${tongue}`) }}
                  </option>
                </select>
              </label>
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-templates-subject") }}
              <input
                v-model="templateDraft.subject"
                maxlength="200"
                :placeholder="say('mail-templates-built')"
                class="sf-field mt-1"
              />
            </label>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-templates-body") }} <AppHint name="mail-templates-body-help" />
              <textarea
                v-model="templateDraft.body"
                rows="5"
                maxlength="4000"
                :placeholder="say('mail-templates-built')"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
              ></textarea>
            </label>
            <p
              v-if="templateDraft.body.trim() && !templateDraft.body.includes('{{link}}')"
              class="rounded border border-warn/40 px-2 py-1 text-[11px] text-warn"
            >
              {{ say("mail-templates-no-link") }}
            </p>
            <div class="flex items-center gap-2">
              <button
                type="submit"
                class="sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
              <button
                type="button"
                class="rounded-md border border-border px-3 py-1.5 text-xs text-muted hover:bg-surface-2"
                @click="templateDraft = { subject: '', body: '' }; saveTemplate()"
              >
                {{ say("mail-templates-clear") }}
              </button>
            </div>
          </form>
        </div>

        <div v-if="group === 'features'" class="mt-4 w-full max-w-6xl">
          <p class="text-xs text-muted">{{ say("features-lede") }}</p>

          <template v-for="stage in LIFECYCLES" :key="stage">
            <div v-if="featuresAt(stage).length" class="mt-5">
              <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say(`features-stage-${stage}`) }}
              </div>
              <p class="mt-1 text-[10.5px] text-faint">{{ say(`features-stage-${stage}-lede`) }}</p>

              <div class="mt-2 grid gap-1.5">
                <div
                  v-for="held in featuresAt(stage)"
                  :key="held.slug"
                  class="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs"
                >
                  <span class="font-mono text-[11.5px]">{{ held.slug }}</span>
                  <AppHint :text="held.doc" />

                  <span
                    v-if="held.reach === 'process' || !held.in_process"
                    class="ml-auto text-[10.5px] text-faint"
                    :title="
                      held.reach === 'process'
                        ? say('features-process-only')
                        : say('features-not-in-process')
                    "
                  >
                    {{
                      held.enabled
                        ? say("features-on")
                        : held.compiled
                          ? say("features-off")
                          : say("features-not-compiled")
                    }}
                  </span>

                  <template v-else>
                    <span v-if="held.asked !== null" class="ml-auto text-[10px] text-faint">
                      {{ say("features-asked-here", { by: held.changed_by ?? "" }) }}
                    </span>
                    <AppToggle
                      :class="held.asked === null ? 'ml-auto' : ''"
                      :model-value="held.enabled"
                      @update:model-value="switchFeature(held, $event)"
                    />
                  </template>
                </div>
              </div>
            </div>
          </template>

          <DangerDialog
            :open="closingWeakens !== null"
            :title="say('features-closing-title')"
            :named="closingWeakens?.slug ?? ''"
            :lede="say('features-closing-lede')"
            :facts="[]"
            :warning="closingWeakens ? say(`features-closing-${closingWeakens.slug}`) : ''"
            :aside="say('features-closing-aside')"
            :trail="say('features-closing-trail')"
            :confirm-label="say('features-closing-confirm')"
            @close="closingWeakens = null"
            @confirm="
              closingWeakens && keepWish(closingWeakens, false);
              closingWeakens = null;
            "
          />
        </div>

        <div v-if="group === 'email'" class="mt-4 max-w-6xl">
          <form
            class="w-full rounded-lg border border-border bg-surface p-4 text-xs"
            @submit.prevent="saveMail"
          >
            <div class="mb-3 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("mail-server-title") }}
            </div>
            <div class="flex flex-col gap-3">
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_110px]">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-host") }} <AppHint name="mail-host-help" />
                <input
                  v-model="mailForm.host"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-port") }} <AppHint name="mail-port-help" />
                <input
                  v-model.number="mailForm.port"
                  type="number"
                  class="sf-field mt-1 font-mono"
                />
              </label>
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-from") }} <AppHint name="mail-from-help" />
              <input
                v-model="mailForm.from_address"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
              />
            </label>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-from-name") }} <AppHint name="mail-from-name-help" />
              <input
                v-model="mailForm.from_name"
                class="sf-field mt-1"
              />
            </label>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-reply-to") }} <AppHint name="mail-reply-to-help" />
              <input
                v-model="mailForm.reply_to"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
                :placeholder="say('settings-unset')"
              />
            </label>
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-username") }} <AppHint name="mail-username-help" />
                <input
                  v-model="mailForm.username"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                  autocomplete="off"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-password") }} <AppHint name="mail-password-help" />
                <input
                  v-model="mailForm.password"
                  type="password"
                  :placeholder="mail?.has_password ? say('mail-password-kept') : ''"
                  class="sf-field mt-1"
                  autocomplete="new-password"
                />
              </label>
            </div>
            <AppToggle v-model="mailForm.implicit_tls">
              {{ say("mail-implicit-tls") }} <AppHint name="mail-implicit-tls-help" />
            </AppToggle>
            <div class="mt-1 flex flex-wrap items-center gap-2">
              <button
                type="submit"
                class="sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
              <button
                v-if="mail"
                type="button"
                class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2"
                @click="removeMail"
              >
                {{ say("mail-forget") }}
              </button>
            </div>
            </div>
          </form>

          <div v-if="mail" class="mt-4 rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("mail-test-title") }} <AppHint name="mail-test-help" />
            </div>
            <form class="mt-2 flex flex-wrap items-end gap-2 text-xs" @submit.prevent="testMail">
              <label class="flex-1 text-[11px] font-medium text-muted">
                {{ say("mail-test-to") }}
                <input
                  v-model="testTo"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                />
              </label>
              <button
                type="submit"
                class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
              >
                {{ say("mail-test-send") }}
              </button>
              <span v-if="testPassed" class="pb-1.5 text-[11px] text-ok">{{
                say("mail-test-passed")
              }}</span>
              <button
                type="button"
                class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
                @click="askTheRelay"
              >
                {{ say("mail-probe-run") }} <AppHint name="mail-probe-help" />
              </button>
            </form>

            <div v-if="relayReport" class="mt-3 grid gap-3 lg:grid-cols-2">
              <div class="sf-list overflow-x-auto p-3">
                <pre class="font-mono text-[10.5px] leading-relaxed text-muted">{{
                  relayReport.transcript.join("\n")
                }}</pre>
                <p v-if="relayReport.refused" class="mt-2 text-[11px] text-danger" role="alert">
                  {{ relayReport.refused }}
                </p>
              </div>

              <div class="sf-list p-3 text-[11px]">
                <div class="font-semibold tracking-[0.08em] text-faint uppercase">
                  {{ say("mail-probe-status") }}
                </div>
                <dl class="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5">
                  <template v-for="fact in relayFacts" :key="fact.label">
                    <dt class="text-muted">{{ fact.label }}</dt>
                    <dd class="font-mono text-ink">{{ fact.value }}</dd>
                  </template>
                </dl>
                <p v-if="!relayFacts.length" class="mt-2 text-muted">
                  {{ say("mail-probe-nothing") }}
                </p>
              </div>
            </div>
          </div>

          <div v-if="mail" class="mt-4 w-full rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("mail-refusals-title", { hours: refusalHours }) }}
              <AppHint name="mail-refusals-help" />
            </div>
            <div class="sf-list mt-2 overflow-x-auto">
              <table class="sf-table">
                <thead>
                  <tr>
                    <th>{{ say("mail-refusals-when") }}</th>
                    <th>{{ say("mail-refusals-to") }}</th>
                    <th>{{ say("mail-refusals-why") }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="held in refusals" :key="held.attempted_at + held.recipient">
                    <td class="text-faint">{{ stamp(held.attempted_at) }}</td>
                    <td class="font-mono text-[10.5px]">{{ held.recipient }}</td>
                    <td class="text-muted">{{ held.detail ?? say("value-none") }}</td>
                  </tr>
                  <tr v-if="!refusals.length">
                    <td colspan="3" class="text-muted">{{ say("mail-refusals-none") }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div v-if="group === 'phone'" class="mt-4 max-w-6xl">
          <p class="max-w-3xl text-[11px] leading-5 text-muted">
            {{ say("sms-intro") }}
          </p>
          <form
            class="mt-3 flex w-full flex-col gap-3 rounded-lg border border-border bg-surface p-4 text-xs"
            @submit.prevent="saveSms"
          >
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("sms-gateway-title") }}
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("sms-url") }} <AppHint name="sms-url-help" />
              <input
                v-model="smsForm.url"
                class="sf-field mt-1 font-mono"
                spellcheck="false"
                placeholder="https://gateway.example/send"
              />
            </label>
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("sms-sender") }} <AppHint name="sms-sender-help" />
                <input
                  v-model="smsForm.sender"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("sms-token") }} <AppHint name="sms-token-help" />
                <input
                  v-model="smsForm.token"
                  type="password"
                  :placeholder="sms?.has_token ? say('sms-token-kept') : ''"
                  class="sf-field mt-1"
                  autocomplete="new-password"
                />
              </label>
            </div>
            <div class="mt-1 flex items-center gap-2">
              <button
                type="submit"
                class="sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
              <button
                v-if="sms"
                type="button"
                class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2"
                @click="removeSms"
              >
                {{ say("sms-forget") }}
              </button>
            </div>
          </form>

          <div v-if="sms" class="mt-4 w-full rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("sms-test-title") }} <AppHint name="sms-test-help" />
            </div>
            <form class="mt-2 flex flex-wrap items-end gap-2 text-xs" @submit.prevent="testSms">
              <label class="flex-1 text-[11px] font-medium text-muted">
                {{ say("sms-test-to") }}
                <input
                  v-model="smsTestTo"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                  placeholder="+22890123456"
                />
              </label>
              <button
                type="submit"
                class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
              >
                {{ say("sms-test-send") }}
              </button>
              <span v-if="smsTestPassed" class="pb-1.5 text-[11px] text-ok">{{
                say("sms-test-passed")
              }}</span>
            </form>
          </div>

          <div v-if="smsToday" class="mt-6 w-full">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("sms-today-title") }} <AppHint name="sms-today-help" />
            </div>
            <div class="mt-2 grid grid-cols-[repeat(2,minmax(0,1fr))] gap-3 2xl:grid-cols-[repeat(4,minmax(0,1fr))]">
              <div
                v-for="count in todayCounts"
                :key="count.label"
                class="min-w-0 overflow-hidden rounded-lg border border-border bg-surface px-3 py-2.5"
              >
                <div class="text-[10.5px] text-faint">{{ count.label }}</div>
                <div class="mt-0.5 font-mono text-base text-ink tabular-nums">
                  {{ count.value }}
                </div>
              </div>
            </div>
          </div>

          <div class="mt-6 w-full rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("sms-brakes-title") }} <AppHint name="sms-brakes-help" />
            </div>
            <form class="mt-2 flex flex-col gap-3 text-xs" @submit.prevent="saveSmsBrakes">
              <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("sms-daily-cap") }} <AppHint name="sms-daily-cap-help" />
                  <input
                    v-model="smsBrakes.daily"
                    type="number"
                    min="0"
                    max="1000000"
                    class="sf-field mt-1 font-mono"
                  />
                </label>
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("sms-per-number-cap") }} <AppHint name="sms-per-number-cap-help" />
                  <input
                    v-model="smsBrakes.perNumber"
                    type="number"
                    min="1"
                    max="1000"
                    class="sf-field mt-1 font-mono"
                  />
                </label>
              </div>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("sms-blocked-prefixes") }} <AppHint name="sms-blocked-prefixes-help" />
                <textarea
                  v-model="smsBrakes.prefixes"
                  rows="3"
                  placeholder="+88213&#10;+979"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                ></textarea>
              </label>
              <button
                type="submit"
                class="w-fit sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
            </form>
          </div>

          <div class="mt-6 w-full rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("sms-templates-title") }} <AppHint name="sms-templates-help" />
            </div>
            <div class="mt-2 grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
            <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveSmsTemplate">
              <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("sms-template-kind") }}
                  <select
                    v-model="smsTplKind"
                    class="sf-field mt-1"
                  >
                    <option v-for="held in SMS_KINDS" :key="held" :value="held">{{ held }}</option>
                  </select>
                </label>
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("sms-template-tongue") }}
                  <select
                    v-model="smsTplTongue"
                    class="sf-field mt-1"
                  >
                    <option v-for="held in TONGUES" :key="held" :value="held">{{ held }}</option>
                  </select>
                </label>
              </div>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("sms-template-body") }} <AppHint name="sms-template-body-help" />
                <textarea
                  v-model="smsTplBody"
                  rows="3"
                  maxlength="160"
                  class="sf-field mt-1 font-mono"
                  spellcheck="false"
                ></textarea>
                <span class="text-[10px] text-faint">{{ smsTplBody.length }}/160</span>
              </label>
              <p v-if="!smsTplValid" class="text-[11px] text-warn" role="alert">
                {{ say("sms-template-missing", { placeholder: smsPlaceholder(smsTplKind) }) }}
              </p>
              <button
                type="submit"
                :disabled="!smsTplValid"
                class="w-fit sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
            </form>
            <div class="min-w-0 rounded-lg border border-border bg-surface-2 p-3">
              <div class="text-[10.5px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("sms-template-preview") }}
              </div>
              <div class="mt-3 max-w-[240px] rounded-xl rounded-tl-sm bg-accent-tint px-3 py-2 text-[11px] leading-5 text-ink">
                {{ smsTplPreview || say("sms-template-preview-empty") }}
              </div>
              <div class="mt-2 font-mono text-[10px] text-faint">
                {{ smsForm.sender || say("sms-template-preview-sender") }}
              </div>
            </div>
            </div>
          </div>

          <div class="mt-6 w-full rounded-lg border border-border bg-surface p-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("ussd-title") }} <AppHint name="ussd-help" />
            </div>
            <p class="mt-1 text-[11px] text-muted">
              {{ say("ussd-callback") }}
              <code class="font-mono text-[10.5px]">{{ ussdCallback }}</code>
            </p>
            <form class="mt-2 flex flex-wrap items-end gap-2 text-xs" @submit.prevent="saveUssd">
              <label class="flex-1 text-[11px] font-medium text-muted">
                {{ say("ussd-secret") }} <AppHint name="ussd-secret-help" />
                <input
                  v-model="ussdSecret"
                  type="password"
                  minlength="16"
                  :placeholder="ussdHeld ? say('sms-token-kept') : ''"
                  class="sf-field mt-1"
                  autocomplete="new-password"
                />
              </label>
              <button
                type="submit"
                class="sf-button sf-button-primary"
              >
                {{ say("settings-save") }}
              </button>
              <button
                v-if="ussdHeld"
                type="button"
                class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2"
                @click="removeUssd"
              >
                {{ say("sms-forget") }}
              </button>
            </form>
          </div>
        </div>
      </template>
    </div>
  </div>

  <DangerDialog
    :open="dooming"
    :title="say('settings-delete-title', { realm })"
    :named="realm"
    :lede="say('settings-delete-dialog-lede')"
    :facts="doomed"
    :aside="say('settings-delete-aside')"
    :answer="{
      code: '404 realm_not_found',
      body: `GET /realms/${realm}/.well-known/openid-configuration`,
    }"
    :warning="say('settings-delete-warning')"
    :confirm-label="say('settings-delete-realm')"
    :failed="failed"
    @close="dooming = false"
    @confirm="dropRealm"
  />
</template>
