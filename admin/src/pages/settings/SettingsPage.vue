<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import {
  forgetMail,
  getMail,
  getRealmSettings,
  reshapeRealm,
  writeMail,
} from "@/services/settings";
import { ApiError } from "@/services/http";
import type { MailBrief } from "@/models/mail";
import type { RealmSettings, RealmUpdate } from "@/models/realm";

const GROUPS = ["general", "login", "sessions", "security", "email"] as const;
type Group = (typeof GROUPS)[number];

const LOGIN_TOGGLES = [
  ["registration_allowed", "settings-self-registration"],
  ["register_email_as_username", "settings-email-as-username"],
  ["verify_email", "settings-verify-email"],
  ["login_with_email_allowed", "settings-login-with-email"],
  ["reset_password_allowed", "settings-reset-password"],
  ["remember_me", "settings-remember-me"],
] as const;

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const group = ref<Group>("general");
const settings = ref<RealmSettings | null>(null);
const mail = ref<MailBrief | null>(null);
const failed = ref("");
const saved = ref(false);

/// The editable copy the forms bind to; adopting a settings document resets
/// it, so a save reflects what the server actually kept.
const draft = ref({
  display_name: "",
  enabled: true,
  registration_allowed: false,
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

function adopt(held: RealmSettings) {
  settings.value = held;
  draft.value = {
    display_name: held.display_name,
    enabled: held.enabled,
    registration_allowed: held.registration_allowed ?? false,
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
        username: mail.value.username ?? "",
        password: "",
        implicit_tls: mail.value.implicit_tls,
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
    return { display_name: held.display_name, enabled: held.enabled };
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
      remember_me: held.remember_me,
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
    return {
      access_token_lifespan: whole(held.access_token_lifespan),
      revoke_refresh_token: held.revoke_refresh_token,
      refresh_token_max_reuse: whole(held.refresh_token_max_reuse),
      offline_session_lifespan: whole(held.offline_session_lifespan),
      offline_session_max_lifespan: whole(held.offline_session_max_lifespan) ?? 0,
      max_offline_grants: whole(held.max_offline_grants) ?? 0,
      require_pushed_authorization_requests: held.require_pushed_authorization_requests,
    };
  }
  const changes: RealmUpdate = {
    brute_force: {
      protected: held.bf_protected,
      max_failures: whole(held.bf_max_failures) ?? 10,
      lockout_seconds: whole(held.bf_lockout_seconds) ?? 60,
      max_lockout_seconds: whole(held.bf_max_lockout_seconds) ?? 900,
      reset_seconds: whole(held.bf_reset_seconds) ?? 900,
    },
  };
  if (held.ssl_enforcement) changes.ssl_enforcement = held.ssl_enforcement;
  return changes;
}

async function saveGroup() {
  saved.value = false;
  failed.value = "";
  try {
    adopt(await reshapeRealm(realm.value, changesOf(group.value)));
    saved.value = true;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

const mailForm = ref({
  host: "",
  port: 587,
  from_address: "",
  from_name: "",
  username: "",
  password: "",
  implicit_tls: false,
});

async function saveMail() {
  saved.value = false;
  const asked = mailForm.value;
  await writeMail(realm.value, {
    host: asked.host,
    port: asked.port,
    from_address: asked.from_address,
    from_name: asked.from_name,
    reply_to: null,
    implicit_tls: asked.implicit_tls,
    username: asked.username || null,
    // Blank keeps the held password; typed replaces it.
    password: asked.password || null,
  });
  mail.value = await getMail(realm.value);
  saved.value = true;
}

async function removeMail() {
  await forgetMail(realm.value);
  mail.value = null;
  saved.value = false;
}
</script>

<template>
  <div class="flex gap-6">
    <nav class="w-44 shrink-0">
      <div class="sticky top-0 flex flex-col gap-0.5">
        <button
          v-for="held in GROUPS"
          :key="held"
          type="button"
          class="rounded-md px-2 py-1.5 text-left text-xs text-muted hover:bg-surface-2 hover:text-ink"
          :class="group === held && 'bg-surface-2 font-medium text-ink'"
          @click="group = held; saved = false"
        >
          {{ say(`settings-group-${held}`) }}
        </button>
      </div>
    </nav>

    <div class="min-w-0 flex-1">
      <h1 class="text-lg font-semibold tracking-tight">
        {{ say(`settings-group-${group}`) }}
      </h1>
      <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

      <template v-if="settings">
        <form
          v-if="group !== 'email'"
          class="mt-4 flex max-w-lg flex-col gap-3 text-xs"
          @submit.prevent="saveGroup"
        >
          <template v-if="group === 'general'">
            <div class="grid grid-cols-[220px_1fr] items-center gap-y-2.5">
              <span class="text-muted">{{ say("settings-name") }}</span>
              <span class="font-mono text-[11.5px]" :title="say('settings-name-fixed')">{{
                settings.name
              }}</span>
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("directory-col-display") }}
              <input
                v-model="draft.display_name"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
              />
            </label>
            <label class="flex items-center gap-2 text-xs">
              <input v-model="draft.enabled" type="checkbox" class="accent-(--sf-accent)" />
              {{ say("users-active") }}
            </label>
          </template>

          <template v-if="group === 'login'">
            <label
              v-for="held in LOGIN_TOGGLES"
              :key="held[0]"
              class="flex items-center gap-2 text-xs"
            >
              <input v-model="draft[held[0]]" type="checkbox" class="accent-(--sf-accent)" />
              {{ say(held[1]) }}
            </label>

            <label class="mt-2 block text-[11px] font-medium text-muted">
              {{ say("settings-client-registration") }}
              <select
                v-model="draft.client_registration"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
              >
                <option value="disabled">disabled</option>
                <option value="open">open</option>
                <option value="protected">protected</option>
              </select>
            </label>
            <div v-if="draft.client_registration !== 'disabled'" class="flex flex-col gap-3">
              <div class="grid grid-cols-2 gap-3">
                <label class="block text-[11px] font-medium text-muted">
                  {{ say("settings-max-clients") }}
                  <input
                    v-model="draft.bounds_max_clients"
                    type="number"
                    min="0"
                    :placeholder="say('settings-unbounded-plain')"
                    class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                  />
                </label>
                <label class="flex items-end gap-2 pb-1.5 text-xs">
                  <input
                    v-model="draft.bounds_requires_consent"
                    type="checkbox"
                    class="accent-(--sf-accent)"
                  />
                  {{ say("settings-requires-consent") }}
                </label>
              </div>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-trusted-hosts") }}
                <textarea
                  v-model="draft.bounds_trusted_hosts"
                  rows="3"
                  :placeholder="say('settings-trusted-hosts-hint')"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
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
            <div class="grid grid-cols-2 gap-3">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-access-lifespan") }}
                <input
                  v-model="draft.access_token_lifespan"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-refresh-reuse") }}
                <input
                  v-model="draft.refresh_token_max_reuse"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-sliding") }}
                <input
                  v-model="draft.offline_session_lifespan"
                  type="number"
                  min="0"
                  :placeholder="say('settings-unset')"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-ceiling") }}
                <input
                  v-model="draft.offline_session_max_lifespan"
                  type="number"
                  min="0"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-offline-grants") }}
                <input
                  v-model="draft.max_offline_grants"
                  type="number"
                  min="0"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
            </div>
            <p class="text-[10.5px] text-faint">{{ say("settings-zero-unbounded") }}</p>
            <label class="flex items-center gap-2 text-xs">
              <input
                v-model="draft.revoke_refresh_token"
                type="checkbox"
                class="accent-(--sf-accent)"
              />
              {{ say("settings-refresh-rotation") }}
            </label>
            <label class="flex items-center gap-2 text-xs">
              <input
                v-model="draft.require_pushed_authorization_requests"
                type="checkbox"
                class="accent-(--sf-accent)"
              />
              {{ say("settings-require-par") }}
            </label>
          </template>

          <template v-if="group === 'security'">
            <label class="block text-[11px] font-medium text-muted">
              {{ say("settings-ssl") }}
              <select
                v-model="draft.ssl_enforcement"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
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
            <label class="flex items-center gap-2 text-xs">
              <input v-model="draft.bf_protected" type="checkbox" class="accent-(--sf-accent)" />
              {{ say("settings-lockout-protected") }}
            </label>
            <div v-if="draft.bf_protected" class="grid grid-cols-2 gap-3">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-failures") }}
                <input
                  v-model="draft.bf_max_failures"
                  type="number"
                  min="1"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-first") }}
                <input
                  v-model="draft.bf_lockout_seconds"
                  type="number"
                  min="1"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-ceiling") }}
                <input
                  v-model="draft.bf_max_lockout_seconds"
                  type="number"
                  min="1"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("settings-lockout-reset") }}
                <input
                  v-model="draft.bf_reset_seconds"
                  type="number"
                  min="1"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
            </div>

            <div class="mt-2">
              <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("settings-password-policy") }}
              </div>
              <pre
                class="mt-1.5 overflow-x-auto rounded border border-border bg-surface-2 p-2 font-mono text-[10.5px]"
                >{{ JSON.stringify(settings.password_policy ?? null, null, 2) }}</pre
              >
            </div>
          </template>

          <div class="mt-1 flex items-center gap-2">
            <button
              type="submit"
              class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
            >
              {{ say("settings-save") }}
            </button>
            <span v-if="saved" class="text-[11px] text-ok">{{ say("settings-saved") }}</span>
          </div>
        </form>

        <div v-if="group === 'email'" class="mt-4 max-w-lg">
          <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveMail">
            <div class="grid grid-cols-[1fr_110px] gap-3">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-host") }}
                <input
                  v-model="mailForm.host"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                  spellcheck="false"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-port") }}
                <input
                  v-model.number="mailForm.port"
                  type="number"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </label>
            </div>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-from") }}
              <input
                v-model="mailForm.from_address"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                spellcheck="false"
              />
            </label>
            <label class="block text-[11px] font-medium text-muted">
              {{ say("mail-from-name") }}
              <input
                v-model="mailForm.from_name"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
              />
            </label>
            <div class="grid grid-cols-2 gap-3">
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-username") }}
                <input
                  v-model="mailForm.username"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
                  spellcheck="false"
                  autocomplete="off"
                />
              </label>
              <label class="block text-[11px] font-medium text-muted">
                {{ say("mail-password") }}
                <input
                  v-model="mailForm.password"
                  type="password"
                  :placeholder="mail?.has_password ? say('mail-password-kept') : ''"
                  class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
                  autocomplete="new-password"
                />
              </label>
            </div>
            <label class="flex items-center gap-2 text-xs">
              <input v-model="mailForm.implicit_tls" type="checkbox" class="accent-(--sf-accent)" />
              {{ say("mail-implicit-tls") }}
            </label>
            <div class="mt-1 flex items-center gap-2">
              <button
                type="submit"
                class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
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
              <span v-if="saved" class="text-[11px] text-ok">{{ say("settings-saved") }}</span>
            </div>
          </form>
        </div>
      </template>
    </div>
  </div>
</template>
