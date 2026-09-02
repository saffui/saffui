<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { forgetMail, getMail, getRealmSettings, writeMail } from "@/services/settings";
import { ApiError } from "@/services/http";
import type { MailBrief } from "@/models/mail";
import type { RealmSettings } from "@/models/realm";

const GROUPS = ["general", "login", "sessions", "security", "email"] as const;
type Group = (typeof GROUPS)[number];

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const group = ref<Group>("general");
const settings = ref<RealmSettings | null>(null);
const mail = ref<MailBrief | null>(null);
const failed = ref("");
const saved = ref(false);

const mailForm = ref({
  host: "",
  port: 587,
  from_address: "",
  from_name: "",
  username: "",
  password: "",
  implicit_tls: false,
});

onMounted(async () => {
  try {
    settings.value = await getRealmSettings(realm.value);
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

function onOff(held: boolean | null | undefined): string {
  if (held === null || held === undefined) return say("settings-unset");
  return held ? say("settings-on") : say("settings-off");
}
function seconds(held: number | null | undefined): string {
  if (held === null || held === undefined) return say("settings-unset");
  return `${new Intl.NumberFormat().format(held)} s`;
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
          @click="group = held"
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
        <p v-if="group !== 'email'" class="mt-1 text-[11px] text-faint">
          {{ say("settings-read-only") }}
        </p>

        <dl
          v-if="group === 'general'"
          class="mt-4 grid max-w-lg grid-cols-[220px_1fr] gap-y-2.5 text-xs"
        >
          <dt class="text-muted">{{ say("settings-name") }}</dt>
          <dd class="font-mono text-[11.5px]">{{ settings.name }}</dd>
          <dt class="text-muted">{{ say("directory-col-display") }}</dt>
          <dd>{{ settings.display_name }}</dd>
          <dt class="text-muted">{{ say("users-col-state") }}</dt>
          <dd>{{ settings.enabled ? say("users-active") : say("users-disabled") }}</dd>
          <dt class="text-muted">{{ say("settings-not-before") }}</dt>
          <dd class="font-mono text-[11.5px]">{{ settings.not_before ?? 0 }}</dd>
        </dl>

        <dl
          v-if="group === 'login'"
          class="mt-4 grid max-w-lg grid-cols-[220px_1fr] gap-y-2.5 text-xs"
        >
          <dt class="text-muted">{{ say("settings-self-registration") }}</dt>
          <dd>{{ onOff(settings.registration_allowed) }}</dd>
          <dt class="text-muted">{{ say("settings-email-as-username") }}</dt>
          <dd>{{ onOff(settings.register_email_as_username) }}</dd>
          <dt class="text-muted">{{ say("settings-verify-email") }}</dt>
          <dd>{{ onOff(settings.verify_email) }}</dd>
          <dt class="text-muted">{{ say("settings-login-with-email") }}</dt>
          <dd>{{ onOff(settings.login_with_email_allowed) }}</dd>
          <dt class="text-muted">{{ say("settings-reset-password") }}</dt>
          <dd>{{ onOff(settings.reset_password_allowed) }}</dd>
          <dt class="text-muted">{{ say("settings-remember-me") }}</dt>
          <dd>{{ onOff(settings.remember_me) }}</dd>
          <dt class="text-muted">{{ say("settings-client-registration") }}</dt>
          <dd>
            {{ settings.client_registration }}
            <span
              v-if="
                settings.client_registration === 'open' &&
                !settings.registration_bounds.trusted_hosts.length
              "
              class="ml-2 rounded border border-warn/40 px-1.5 py-0.5 text-[10px] text-warn"
              >{{ say("settings-unbounded") }}</span
            >
          </dd>
        </dl>

        <dl
          v-if="group === 'sessions'"
          class="mt-4 grid max-w-lg grid-cols-[220px_1fr] gap-y-2.5 text-xs"
        >
          <dt class="text-muted">{{ say("settings-access-lifespan") }}</dt>
          <dd class="font-mono text-[11.5px]">{{ seconds(settings.access_token_lifespan) }}</dd>
          <dt class="text-muted">{{ say("settings-refresh-rotation") }}</dt>
          <dd>{{ onOff(settings.revoke_refresh_token) }}</dd>
          <dt class="text-muted">{{ say("settings-refresh-reuse") }}</dt>
          <dd class="font-mono text-[11.5px]">
            {{ settings.refresh_token_max_reuse ?? say("settings-unset") }}
          </dd>
          <dt class="text-muted">{{ say("settings-offline-sliding") }}</dt>
          <dd class="font-mono text-[11.5px]">
            {{ seconds(settings.offline_session_lifespan) }}
          </dd>
          <dt class="text-muted">{{ say("settings-offline-ceiling") }}</dt>
          <dd class="font-mono text-[11.5px]">
            {{ settings.offline_session_max_lifespan || say("settings-unbounded-plain") }}
          </dd>
          <dt class="text-muted">{{ say("settings-offline-grants") }}</dt>
          <dd class="font-mono text-[11.5px]">
            {{ settings.max_offline_grants || say("settings-unbounded-plain") }}
          </dd>
          <dt class="text-muted">{{ say("settings-require-par") }}</dt>
          <dd>{{ onOff(settings.require_pushed_authorization_requests) }}</dd>
        </dl>

        <div v-if="group === 'security'" class="mt-4 max-w-lg text-xs">
          <dl class="grid grid-cols-[220px_1fr] gap-y-2.5">
            <dt class="text-muted">{{ say("settings-ssl") }}</dt>
            <dd>{{ settings.ssl_enforcement ?? say("settings-unset") }}</dd>
          </dl>
          <div class="mt-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-password-policy") }}
            </div>
            <pre
              class="mt-1.5 overflow-x-auto rounded border border-border bg-surface-2 p-2 font-mono text-[10.5px]"
              >{{ JSON.stringify(settings.password_policy ?? null, null, 2) }}</pre
            >
          </div>
          <div class="mt-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("settings-brute-force") }}
            </div>
            <pre
              class="mt-1.5 overflow-x-auto rounded border border-border bg-surface-2 p-2 font-mono text-[10.5px]"
              >{{ JSON.stringify(settings.brute_force ?? null, null, 2) }}</pre
            >
          </div>
        </div>

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
