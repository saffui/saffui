<script setup lang="ts">
import { ref, watch } from "vue";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import type { ClientDetail } from "@/models/client";
import { rotateClientSecret, updateClient } from "@/services/clients";
import {
  clientKeyConfiguration,
  clientKeyDraft,
  type ClientKeyDraft,
} from "./clientKeyForm";

const props = defineProps<{ realm: string; client: ClientDetail }>();
const emit = defineEmits<{ updated: [] }>();

const draft = ref<ClientKeyDraft>(clientKeyDraft(props.client.key_configuration));
const formError = ref("");
const saving = ref(false);
const freshSecret = ref("");
const tlsForm = ref<"off" | "dns" | "uri" | "dn">("off");
const tlsValue = ref("");
const ENCRYPTION_ROWS = [
  {
    label: "client-keys-id-token-encryption",
    algorithm: "idTokenEncryptionAlgorithm",
    method: "idTokenEncryptionMethod",
  },
  {
    label: "client-keys-userinfo-encryption",
    algorithm: "userinfoEncryptionAlgorithm",
    method: "userinfoEncryptionMethod",
  },
  {
    label: "client-keys-request-encryption",
    algorithm: "requestObjectEncryptionAlgorithm",
    method: "requestObjectEncryptionMethod",
  },
] as const;

function adoptTls(client: ClientDetail) {
  tlsForm.value = client.tls_san_dns
    ? "dns"
    : client.tls_san_uri
      ? "uri"
      : client.tls_subject_dn
        ? "dn"
        : "off";
  tlsValue.value = client.tls_san_dns ?? client.tls_san_uri ?? client.tls_subject_dn ?? "";
}

watch(
  () => props.client,
  (client) => {
    draft.value = clientKeyDraft(client.key_configuration);
    adoptTls(client);
  },
  { immediate: true },
);

async function saveKeys() {
  const result = clientKeyConfiguration(
    draft.value,
    props.client.key_configuration.authentication_method,
  );
  if (!result.configuration) {
    formError.value = say(`client-keys-error-${result.error}`);
    return;
  }
  saving.value = true;
  formError.value = "";
  try {
    await updateClient(props.realm, props.client.client_id, {
      key_configuration: result.configuration,
    });
    emit("updated");
  } catch {
    // The toast carries the refusal.
  } finally {
    saving.value = false;
  }
}

function tlsUpdate(): { tls_san_dns?: string; tls_san_uri?: string; tls_subject_dn?: string } {
  const value = tlsValue.value.trim();
  const keys = { dns: "tls_san_dns", uri: "tls_san_uri", dn: "tls_subject_dn" } as const;
  if (tlsForm.value !== "off" && value) return { [keys[tlsForm.value]]: value };
  if (props.client.tls_san_dns != null) return { tls_san_dns: "" };
  if (props.client.tls_san_uri != null) return { tls_san_uri: "" };
  if (props.client.tls_subject_dn != null) return { tls_subject_dn: "" };
  return {};
}

async function saveTls() {
  saving.value = true;
  try {
    await updateClient(props.realm, props.client.client_id, tlsUpdate());
    emit("updated");
  } catch {
    // The toast carries the refusal.
  } finally {
    saving.value = false;
  }
}

async function rotate() {
  try {
    freshSecret.value = await rotateClientSecret(props.realm, props.client.client_id);
  } catch {
    // The toast carries the refusal.
  }
}

async function copyFreshSecret() {
  try {
    await navigator.clipboard.writeText(freshSecret.value);
  } catch {
    // The field stays selectable.
  }
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <section class="rounded-md border border-border bg-surface-2/40 p-3.5">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("client-keys-source-title") }}
      </div>
      <div class="mt-3 grid gap-3 sm:grid-cols-2">
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-auth-method") }}
          <input
            :value="client.key_configuration.authentication_method"
            readonly
            class="sf-field mt-1 font-mono opacity-75"
          />
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-source") }}
          <select v-model="draft.source" class="sf-field mt-1">
            <option value="none">{{ say("client-keys-source-none") }}</option>
            <option value="uri">{{ say("client-keys-source-uri") }}</option>
            <option value="inline">{{ say("client-keys-source-inline") }}</option>
          </select>
        </label>
      </div>
      <label v-if="draft.source === 'uri'" class="mt-3 block text-[11px] font-medium text-muted">
        {{ say("client-keys-jwks-uri") }}
        <input
          v-model="draft.jwksUri"
          type="url"
          required
          placeholder="https://app.example/.well-known/jwks.json"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
        />
      </label>
      <label v-if="draft.source === 'inline'" class="mt-3 block text-[11px] font-medium text-muted">
        {{ say("client-keys-inline-jwks") }}
        <textarea
          v-model="draft.inlineJwks"
          rows="8"
          class="sf-field mt-1 font-mono text-[10.5px]"
          spellcheck="false"
        ></textarea>
      </label>
      <p class="mt-2 text-[10.5px] leading-4 text-faint">{{ say("client-keys-source-help") }}</p>
    </section>

    <section>
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("client-keys-signing-title") }}
      </div>
      <div class="mt-2 grid gap-3 sm:grid-cols-2">
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-id-token-signing") }}
          <select v-model="draft.idTokenSigning" class="sf-field mt-1 font-mono">
            <option value="">{{ say("client-keys-realm-default") }}</option>
            <option v-for="algorithm in client.key_capabilities.signing_algorithms" :key="algorithm" :value="algorithm">{{ algorithm }}</option>
          </select>
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-userinfo-signing") }}
          <select v-model="draft.userinfoSigning" class="sf-field mt-1 font-mono">
            <option value="">{{ say("client-keys-unsigned") }}</option>
            <option v-for="algorithm in client.key_capabilities.signing_algorithms" :key="algorithm" :value="algorithm">{{ algorithm }}</option>
          </select>
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-request-signing") }}
          <select v-model="draft.requestObjectSigning" class="sf-field mt-1 font-mono">
            <option value="">{{ say("settings-unset") }}</option>
            <option v-for="algorithm in client.key_capabilities.signing_algorithms" :key="algorithm" :value="algorithm">{{ algorithm }}</option>
          </select>
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("client-keys-assertion-signing") }}
          <select
            v-model="draft.clientAssertionSigning"
            :disabled="client.key_configuration.authentication_method !== 'private-key-jwt'"
            class="sf-field mt-1 font-mono disabled:opacity-50"
          >
            <option value="">{{ say("settings-unset") }}</option>
            <option v-for="algorithm in client.key_capabilities.signing_algorithms" :key="algorithm" :value="algorithm">{{ algorithm }}</option>
          </select>
        </label>
      </div>
    </section>

    <section>
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("client-keys-encryption-title") }}
      </div>
      <div class="mt-2 flex flex-col gap-3">
        <div
          v-for="row in ENCRYPTION_ROWS"
          :key="row.label"
          class="grid gap-2 sm:grid-cols-[1fr_1fr_1fr] sm:items-end"
        >
          <span class="pb-2 text-[11px] font-medium text-muted">{{ say(row.label) }}</span>
          <label class="text-[10.5px] text-faint">
            {{ say("client-keys-algorithm") }}
            <select v-model="draft[row.algorithm]" class="sf-field mt-1 font-mono">
              <option value="">{{ say("settings-unset") }}</option>
              <option v-for="algorithm in client.key_capabilities.encryption_algorithms" :key="algorithm" :value="algorithm">{{ algorithm }}</option>
            </select>
          </label>
          <label class="text-[10.5px] text-faint">
            {{ say("client-keys-method") }}
            <select v-model="draft[row.method]" class="sf-field mt-1 font-mono">
              <option value="">{{ say("settings-unset") }}</option>
              <option v-for="method in client.key_capabilities.encryption_methods" :key="method" :value="method">{{ method }}</option>
            </select>
          </label>
        </div>
      </div>
    </section>

    <p v-if="formError" class="text-[11px] text-danger" role="alert">{{ formError }}</p>
    <button type="button" :disabled="saving" class="self-start sf-button sf-button-primary" @click="saveKeys">
      {{ say("client-keys-save") }}
    </button>

    <section
      v-if="client.key_configuration.authentication_method === 'client-secret'"
      class="border-t border-border pt-4"
    >
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("client-secret-title") }} <AppHint name="client-secret-help" />
      </div>
      <button type="button" class="mt-2 sf-button sf-button-secondary" @click="rotate">
        {{ say("client-rotate-secret") }}
      </button>
      <div v-if="freshSecret" class="mt-2 flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2">
        <code class="min-w-0 flex-1 select-all break-all font-mono text-[11px]">{{ freshSecret }}</code>
        <button type="button" class="sf-button sf-button-secondary" @click="copyFreshSecret">
          {{ say("action-copy") }}
        </button>
      </div>
      <p v-if="freshSecret" class="mt-1 text-[10.5px] text-warn">{{ say("settings-secret-once") }}</p>
    </section>

    <section
      v-if="client.key_configuration.authentication_method === 'tls-client-auth'"
      class="border-t border-border pt-4"
    >
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("client-tls-title") }} <AppHint name="client-tls-help" />
      </div>
      <div class="mt-2 flex gap-2">
        <select v-model="tlsForm" class="sf-field max-w-44">
          <option value="off">{{ say("client-tls-off") }}</option>
          <option value="dns">{{ say("client-tls-dns") }}</option>
          <option value="uri">{{ say("client-tls-uri") }}</option>
          <option value="dn">{{ say("client-tls-dn") }}</option>
        </select>
        <input
          v-if="tlsForm !== 'off'"
          v-model="tlsValue"
          :placeholder="tlsForm === 'dns' ? 'app.example' : tlsForm === 'uri' ? 'spiffe://app' : 'CN=app,O=Acme'"
          class="min-w-0 flex-1 sf-field font-mono"
          spellcheck="false"
        />
      </div>
      <button type="button" :disabled="saving" class="mt-2 sf-button sf-button-secondary" @click="saveTls">
        {{ say("client-tls-save") }}
      </button>
    </section>
  </div>
</template>
