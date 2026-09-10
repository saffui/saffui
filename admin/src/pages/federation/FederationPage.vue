<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { afterWrites } from "@/services/writes";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import AppToggle from "@/components/AppToggle.vue";
import {
  createIdp,
  deleteIdp,
  kindOf,
  listDirectories,
  listIdps,
  updateIdp,
} from "@/services/federation";
import type { DirectoryRow, IdpRow } from "@/models/federation";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const idps = ref<IdpRow[]>([]);
const directories = ref<DirectoryRow[]>([]);
const failed = ref("");

async function load() {
  try {
    [idps.value, directories.value] = await Promise.all([
      listIdps(realm.value),
      listDirectories(realm.value),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

// Event receivers and outbound connectors live on the events page, trusted
// platforms in their own section below; here stay the providers people
// sign in through.
const brokers = computed(() =>
  idps.value.filter((row) => {
    const kind = kindOf(row);
    return !kind.startsWith("caep") && kind !== "scim-outbound" && kind !== "workload";
  }),
);

/// The platforms whose workloads may exchange their own tokens for this
/// realm's: CI runners, cluster workloads, anything with an issuer.
const platforms = computed(() => idps.value.filter((row) => kindOf(row) === "workload"));

function bagText(row: IdpRow, key: string): string {
  const held = row.configs?.[key];
  if (held === undefined) return "";
  if (typeof held === "string") return held;
  return held.Str ?? "";
}

const editing = ref<null | { alias: string | null }>(null);
const form = ref({
  alias: "",
  displayName: "",
  enabled: true,
  issuer: "",
  jwksUri: "",
  audience: "",
  subjects: "",
  clientId: "",
  algs: "",
});
const saving = ref(false);
const doomName = ref("");

function openCreate() {
  editing.value = { alias: null };
  form.value = {
    alias: "",
    displayName: "",
    enabled: true,
    issuer: "",
    jwksUri: "",
    audience: "",
    subjects: "",
    clientId: "",
    algs: "",
  };
  doomName.value = "";
}

function openEdit(row: IdpRow) {
  editing.value = { alias: row.provider_id };
  form.value = {
    alias: row.provider_id,
    displayName: row.display_name,
    enabled: row.enabled !== false,
    issuer: bagText(row, "issuer"),
    jwksUri: bagText(row, "jwks_uri"),
    audience: bagText(row, "audience"),
    subjects: bagText(row, "subject_patterns"),
    clientId: bagText(row, "client_id"),
    algs: bagText(row, "allowed_algs"),
  };
  doomName.value = "";
}

/// The bag as the server reads it: only the keys a platform knows, the
/// algorithms only when the operator named some.
function bagged(): Record<string, { Str: string }> {
  const bag: Record<string, { Str: string }> = {
    kind: { Str: "workload" },
    issuer: { Str: form.value.issuer.trim() },
    jwks_uri: { Str: form.value.jwksUri.trim() },
    audience: { Str: form.value.audience.trim() },
    subject_patterns: { Str: form.value.subjects.trim() },
    client_id: { Str: form.value.clientId.trim() },
  };
  if (form.value.algs.trim()) bag.allowed_algs = { Str: form.value.algs.trim() };
  return bag;
}

async function save() {
  if (!editing.value) return;
  saving.value = true;
  try {
    const alias = editing.value.alias ?? form.value.alias.trim();
    const body = {
      provider_id: alias,
      name: alias,
      display_name: form.value.displayName.trim(),
      description: "",
      enabled: form.value.enabled,
      trust_email: false,
      configs: bagged(),
    };
    if (editing.value.alias) await updateIdp(realm.value, editing.value.alias, body);
    else await createIdp(realm.value, body);
    editing.value = null;
    idps.value = await listIdps(realm.value);
  } catch {
    // The toast already said.
  } finally {
    saving.value = false;
  }
}

async function drop() {
  if (!editing.value?.alias) return;
  try {
    await deleteIdp(realm.value, editing.value.alias);
    editing.value = null;
    idps.value = await listIdps(realm.value);
  } catch {
    // The toast already said.
  }
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("federation-title") }}</h1>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("federation-idps") }}
    </h2>
    <p v-if="!brokers.length" class="mt-2 text-xs text-muted">{{ say("federation-no-idps") }}</p>
    <div v-else class="sf-list mt-2 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
            <th>{{ say("clients-col-name") }}</th>
            <th>{{ say("federation-col-alias") }}</th>
            <th>{{ say("federation-col-trust") }}</th>
            <th>{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in brokers"
            :key="row.internal_id"
            class="border-b border-border/60 last:border-0"
          >
            <td>{{ row.display_name || row.name }}</td>
            <td class="font-mono text-[11.5px]">{{ row.provider_id }}</td>
            <td>
              <span
                v-if="row.trust_email"
                class="inline-flex items-center gap-1.5 text-[10.5px] text-ok"
              >
                {{ say("federation-trusted") }}
              </span>
            </td>
            <td class="text-[10.5px]">
              {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("federation-directories") }}
    </h2>
    <p v-if="!directories.length" class="mt-2 text-xs text-muted">
      {{ say("federation-no-directories") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in directories"
        :key="row.alias"
        class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <span class="font-mono text-[11.5px]">{{ row.alias }}</span>
        <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">
          {{ say("federation-priority") }} {{ row.priority }}
        </span>
        <span class="ml-auto text-[10.5px]" :class="row.enabled === false ? 'text-danger' : 'text-faint'">
          {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
        </span>
      </div>
    </div>

    <div class="mt-6 flex max-w-3xl flex-wrap items-center gap-2">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("federation-platforms") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="openCreate"
      >
        {{ say("federation-add-platform") }}
      </button>
    </div>
    <p v-if="!platforms.length" class="mt-2 text-xs text-muted">
      {{ say("federation-no-platforms") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in platforms"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <button type="button" class="font-medium hover:text-accent" @click="openEdit(row)">
            {{ row.display_name || row.name }}
          </button>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
            {{ say("platform-acts-as") }} {{ bagText(row, "client_id") }}
          </span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">{{ bagText(row, "issuer") }}</div>
      </div>
    </div>

    <AppDrawer
      v-if="editing"
      :title="editing.alias ?? say('federation-new-platform')"
      subtitle="workload"
      @close="editing = null"
    >
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="save">
        <label v-if="!editing.alias" class="block text-[11px] font-medium text-muted">
          {{ say("connector-alias") }}
          <input
            v-model="form.alias"
            required
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("connector-display") }}
          <input
            v-model="form.displayName"
            class="sf-field mt-1"
          />
        </label>
        <AppToggle v-model="form.enabled">{{ say("connector-enabled") }}</AppToggle>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("platform-issuer") }}
          <input
            v-model="form.issuer"
            required
            spellcheck="false"
            placeholder="https://token.actions.githubusercontent.com"
            class="sf-field mt-1 font-mono"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("platform-jwks") }}
          <input
            v-model="form.jwksUri"
            required
            spellcheck="false"
            placeholder="https://token.actions.githubusercontent.com/.well-known/jwks"
            class="sf-field mt-1 font-mono"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("connector-audience") }}
          <input
            v-model="form.audience"
            required
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
          <span class="mt-0.5 block font-normal text-faint">
            {{ say("platform-audience-hint") }}
          </span>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("platform-subjects") }}
          <textarea
            v-model="form.subjects"
            required
            spellcheck="false"
            rows="3"
            placeholder="repo:acme/deploy:ref:refs/heads/main repo:acme/api:*"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink"
          ></textarea>
          <span class="mt-0.5 block font-normal text-faint">
            {{ say("platform-subjects-hint") }}
          </span>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("platform-client") }}
          <input
            v-model="form.clientId"
            required
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
          <span class="mt-0.5 block font-normal text-faint">
            {{ say("platform-client-hint") }}
          </span>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("platform-algs") }}
          <input
            v-model="form.algs"
            spellcheck="false"
            placeholder="RS256 ES256"
            class="sf-field mt-1 font-mono"
          />
          <span class="mt-0.5 block font-normal text-faint">
            {{ say("platform-algs-hint") }}
          </span>
        </label>

        <button
          type="submit"
          :disabled="saving"
          class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink disabled:opacity-40"
        >
          {{ say("settings-save") }}
        </button>

        <div v-if="editing.alias" class="mt-2 rounded-lg border border-danger/40 p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
            {{ say("settings-danger") }}
          </div>
          <p class="mt-1 text-[11px] text-muted">{{ say("platform-delete-lede") }}</p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomName"
              :placeholder="editing.alias"
              spellcheck="false"
              class="sf-field font-mono"
            />
            <button
              type="button"
              class="sf-button sf-button-danger disabled:opacity-40"
              :disabled="doomName !== editing.alias"
              @click="drop"
            >
              {{ say("platform-delete") }}
            </button>
          </div>
        </div>
      </form>
    </AppDrawer>
  </div>
</template>
