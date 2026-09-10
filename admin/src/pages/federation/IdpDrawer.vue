<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import AppToggle from "@/components/AppToggle.vue";
import { say } from "@/i18n";
import type { RoleRow } from "@/models/directory";
import type { IdpMapperRow, IdpRow } from "@/models/federation";
import { listRoles } from "@/services/directory";
import {
  createIdp,
  createIdpMapper,
  deleteIdp,
  deleteIdpMapper,
  listIdpMappers,
  updateIdp,
  updateIdpMapper,
} from "@/services/federation";
import {
  ATTRIBUTE_MAPPER,
  ROLE_MAPPER,
  emptyMapperDraft,
  emptyOidcDraft,
  mapperDraft,
  mapperMutation,
  oidcDraft,
  oidcMutation,
} from "./forms";

const props = defineProps<{ realm: string; row?: IdpRow }>();
const emit = defineEmits<{ close: []; saved: []; deleted: [] }>();

const current = ref<"configuration" | "mappers">("configuration");
const draft = ref(props.row ? oidcDraft(props.row) : emptyOidcDraft());
const saving = ref(false);
const doomName = ref("");
const mappers = ref<IdpMapperRow[]>([]);
const roles = ref<RoleRow[]>([]);
const mapperOpen = ref(false);
const mapperId = ref<string | null>(null);
const rule = ref(emptyMapperDraft());

const alias = computed(() => props.row?.provider_id ?? draft.value.alias.trim());

async function loadRules() {
  if (!props.row) return;
  const [held, catalogue] = await Promise.all([
    listIdpMappers(props.realm, props.row.provider_id),
    listRoles(props.realm, 0, 200),
  ]);
  mappers.value = held;
  roles.value = catalogue.items.filter((role) => role.client_id === null);
}

onMounted(() => void loadRules());

async function saveProvider() {
  saving.value = true;
  try {
    const body = oidcMutation(draft.value);
    if (props.row) await updateIdp(props.realm, props.row.provider_id, body);
    else await createIdp(props.realm, body);
    emit("saved");
  } catch {
    // The toast carries the refusal.
  } finally {
    saving.value = false;
  }
}

async function dropProvider() {
  if (!props.row || doomName.value !== props.row.provider_id) return;
  try {
    await deleteIdp(props.realm, props.row.provider_id);
    emit("deleted");
  } catch {
    // The toast carries the refusal.
  }
}

function newMapper() {
  mapperId.value = null;
  rule.value = emptyMapperDraft();
  mapperOpen.value = true;
}

function editMapper(row: IdpMapperRow) {
  mapperId.value = row.mapper_id;
  rule.value = mapperDraft(row);
  mapperOpen.value = true;
}

async function saveMapper() {
  if (!props.row) return;
  try {
    const body = mapperMutation(rule.value);
    if (mapperId.value) {
      await updateIdpMapper(props.realm, props.row.provider_id, mapperId.value, body);
    } else {
      await createIdpMapper(props.realm, props.row.provider_id, body);
    }
    mapperOpen.value = false;
    mappers.value = await listIdpMappers(props.realm, props.row.provider_id);
  } catch {
    // The toast carries the refusal.
  }
}

async function dropMapper(row: IdpMapperRow) {
  if (!props.row) return;
  try {
    await deleteIdpMapper(props.realm, props.row.provider_id, row.mapper_id);
    mappers.value = await listIdpMappers(props.realm, props.row.provider_id);
  } catch {
    // The toast carries the refusal.
  }
}

function typeLabel(row: IdpMapperRow): string {
  return row.mapper_type === ATTRIBUTE_MAPPER
    ? say("idp-mapper-attribute")
    : say("idp-mapper-role");
}
</script>

<template>
  <AppDrawer
    :title="props.row?.display_name || props.row?.provider_id || say('idp-new')"
    :subtitle="props.row?.provider_id || say('idp-oidc')"
    @close="emit('close')"
  >
    <div class="flex h-8 items-center gap-0.5 border-b border-border" role="tablist">
      <button
        v-for="tab in ['configuration', 'mappers'] as const"
        :key="tab"
        type="button"
        role="tab"
        :aria-selected="current === tab"
        :disabled="tab === 'mappers' && !props.row"
        class="h-8 border-b-2 px-3 text-xs disabled:cursor-not-allowed disabled:opacity-40"
        :class="current === tab ? 'border-accent text-ink' : 'border-transparent text-muted hover:text-ink'"
        @click="current = tab"
      >
        {{ say(`idp-tab-${tab}`) }}
      </button>
    </div>

    <form v-if="current === 'configuration'" class="mt-4 space-y-4" @submit.prevent="saveProvider">
      <section class="grid gap-3 sm:grid-cols-2">
        <label class="text-[11px] font-medium text-muted">
          {{ say("connector-alias") }}
          <input
            v-model="draft.alias"
            required
            spellcheck="false"
            :disabled="Boolean(props.row)"
            class="sf-field mt-1 font font-mono disabled:opacity-60"
          />
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("connector-display") }}
          <input v-model="draft.displayName" class="sf-field mt-1" />
        </label>
        <label class="text-[11px] font-medium text-muted sm:col-span-2">
          {{ say("idp-description") }}
          <input v-model="draft.description" class="sf-field mt-1" />
        </label>
        <AppToggle v-model="draft.enabled">{{ say("connector-enabled") }}</AppToggle>
        <AppToggle v-model="draft.trustEmail">{{ say("idp-trust-email") }}</AppToggle>
      </section>

      <section class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-endpoints") }}
        </h3>
        <div class="mt-3 grid gap-3">
          <label v-for="field in [
            ['issuer', 'idp-issuer'],
            ['authorizationEndpoint', 'idp-authorization-endpoint'],
            ['tokenEndpoint', 'idp-token-endpoint'],
            ['jwksUri', 'idp-jwks-uri'],
          ] as const" :key="field[0]" class="text-[11px] font-medium text-muted">
            {{ say(field[1]) }}
            <input
              v-model="draft[field[0]]"
              type="url"
              required
              spellcheck="false"
              placeholder="https://"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </div>
      </section>

      <section class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-client") }}
        </h3>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted">
            {{ say("idp-client-id") }}
            <input v-model="draft.clientId" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("idp-client-secret") }}
            <input
              v-model="draft.clientSecret"
              type="password"
              :required="!props.row"
              autocomplete="new-password"
              :placeholder="props.row ? say('idp-secret-kept') : ''"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("idp-scope") }}
            <input v-model="draft.scope" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("platform-algs") }}
            <input v-model="draft.algorithms" spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
        </div>
      </section>

      <button type="submit" :disabled="saving" class="sf-button sf-button-primary">
        {{ say("settings-save") }}
      </button>

      <section v-if="props.row" class="border-t border-danger/40 pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
          {{ say("settings-danger") }}
        </h3>
        <p class="mt-1 text-[11px] leading-4 text-muted">{{ say("idp-delete-lede") }}</p>
        <div class="mt-2 flex min-w-0 items-center gap-2">
          <input v-model="doomName" :placeholder="alias" class="min-w-0 flex-1 sf-field font-mono" />
          <button
            type="button"
            class="sf-button sf-button-danger"
            :disabled="doomName !== alias"
            @click="dropProvider"
          >
            {{ say("idp-delete") }}
          </button>
        </div>
      </section>
    </form>

    <section v-else class="mt-4">
      <div class="flex items-center justify-between gap-3">
        <p class="text-xs leading-5 text-muted">{{ say("idp-mappers-lede") }}</p>
        <button type="button" class="sf-button sf-button-primary" @click="newMapper">
          {{ say("idp-mapper-new") }}
        </button>
      </div>

      <div v-if="mappers.length" class="sf-list mt-3 overflow-x-auto">
        <table class="sf-table min-w-[420px]">
          <thead><tr><th>{{ say("mappers-col-name") }}</th><th>{{ say("mappers-col-type") }}</th><th></th></tr></thead>
          <tbody>
            <tr v-for="row in mappers" :key="row.mapper_id">
              <td>
                <button type="button" class="font-medium hover:text-accent" @click="editMapper(row)">
                  {{ row.name }}
                </button>
              </td>
              <td class="text-[11px] text-muted">{{ typeLabel(row) }}</td>
              <td class="text-right">
                <button type="button" class="sf-button sf-button-ghost" @click="dropMapper(row)">
                  {{ say("idp-mapper-delete") }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="mt-3 text-xs text-muted">{{ say("mappers-none") }}</p>

      <form v-if="mapperOpen" class="mt-4 space-y-3 border-t border-border pt-4" @submit.prevent="saveMapper">
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted">
            {{ say("mappers-col-name") }}
            <input v-model="rule.name" required class="sf-field mt-1" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("mappers-col-type") }}
            <select v-model="rule.type" class="sf-field mt-1">
              <option :value="ATTRIBUTE_MAPPER">{{ say("idp-mapper-attribute") }}</option>
              <option :value="ROLE_MAPPER">{{ say("idp-mapper-role") }}</option>
            </select>
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("idp-mapper-sync") }}
            <select v-model="rule.syncMode" class="sf-field mt-1">
              <option value="import">{{ say("idp-mapper-import") }}</option>
              <option value="force">{{ say("idp-mapper-force") }}</option>
            </select>
          </label>
          <template v-if="rule.type === ATTRIBUTE_MAPPER">
            <label class="text-[11px] font-medium text-muted">
              {{ say("idp-mapper-claim") }}
              <input v-model="rule.claim" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
            <label class="text-[11px] font-medium text-muted sm:col-span-2">
              {{ say("idp-mapper-user-attribute") }}
              <input v-model="rule.userAttribute" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
          </template>
          <label v-else class="text-[11px] font-medium text-muted sm:col-span-2">
            {{ say("idp-mapper-local-role") }}
            <select v-model="rule.role" required class="sf-field mt-1">
              <option disabled value="">{{ say("idp-mapper-choose-role") }}</option>
              <option v-for="role in roles" :key="role.role_id" :value="role.role_id">
                {{ role.display_name || role.name }}
              </option>
            </select>
          </label>
        </div>
        <div class="flex gap-2">
          <button type="submit" class="sf-button sf-button-primary">{{ say("settings-save") }}</button>
          <button type="button" class="sf-button sf-button-secondary" @click="mapperOpen = false">
            {{ say("idp-mapper-cancel") }}
          </button>
        </div>
      </form>
    </section>
  </AppDrawer>
</template>
