<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
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
  NAME_ID_FORMATS,
  PERSISTENT_NAME_ID,
  SAML_ATTRIBUTE_MAPPER,
  SAML_ROLE_MAPPER,
  type BrokerProtocol,
  emptyMapperDraft,
  findProviderBlocker,
  mapperDraft,
  mapperMutation,
  mapperTypeLabel,
  mapperTypesFor,
  providerDraft,
  providerMutation,
  readProtocol,
  samlMetadataAddress,
} from "./forms";
import { presetDraft, type ProviderPreset } from "./providerCatalog";

const props = defineProps<{ realm: string; row?: IdpRow; preset?: ProviderPreset }>();
const emit = defineEmits<{ close: []; saved: []; deleted: [] }>();

const current = ref<"configuration" | "mappers">("configuration");
const draft = ref(props.row ? providerDraft(props.row) : presetDraft(props.preset));
const saving = ref(false);
const doomName = ref("");
const mappers = ref<IdpMapperRow[]>([]);
const roles = ref<RoleRow[]>([]);
const mapperOpen = ref(false);
const mapperId = ref<string | null>(null);
const rule = ref(emptyMapperDraft());

const alias = computed(() => props.row?.provider_id ?? draft.value.alias.trim());
/// The protocol the saved provider speaks: its rules read what it sends, whatever
/// the form above is being changed to.
const savedProtocol = computed(() => (props.row ? readProtocol(props.row) : draft.value.protocol));
const mapperTypes = computed(() => mapperTypesFor(savedProtocol.value));
const blocker = computed(() => findProviderBlocker(draft.value));
const metadataAddress = computed(() =>
  props.row ? samlMetadataAddress(window.location.origin, props.realm, props.row.provider_id) : "",
);
const protocolLabel = computed(() =>
  draft.value.protocol === "saml"
    ? "idp-protocol-saml"
    : draft.value.protocol === "oauth2"
      ? "idp-protocol-oauth2"
      : "idp-oidc",
);

const endpointFields = computed(() =>
  draft.value.protocol === "oidc"
    ? ([
        ["issuer", "idp-issuer", "idp-issuer-help"],
        ["authorizationEndpoint", "idp-authorization-endpoint", ""],
        ["tokenEndpoint", "idp-token-endpoint", ""],
        ["jwksUri", "idp-jwks-uri", "idp-jwks-uri-help"],
      ] as const)
    : ([
        ["authorizationEndpoint", "idp-authorization-endpoint", ""],
        ["tokenEndpoint", "idp-token-endpoint", ""],
        ["userinfoEndpoint", "idp-userinfo-endpoint", "idp-userinfo-endpoint-help"],
      ] as const),
);
const identityFields = [
  ["subjectPointer", "idp-subject-pointer", "idp-subject-pointer-help"],
  ["usernamePointer", "idp-username-pointer", ""],
  ["emailPointer", "idp-email-pointer", ""],
  ["emailVerifiedPointer", "idp-email-verified-pointer", "idp-email-verified-pointer-help"],
] as const;
const emailListFields = [
  ["emailsListPointer", "idp-emails-list-pointer"],
  ["emailsAddressPointer", "idp-emails-address-pointer"],
  ["emailsVerifiedPointer", "idp-emails-verified-pointer"],
  ["emailsPrimaryPointer", "idp-emails-primary-pointer"],
] as const;
const samlFields = [
  ["principalAttribute", "idp-principal-attribute", "idp-principal-attribute-help"],
  ["usernameAttribute", "idp-username-attribute", "idp-username-attribute-help"],
  ["emailAttribute", "idp-email-attribute", "idp-email-attribute-help"],
  ["spEntityId", "idp-sp-entity-id", "idp-sp-entity-id-help"],
] as const;

/// A saved provider does not cross between SAML and the other protocols: its rules
/// read what one of them sends and would stop applying.
function crossesSaml(protocol: BrokerProtocol): boolean {
  return Boolean(props.row) && (savedProtocol.value === "saml") !== (protocol === "saml");
}

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
    const body = providerMutation(draft.value);
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

async function copyMetadataAddress() {
  try {
    await navigator.clipboard.writeText(metadataAddress.value);
  } catch {
    // Selectable by hand.
  }
}

function newMapper() {
  mapperId.value = null;
  rule.value = emptyMapperDraft(savedProtocol.value);
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
</script>

<template>
  <AppDrawer
    :title="props.row?.display_name || props.row?.provider_id || say('idp-new')"
    :subtitle="props.row?.provider_id || say(protocolLabel)"
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
        {{ say(tab === "mappers" && savedProtocol === "saml" ? "idp-tab-mappers-saml" : `idp-tab-${tab}`) }}
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
        <label class="text-[11px] font-medium text-muted sm:col-span-2">
          <span class="inline-flex items-center gap-1">
            {{ say("idp-protocol") }} <AppHint name="idp-protocol-help" />
          </span>
          <select v-model="draft.protocol" class="sf-field mt-1">
            <option value="oidc" :disabled="crossesSaml('oidc')">{{ say("idp-oidc") }}</option>
            <option value="oauth2" :disabled="crossesSaml('oauth2')">{{ say("idp-protocol-oauth2") }}</option>
            <option value="saml" :disabled="crossesSaml('saml')">{{ say("idp-protocol-saml") }}</option>
          </select>
        </label>
        <AppToggle v-model="draft.enabled">{{ say("connector-enabled") }}</AppToggle>
        <span class="inline-flex items-center gap-1">
          <AppToggle v-model="draft.trustEmail">{{ say("idp-trust-email") }}</AppToggle>
          <AppHint name="idp-trust-email-help" />
        </span>
      </section>

      <section v-if="draft.protocol !== 'saml'" class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-endpoints") }}
        </h3>
        <div class="mt-3 grid gap-3">
          <label v-for="field in endpointFields" :key="field[0]" class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say(field[1]) }} <AppHint v-if="field[2]" :name="field[2]" />
            </span>
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

      <section v-if="draft.protocol === 'oauth2'" class="border-t border-border pt-4">
        <h3 class="inline-flex items-center gap-1 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-identity") }} <AppHint name="idp-identity-help" />
        </h3>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label v-for="field in identityFields" :key="field[0]" class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say(field[1]) }} <AppHint v-if="field[2]" :name="field[2]" />
            </span>
            <input
              v-model="draft[field[0]]"
              :required="field[0] === 'subjectPointer'"
              spellcheck="false"
              placeholder="/"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </div>
        <h4 class="mt-4 inline-flex items-center gap-1 text-[11px] font-medium text-muted">
          {{ say("idp-emails") }} <AppHint name="idp-emails-help" />
        </h4>
        <div class="mt-2 grid gap-3 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted sm:col-span-2">
            {{ say("idp-emails-endpoint") }}
            <input
              v-model="draft.emailsEndpoint"
              type="url"
              spellcheck="false"
              placeholder="https://"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label v-for="field in emailListFields" :key="field[0]" class="text-[11px] font-medium text-muted">
            {{ say(field[1]) }}
            <input
              v-model="draft[field[0]]"
              :disabled="!draft.emailsEndpoint"
              spellcheck="false"
              class="sf-field mt-1 font-mono disabled:opacity-60"
            />
          </label>
        </div>
      </section>

      <section v-if="draft.protocol === 'saml'" class="border-t border-border pt-4">
        <h3 class="inline-flex items-center gap-1 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-saml") }} <AppHint name="idp-saml-help" />
        </h3>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted sm:col-span-2">
            <span class="inline-flex items-center gap-1">
              {{ say("idp-metadata") }} <AppHint name="idp-metadata-help" />
            </span>
            <textarea
              v-model="draft.idpMetadata"
              required
              rows="6"
              spellcheck="false"
              class="sf-field mt-1 font-mono text-[11px]"
            ></textarea>
          </label>
          <label class="text-[11px] font-medium text-muted sm:col-span-2">
            <span class="inline-flex items-center gap-1">
              {{ say("idp-name-id-format") }} <AppHint name="idp-name-id-format-help" />
            </span>
            <select v-model="draft.nameIdFormat" class="sf-field mt-1">
              <option v-for="format in NAME_ID_FORMATS" :key="format[0]" :value="format[0]">
                {{ say(format[1]) }}
              </option>
            </select>
          </label>
          <label v-for="field in samlFields" :key="field[0]" class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say(field[1]) }} <AppHint :name="field[2]" />
            </span>
            <input
              v-model="draft[field[0]]"
              :required="field[0] === 'principalAttribute' && draft.nameIdFormat !== PERSISTENT_NAME_ID"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </div>
        <div v-if="props.row" class="mt-4 space-y-1">
          <span class="inline-flex items-center gap-1 text-[11px] font-medium text-muted">
            {{ say("idp-saml-metadata-address") }} <AppHint name="idp-saml-metadata-address-help" />
          </span>
          <div class="flex min-w-0 items-center gap-2">
            <code class="min-w-0 flex-1 truncate sf-field font-mono text-[11px]">{{ metadataAddress }}</code>
            <button type="button" class="sf-button sf-button-secondary" @click="copyMetadataAddress">
              {{ say("action-copy") }}
            </button>
          </div>
          <p v-if="props.row.enabled === false" class="text-[11px] text-muted">
            {{ say("idp-saml-metadata-disabled") }}
          </p>
        </div>
      </section>

      <section v-if="draft.protocol !== 'saml'" class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("idp-client") }}
        </h3>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted">
            {{ say("idp-client-id") }}
            <input v-model="draft.clientId" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say("idp-client-secret") }} <AppHint name="idp-client-secret-help" />
            </span>
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
            <input
              v-model="draft.scope"
              :required="draft.protocol === 'oidc'"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label v-if="draft.protocol === 'oidc'" class="text-[11px] font-medium text-muted">
            {{ say("platform-algs") }}
            <input v-model="draft.algorithms" spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say("idp-token-auth") }} <AppHint name="idp-token-auth-help" />
            </span>
            <select v-model="draft.tokenAuth" class="sf-field mt-1">
              <option value="client_secret_basic">{{ say("idp-token-auth-basic") }}</option>
              <option value="client_secret_post">{{ say("idp-token-auth-post") }}</option>
            </select>
          </label>
          <span class="inline-flex items-center gap-1 sm:col-span-2">
            <AppToggle v-model="draft.pkce">{{ say("idp-pkce") }}</AppToggle>
            <AppHint name="idp-pkce-help" />
          </span>
        </div>
      </section>

      <p v-if="blocker" class="text-[11px] text-warn" role="alert">{{ say(blocker) }}</p>
      <button type="submit" :disabled="saving || Boolean(blocker)" class="sf-button sf-button-primary">
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
        <p class="text-xs leading-5 text-muted">
          {{ say(savedProtocol === "saml" ? "idp-mappers-lede-saml" : "idp-mappers-lede") }}
        </p>
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
              <td class="text-[11px] text-muted">{{ say(mapperTypeLabel(row.mapper_type)) }}</td>
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
            <span class="inline-flex items-center gap-1">
              {{ say("mappers-col-type") }} <AppHint name="idp-mapper-type-help" />
            </span>
            <select v-model="rule.type" class="sf-field mt-1">
              <option v-for="type in mapperTypes" :key="type" :value="type">{{ say(mapperTypeLabel(type)) }}</option>
            </select>
          </label>
          <label class="text-[11px] font-medium text-muted">
            <span class="inline-flex items-center gap-1">
              {{ say("idp-mapper-sync") }} <AppHint name="idp-mapper-sync-help" />
            </span>
            <select v-model="rule.syncMode" class="sf-field mt-1">
              <option value="import">{{ say("idp-mapper-import") }}</option>
              <option value="force">{{ say("idp-mapper-force") }}</option>
            </select>
          </label>
          <template v-if="rule.type === ATTRIBUTE_MAPPER">
            <label class="text-[11px] font-medium text-muted">
              <span class="inline-flex items-center gap-1">
                {{ say("idp-mapper-claim") }} <AppHint name="idp-mapper-claim-help" />
              </span>
              <input v-model="rule.claim" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
            <label class="text-[11px] font-medium text-muted sm:col-span-2">
              <span class="inline-flex items-center gap-1">
                {{ say("idp-mapper-user-attribute") }} <AppHint name="idp-mapper-user-attribute-help" />
              </span>
              <input v-model="rule.userAttribute" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
          </template>
          <template v-else-if="rule.type === SAML_ATTRIBUTE_MAPPER">
            <label class="text-[11px] font-medium text-muted">
              <span class="inline-flex items-center gap-1">
                {{ say("idp-mapper-attribute-name") }} <AppHint name="idp-mapper-attribute-name-help" />
              </span>
              <input v-model="rule.attributeName" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
            <label class="text-[11px] font-medium text-muted sm:col-span-2">
              <span class="inline-flex items-center gap-1">
                {{ say("idp-mapper-user-attribute") }} <AppHint name="idp-mapper-user-attribute-help" />
              </span>
              <input v-model="rule.userAttribute" required spellcheck="false" class="sf-field mt-1 font-mono" />
            </label>
            <span class="inline-flex items-center gap-1 sm:col-span-2">
              <AppToggle v-model="rule.multivalued">{{ say("idp-mapper-multivalued") }}</AppToggle>
              <AppHint name="idp-mapper-multivalued-help" />
            </span>
          </template>
          <template v-else>
            <template v-if="rule.type === SAML_ROLE_MAPPER">
              <label class="text-[11px] font-medium text-muted">
                <span class="inline-flex items-center gap-1">
                  {{ say("idp-mapper-attribute-name") }} <AppHint name="idp-mapper-attribute-name-help" />
                </span>
                <input v-model="rule.attributeName" required spellcheck="false" class="sf-field mt-1 font-mono" />
              </label>
              <label class="text-[11px] font-medium text-muted">
                <span class="inline-flex items-center gap-1">
                  {{ say("idp-mapper-attribute-value") }} <AppHint name="idp-mapper-attribute-value-help" />
                </span>
                <input v-model="rule.attributeValue" required spellcheck="false" class="sf-field mt-1 font-mono" />
              </label>
            </template>
            <label class="text-[11px] font-medium text-muted sm:col-span-2">
              <span class="inline-flex items-center gap-1">
                {{ say("idp-mapper-local-role") }} <AppHint name="idp-mapper-local-role-help" />
              </span>
              <select v-model="rule.role" required class="sf-field mt-1">
                <option disabled value="">{{ say("idp-mapper-choose-role") }}</option>
                <option v-for="role in roles" :key="role.role_id" :value="role.role_id">
                  {{ role.display_name || role.name }}
                </option>
              </select>
            </label>
          </template>
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
