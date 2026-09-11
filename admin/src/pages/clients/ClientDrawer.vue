<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  attachMapperToClient,
  attachScope,
  deleteClient,
  detachMapperFromClient,
  detachScope,
  getClient,
  listAttachedScopes,
  listClientMappers,
  updateClient,
  getAgent,
  reshapeAgent,
} from "@/services/clients";
import { listRealmMappers, listScopeCatalogue } from "@/services/scopes";
import { createRole, deleteRole, listRoles } from "@/services/directory";
import type { RoleRow } from "@/models/directory";
import AppToggle from "@/components/AppToggle.vue";
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import AppStringList from "@/components/AppStringList.vue";
import { useRouter } from "vue-router";
import type { ClientDetail, ClientScope, ProtocolMapper } from "@/models/client";
import ClientKeysTab from "./ClientKeysTab.vue";
import { clientMapperPickerRows } from "@/pages/adminActionPickers";

const props = defineProps<{ realm: string; clientId: string }>();
const emit = defineEmits<{ close: [] }>();

const TABS = ["overview", "keys", "scopes", "mappers", "roles"] as const;
const tab = ref<(typeof TABS)[number]>("overview");

const client = ref<ClientDetail | null>(null);
const scopes = ref<ClientScope[]>([]);
const mappers = ref<ProtocolMapper[]>([]);
const mapperPickerOpen = ref(false);
const mapperPickerRows = ref<{ id: string; label: string; held: boolean }[]>([]);
const failed = ref("");

/// The roles this client is the audience of, apart from the realm's own.
const clientRoles = ref<RoleRow[]>([]);
const roleDraft = ref({ name: "", description: "" });
async function loadClientRoles() {
  const held = await listRoles(props.realm, 0, 200);
  clientRoles.value = held.items.filter((row) => row.client_id === props.clientId);
}
async function makeClientRole() {
  if (!roleDraft.value.name.trim()) return;
  try {
    await createRole(props.realm, {
      name: roleDraft.value.name.trim(),
      description: roleDraft.value.description.trim(),
      client_id: props.clientId,
    });
    roleDraft.value = { name: "", description: "" };
    await loadClientRoles();
  } catch {
    // The toast already said.
  }
}
async function dropClientRole(roleId: string) {
  try {
    await deleteRole(props.realm, roleId);
    await loadClientRoles();
  } catch {
    // The toast already said: a granted role refuses in words.
  }
}

async function load() {
  failed.value = "";
  try {
    [client.value, scopes.value, mappers.value] = await Promise.all([
      getClient(props.realm, props.clientId),
      listAttachedScopes(props.realm, props.clientId),
      listClientMappers(props.realm, props.clientId),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(async () => {
  void loadAgent();
  await load();
  adoptClient();
  try {
    await loadClientRoles();
  } catch {
    // Read-only callers still get the other tabs.
  }
});

// Required is granted without being asked for; offered waits to be asked.
const required = computed(() => scopes.value.filter((held) => !held.optional));
const offered = computed(() => scopes.value.filter((held) => held.optional));

const router = useRouter();
const draft = ref({
  name: "",
  enabled: true,
  root: "",
  home: "",
  description: "",
  origins: [] as string[],
  redirects: [] as string[],
  logouts: [] as string[],
  backchannel: "",
  frontchannel: "",
  deviceGrant: false,
  tokenExchange: false,
  cibaDelivery: "off",
  cibaEndpoint: "",
});
function adoptClient() {
  const held = client.value;
  if (!held) return;
  draft.value = {
    name: held.name ?? "",
    enabled: held.enabled,
    root: held.root_url ?? "",
    home: held.client_uri ?? "",
    description: held.description ?? "",
    origins: [...held.web_origins],
    redirects: [...held.redirect_uris],
    logouts: [...held.post_logout_redirect_uris],
    backchannel: held.backchannel_logout_uri ?? "",
    frontchannel: held.frontchannel_logout_uri ?? "",
    deviceGrant: held.device_grant,
    tokenExchange: held.token_exchange,
    cibaDelivery: held.ciba_delivery,
    cibaEndpoint: held.ciba_notification_endpoint ?? "",
  };
}
function clean(held: string[]): string[] {
  return [...new Set(held.map((row) => row.trim()).filter(Boolean))];
}
async function saveClient() {
  try {
    await updateClient(props.realm, props.clientId, {
      name: draft.value.name || undefined,
      root_url: draft.value.root.trim(),
      web_origins: clean(draft.value.origins),
      redirect_uris: clean(draft.value.redirects),
      post_logout_redirect_uris: clean(draft.value.logouts),
      backchannel_logout_uri: draft.value.backchannel.trim(),
      frontchannel_logout_uri: draft.value.frontchannel.trim(),
      description: draft.value.description,
      client_uri: draft.value.home.trim(),
      device_grant: draft.value.deviceGrant,
      token_exchange: draft.value.tokenExchange,
      ciba_delivery: draft.value.cibaDelivery,
      ciba_notification_endpoint: draft.value.cibaEndpoint.trim() || undefined,
    });
    await load();
    adoptClient();
  } catch {
    // The toast already said.
  }
}
/// The agent face of this client, when it has one: absent quietly for
/// every ordinary client, edited through the agents door alone.
const agentFace = ref<import("@/services/clients").AgentBrief | null>(null);
const grantDraft = ref("");
const agentNotice = ref("");
async function loadAgent() {
  try {
    agentFace.value = await getAgent(props.realm, props.clientId);
  } catch {
    agentFace.value = null;
  }
}
async function grantCapability() {
  const wanted = grantDraft.value.trim();
  if (!wanted) return;
  agentNotice.value = "";
  try {
    agentFace.value = await reshapeAgent(props.realm, props.clientId, { add: [wanted] });
    grantDraft.value = "";
  } catch (why) {
    agentNotice.value = why instanceof Error ? why.message : String(why);
  }
}
async function ungrantCapability(held: string) {
  agentNotice.value = "";
  try {
    agentFace.value = await reshapeAgent(props.realm, props.clientId, { remove: [held] });
  } catch (why) {
    agentNotice.value = why instanceof Error ? why.message : String(why);
  }
}

async function refreshClient() {
  await load();
  adoptClient();
}

/// The client-wide cut, struck at now and lifted with 0; the plane refuses
/// a future instant, so now is the only cut this button can strike.
const doomCut = ref("");
async function refuseTokensMintedSoFar() {
  try {
    await updateClient(props.realm, props.clientId, {
      not_before: Math.floor(Date.now() / 1000),
    });
    doomCut.value = "";
    await load();
  } catch {
    // The toast already said.
  }
}
async function liftTheCut() {
  try {
    await updateClient(props.realm, props.clientId, { not_before: 0 });
    await load();
  } catch {
    // The toast already said.
  }
}
function instant(epoch: number | null | undefined): string {
  if (!epoch) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}

const doomName = ref("");
async function dropClient() {
  try {
    await deleteClient(props.realm, props.clientId);
    emit("close");
    router.replace(`/${props.realm}/clients`);
  } catch {
    // The toast already said.
  }
}

const picker = ref<"" | "required" | "offered">("");
const pickRows = ref<{ id: string; label: string; held: boolean }[]>([]);
async function openPicker(kind: "required" | "offered") {
  picker.value = kind;
  const catalogue = await listScopeCatalogue(props.realm);
  const held = new Set(scopes.value.map((row) => row.name));
  pickRows.value = catalogue.map((row) => ({
    id: row.name,
    label: row.name,
    held: held.has(row.name),
  }));
}
async function pickAdd(name: string) {
  try {
    await attachScope(props.realm, props.clientId, name, picker.value === "offered");
    picker.value = "";
    scopes.value = await listAttachedScopes(props.realm, props.clientId);
  } catch {
    // The toast already said.
  }
}
async function dropScope(name: string) {
  await detachScope(props.realm, props.clientId, name);
  scopes.value = await listAttachedScopes(props.realm, props.clientId);
}

async function openMapperPicker() {
  const catalogue = await listRealmMappers(props.realm);
  mapperPickerRows.value = clientMapperPickerRows(catalogue, mappers.value);
  mapperPickerOpen.value = true;
}

async function attachMapper(mapperId: string) {
  try {
    await attachMapperToClient(props.realm, props.clientId, mapperId);
    mapperPickerOpen.value = false;
    mappers.value = await listClientMappers(props.realm, props.clientId);
  } catch {
    // The toast already said.
  }
}

async function detachMapper(mapperId: string) {
  try {
    await detachMapperFromClient(props.realm, props.clientId, mapperId);
    mappers.value = await listClientMappers(props.realm, props.clientId);
  } catch {
    // The toast already said.
  }
}
</script>

<template>
  <AppDrawer
    :title="client?.name || props.clientId"
    :subtitle="props.clientId"
    @close="emit('close')"
  >
    <p v-if="failed" class="text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="flex gap-1 border-b border-border pb-2">
      <button
        v-for="held in TABS"
        :key="held"
        type="button"
        class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
        :class="tab === held && 'bg-surface-2 font-medium text-ink'"
        @click="tab = held"
      >
        {{ say(`client-tab-${held}`) }}
      </button>
    </div>

    <div v-if="tab === 'overview' && client" class="mt-4 flex flex-col gap-4">
      <div
        v-if="agentFace"
        class="rounded-lg border border-brass/40 bg-brass/5 px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="rounded-full bg-brass/15 px-2 py-0.5 text-[10px] font-semibold text-brass">
            {{ say("agent-badge") }}
          </span>
          <span class="text-muted">{{ say("agent-lede") }}</span>
        </div>
        <div class="mt-2 flex flex-wrap gap-1.5">
          <span
            v-for="held in agentFace.capabilities"
            :key="held"
            class="inline-flex items-center gap-1 rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[11px]"
          >
            {{ held }}
            <button
              type="button"
              class="text-muted hover:text-danger"
              :title="say('agent-ungrant')"
              @click="ungrantCapability(held)"
            >
              ×
            </button>
          </span>
        </div>
        <form class="mt-2 flex gap-1.5" @submit.prevent="grantCapability">
          <input
            v-model="grantDraft"
            :placeholder="say('agent-grant-placeholder')"
            class="w-full rounded-md border border-border bg-surface-2 px-2.5 py-1 font-mono text-[11px] text-ink"
          />
          <button
            type="submit"
            class="rounded-md border border-border px-2.5 py-1 text-[11px] hover:bg-surface-2"
          >
            {{ say("agent-grant") }}
          </button>
        </form>
        <p v-if="agentNotice" class="mt-1.5 text-[11px] text-danger">{{ agentNotice }}</p>
        <p class="mt-1.5 text-[10.5px] text-muted">
          {{ say("agent-keyless") }}
          <template v-if="agentFace.session_seconds"
            >· {{ say("agent-session", { seconds: String(agentFace.session_seconds) }) }}</template
          >
        </p>
      </div>
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveClient">
        <div class="grid grid-cols-1 items-center gap-y-2 sm:grid-cols-[140px_1fr]">
          <span class="text-muted">{{ say("clients-col-kind") }}</span>
          <span>{{ client.confidential ? say("clients-confidential") : say("clients-public") }}</span>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("directory-col-display") }}
          <input
            v-model="draft.name"
            class="sf-field mt-1"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-root") }} <AppHint name="client-root-help" />
          <input
            v-model="draft.root"
            placeholder="https://app.example"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-home") }} <AppHint name="client-home-help" />
          <input
            v-model="draft.home"
            placeholder="https://app.example/welcome"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-description") }}
          <textarea
            v-model="draft.description"
            rows="2"
            class="sf-field mt-1"
          ></textarea>
        </label>
        <div class="text-[11px] font-medium text-muted">
          {{ say("client-redirects") }} <AppHint name="client-redirects-help" />
          <AppStringList
            v-model="draft.redirects"
            :input-label="say('client-redirects')"
            :add-label="say('client-add-redirect')"
            :remove-label="say('action-remove')"
            placeholder="https://app.example/callback"
          />
        </div>
        <div class="text-[11px] font-medium text-muted">
          {{ say("client-post-logout") }}
          <AppStringList
            v-model="draft.logouts"
            :input-label="say('client-post-logout')"
            :add-label="say('client-add-logout')"
            :remove-label="say('action-remove')"
            placeholder="https://app.example/signed-out"
          />
        </div>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("client-frontchannel-logout") }}
            <input
              v-model="draft.frontchannel"
              class="sf-field mt-1 font-mono"
              spellcheck="false"
              placeholder="https://app.example/logout/front"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("client-backchannel-logout") }}
            <input
              v-model="draft.backchannel"
              class="sf-field mt-1 font-mono"
              spellcheck="false"
              placeholder="https://app.example/logout/back"
            />
          </label>
        </div>
        <div class="text-[11px] font-medium text-muted">
          {{ say("client-origins") }} <AppHint name="client-origins-help" />
          <AppStringList
            v-model="draft.origins"
            :input-label="say('client-origins')"
            :add-label="say('client-add-origin')"
            :remove-label="say('action-remove')"
            placeholder="https://app.example"
          />
        </div>
        <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-grants") }} <AppHint name="client-grants-help" />
        </div>
        <AppToggle v-model="draft.deviceGrant" :label="say('client-grant-device')" />
        <AppToggle v-model="draft.tokenExchange" :label="say('client-grant-exchange')" />
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-grant-ciba") }} <AppHint name="client-grant-ciba-help" />
          <select
            v-model="draft.cibaDelivery"
            class="sf-field mt-1"
          >
            <option value="off">{{ say("client-ciba-off") }}</option>
            <option value="poll">{{ say("client-ciba-poll") }}</option>
            <option value="ping">{{ say("client-ciba-ping") }}</option>
          </select>
        </label>
        <label v-if="draft.cibaDelivery === 'ping'" class="block text-[11px] font-medium text-muted">
          {{ say("client-ciba-endpoint") }}
          <input
            v-model="draft.cibaEndpoint"
            placeholder="https://app.example/ciba"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
          />
        </label>

        <div>
          <button
            type="submit"
            class="sf-button sf-button-primary"
          >
            {{ say("settings-save") }}
          </button>
        </div>

        <div class="mt-2 rounded-lg border border-danger/40 p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
            {{ say("settings-danger") }}
          </div>
          <p class="mt-1 text-[11px] text-muted">{{ say("client-cut-lede") }}</p>
          <p v-if="client?.not_before" class="mt-1 text-[11px]">
            {{ say("client-cut-standing") }}
            <span class="font-mono">{{ instant(client.not_before) }}</span>
            <button
              type="button"
              class="ml-2 rounded-md border border-border px-2 py-1 text-[11px] hover:bg-surface-2"
              @click="liftTheCut"
            >
              {{ say("realm-cut-lift") }}
            </button>
          </p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomCut"
              :placeholder="props.clientId"
              class="sf-field font-mono"
              spellcheck="false"
            />
            <button
              type="button"
              class="sf-button sf-button-danger disabled:opacity-40"
              :disabled="doomCut !== props.clientId"
              @click="refuseTokensMintedSoFar"
            >
              {{ say("realm-cut-strike") }}
            </button>
          </div>
          <p class="mt-4 text-[11px] text-muted">{{ say("client-delete-lede") }}</p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomName"
              :placeholder="props.clientId"
              class="sf-field font-mono"
              spellcheck="false"
            />
            <button
              type="button"
              class="sf-button sf-button-danger disabled:opacity-40"
              :disabled="doomName !== props.clientId"
              @click="dropClient"
            >
              {{ say("client-delete") }}
            </button>
          </div>
        </div>
      </form>
    </div>

    <ClientKeysTab
      v-if="tab === 'keys' && client"
      class="mt-4"
      :realm="props.realm"
      :client="client"
      @updated="refreshClient"
    />

    <div v-if="tab === 'scopes'" class="mt-4 flex flex-col gap-5">
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-scopes-required") }}
        </div>
        <p v-if="!required.length" class="mt-1.5 text-xs text-muted">
          {{ say("client-scopes-none") }}
        </p>
        <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            v-for="scope in required"
            :key="scope.client_scope_id"
            class="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            :title="scope.description"
          >
            {{ scope.name }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropScope(scope.name)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('required')"
          >
            {{ say("client-attach-required") }}
          </button>
          <AppPicker
            v-if="picker === 'required'"
            :rows="pickRows"
            :title="say('client-attach-required')"
            @add="pickAdd"
            @close="picker = ''"
          />
        </div>
      </div>
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-scopes-offered") }}
        </div>
        <p v-if="!offered.length" class="mt-1.5 text-xs text-muted">
          {{ say("client-scopes-none") }}
        </p>
        <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            v-for="scope in offered"
            :key="scope.client_scope_id"
            class="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted"
            :title="scope.description"
          >
            {{ scope.name }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropScope(scope.name)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('offered')"
          >
            {{ say("client-attach-offered") }}
          </button>
          <AppPicker
            v-if="picker === 'offered'"
            :rows="pickRows"
            :title="say('client-attach-offered')"
            @add="pickAdd"
            @close="picker = ''"
          />
        </div>
      </div>
    </div>

    <div v-if="tab === 'mappers'" class="relative mt-4">
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <p class="min-w-0 flex-1 text-[11px] text-muted">
          {{ say("client-mappers-lede") }}
          <RouterLink
            :to="`/${props.realm}/protocol-mappers`"
            class="text-accent hover:underline"
          >
            {{ say("client-mappers-catalogue") }}
          </RouterLink>
        </p>
        <AppHint name="client-mapper-attach-help" />
        <button
          type="button"
          class="sf-button sf-button-secondary"
          @click="openMapperPicker"
        >
          {{ say("client-mapper-attach") }}
        </button>
      </div>
      <p v-if="!mappers.length" class="text-xs text-muted">{{ say("mappers-none") }}</p>
      <div v-else class="overflow-x-auto rounded-lg border border-border">
        <table class="sf-table">
          <thead>
            <tr>
              <th>{{ say("mappers-col-name") }}</th>
              <th>{{ say("mappers-col-type") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="mapper in mappers"
              :key="mapper.mapper_id"
              class="border-b border-border/60 last:border-0"
            >
              <td>{{ mapper.name }}</td>
              <td class="font-mono text-[10.5px] text-muted">
                {{ mapper.mapper_type }}
              </td>
              <td class="text-right">
                <button
                  type="button"
                  class="inline-flex items-center gap-1 text-[10.5px] text-faint hover:text-danger"
                  @click="detachMapper(mapper.mapper_id)"
                >
                  <AppIcon name="remove" :size="11" />
                  {{ say("client-mapper-detach") }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <AppPicker
        v-if="mapperPickerOpen"
        :rows="mapperPickerRows"
        :title="say('client-mapper-attach')"
        @add="attachMapper"
        @close="mapperPickerOpen = false"
      />
    </div>

    <div v-if="tab === 'roles'" class="mt-4 flex flex-col gap-3">
      <p class="text-[11px] text-muted">{{ say("client-roles-lede") }}</p>
      <form class="flex max-w-xl flex-wrap items-end gap-2 text-xs" @submit.prevent="makeClientRole">
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("settings-name") }}
          <input
            v-model="roleDraft.name"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
          />
        </label>
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("scopes-col-description") }}
          <input
            v-model="roleDraft.description"
            class="sf-field mt-1"
          />
        </label>
        <button
          type="submit"
          class="sf-button sf-button-primary"
        >
          {{ say("realm-create") }}
        </button>
      </form>
      <p v-if="!clientRoles.length" class="text-xs text-muted">{{ say("client-roles-none") }}</p>
      <div v-else class="overflow-x-auto rounded-lg border border-border">
        <table class="sf-table">
          <thead>
            <tr>
              <th>{{ say("scopes-col-name") }}</th>
              <th>{{ say("scopes-col-description") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="role in clientRoles"
              :key="role.role_id"
              class="border-b border-border/60 last:border-0"
            >
              <td class="font-mono text-[11.5px]">{{ role.name }}</td>
              <td class="text-muted">{{ role.description }}</td>
              <td class="text-right">
                <button
                  type="button"
                  class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
                  @click="dropClientRole(role.role_id)"
                >
                  {{ say("action-remove") }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </AppDrawer>
</template>
