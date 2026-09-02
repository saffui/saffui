<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  attachScope,
  deleteClient,
  detachScope,
  getClient,
  listAttachedScopes,
  listClientMappers,
  rotateClientSecret,
  updateClient,
} from "@/services/clients";
import { listScopeCatalogue } from "@/services/scopes";
import { createRole, deleteRole, listRoles } from "@/services/directory";
import type { RoleRow } from "@/models/directory";
import AppToggle from "@/components/AppToggle.vue";
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import { useRouter } from "vue-router";
import type { ClientBrief, ClientScope, ProtocolMapper } from "@/models/client";

const props = defineProps<{ realm: string; clientId: string }>();
const emit = defineEmits<{ close: [] }>();

const TABS = ["overview", "scopes", "mappers", "roles"] as const;
const tab = ref<(typeof TABS)[number]>("overview");

const client = ref<ClientBrief | null>(null);
const scopes = ref<ClientScope[]>([]);
const mappers = ref<ProtocolMapper[]>([]);
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
const draft = ref({ name: "", enabled: true, redirects: "", logouts: "" });
function adoptClient() {
  const held = client.value;
  if (!held) return;
  draft.value = {
    name: held.name ?? "",
    enabled: held.enabled,
    redirects: held.redirect_uris.join("\n"),
    logouts: held.post_logout_redirect_uris.join("\n"),
  };
}
function lines(held: string): string[] {
  return held
    .split(/\n/)
    .map((row) => row.trim())
    .filter(Boolean);
}
async function saveClient() {
  try {
    await updateClient(props.realm, props.clientId, {
      name: draft.value.name || undefined,
      redirect_uris: lines(draft.value.redirects),
      post_logout_redirect_uris: lines(draft.value.logouts),
    });
    await load();
    adoptClient();
  } catch {
    // The toast already said.
  }
}

const freshSecret = ref("");
async function rotate() {
  try {
    freshSecret.value = await rotateClientSecret(props.realm, props.clientId);
  } catch {
    // The toast already said.
  }
}
async function copyFreshSecret() {
  try {
    await navigator.clipboard.writeText(freshSecret.value);
  } catch {
    // Selectable by hand.
  }
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
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveClient">
        <div class="grid grid-cols-[140px_1fr] items-center gap-y-2">
          <span class="text-muted">{{ say("clients-col-kind") }}</span>
          <span>{{ client.confidential ? say("clients-confidential") : say("clients-public") }}</span>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("directory-col-display") }}
          <input
            v-model="draft.name"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-redirects") }} <AppHint name="client-redirects-help" />
          <textarea
            v-model="draft.redirects"
            rows="3"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink"
            spellcheck="false"
          ></textarea>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-post-logout") }}
          <textarea
            v-model="draft.logouts"
            rows="2"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink"
            spellcheck="false"
          ></textarea>
        </label>
        <div>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("settings-save") }}
          </button>
        </div>

        <template v-if="client.confidential">
          <div class="mt-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("client-secret-title") }} <AppHint name="client-secret-help" />
          </div>
          <div class="flex items-center gap-2">
            <button
              type="button"
              class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
              @click="rotate"
            >
              {{ say("client-rotate-secret") }}
            </button>
          </div>
          <div
            v-if="freshSecret"
            class="flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2"
          >
            <code class="min-w-0 flex-1 truncate font-mono text-[11px]">{{ freshSecret }}</code>
            <button
              type="button"
              class="rounded border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-3"
              @click="copyFreshSecret"
            >
              {{ say("action-copy") }}
            </button>
          </div>
          <p v-if="freshSecret" class="text-[10.5px] text-warn">{{ say("settings-secret-once") }}</p>
        </template>

        <div class="mt-2 rounded-lg border border-danger/40 p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
            {{ say("settings-danger") }}
          </div>
          <p class="mt-1 text-[11px] text-muted">{{ say("client-delete-lede") }}</p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomName"
              :placeholder="props.clientId"
              class="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
            />
            <button
              type="button"
              class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
              :disabled="doomName !== props.clientId"
              @click="dropClient"
            >
              {{ say("client-delete") }}
            </button>
          </div>
        </div>
      </form>
    </div>

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

    <div v-if="tab === 'mappers'" class="mt-4">
      <p v-if="!mappers.length" class="text-xs text-muted">{{ say("mappers-none") }}</p>
      <div v-else class="overflow-x-auto rounded-lg border border-border">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-border text-[11px] text-muted">
              <th class="px-3 py-2 font-medium">{{ say("mappers-col-name") }}</th>
              <th class="px-3 py-2 font-medium">{{ say("mappers-col-type") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="mapper in mappers"
              :key="mapper.mapper_id"
              class="border-b border-border/60 last:border-0"
            >
              <td class="px-3 py-2">{{ mapper.name }}</td>
              <td class="px-3 py-2 font-mono text-[10.5px] text-muted">
                {{ mapper.mapper_type }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="tab === 'roles'" class="mt-4 flex flex-col gap-3">
      <p class="text-[11px] text-muted">{{ say("client-roles-lede") }}</p>
      <form class="flex max-w-xl items-end gap-2 text-xs" @submit.prevent="makeClientRole">
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("settings-name") }}
          <input
            v-model="roleDraft.name"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          />
        </label>
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("scopes-col-description") }}
          <input
            v-model="roleDraft.description"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <button
          type="submit"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        >
          {{ say("realm-create") }}
        </button>
      </form>
      <p v-if="!clientRoles.length" class="text-xs text-muted">{{ say("client-roles-none") }}</p>
      <div v-else class="overflow-x-auto rounded-lg border border-border">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-border text-[11px] text-muted">
              <th class="px-3 py-2 font-medium">{{ say("scopes-col-name") }}</th>
              <th class="px-3 py-2 font-medium">{{ say("scopes-col-description") }}</th>
              <th class="px-3 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="role in clientRoles"
              :key="role.role_id"
              class="border-b border-border/60 last:border-0"
            >
              <td class="px-3 py-2 font-mono text-[11.5px]">{{ role.name }}</td>
              <td class="px-3 py-2 text-muted">{{ role.description }}</td>
              <td class="px-3 py-2 text-right">
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
