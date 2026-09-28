<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink, useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import AppToggle from "@/components/AppToggle.vue";
import DangerDialog from "@/components/DangerDialog.vue";
import { say } from "@/i18n";
import type { ClientScope, ProtocolMapper } from "@/models/client";
import {
  attachMapperToScope,
  createScope,
  deleteScope,
  detachMapperFromScope,
  listRealmMappers,
  listScopeCatalogue,
  listScopeMappers,
  updateScope,
} from "@/services/scopes";
import { afterWrites } from "@/services/writes";
import { mapperKindKey } from "./mapperLabels";
import { scopeWrite, type ScopeDraft } from "./scopeForm";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const scopes = ref<ClientScope[]>([]);
const failed = ref("");
const editorOpen = ref(false);
const selected = ref<ClientScope | null>(null);
const pendingDelete = ref<ClientScope | null>(null);
const attached = ref<ProtocolMapper[]>([]);
const pickerOpen = ref(false);
const pickRows = ref<{ id: string; label: string; held: boolean }[]>([]);
const draft = ref<ScopeDraft>({ name: "", description: "", defaultScope: false });

async function load() {
  try {
    scopes.value = await listScopeCatalogue(realm.value);
    failed.value = "";
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

onMounted(load);
afterWrites(load);

async function openScope(scope?: ClientScope) {
  selected.value = scope ?? null;
  draft.value = {
    name: scope?.name ?? "",
    description: scope?.description ?? "",
    defaultScope: Boolean(scope?.default_scope),
  };
  attached.value = [];
  pickerOpen.value = false;
  editorOpen.value = true;
  if (scope) {
    try {
      attached.value = await listScopeMappers(realm.value, scope.client_scope_id);
    } catch (refused) {
      failed.value = refused instanceof Error ? refused.message : String(refused);
    }
  }
}

async function saveScope() {
  const body = scopeWrite(draft.value, selected.value);
  if (!body.name) return;
  try {
    if (selected.value) {
      await updateScope(realm.value, selected.value.client_scope_id, body);
    } else {
      await createScope(realm.value, body);
    }
    editorOpen.value = false;
    await load();
  } catch {
    // The request toast contains the refusal.
  }
}

async function confirmDelete() {
  if (!pendingDelete.value) return;
  try {
    await deleteScope(realm.value, pendingDelete.value.client_scope_id);
    pendingDelete.value = null;
    editorOpen.value = false;
    await load();
  } catch {
    // The request toast contains the refusal.
  }
}

async function openMapperPicker() {
  if (!selected.value) return;
  const catalogue = await listRealmMappers(realm.value);
  const held = new Set(attached.value.map((row) => row.mapper_id));
  pickRows.value = catalogue.map((row) => ({
    id: row.mapper_id,
    label: row.name,
    held: held.has(row.mapper_id),
  }));
  pickerOpen.value = true;
}

async function addMapper(mapperId: string) {
  if (!selected.value) return;
  try {
    await attachMapperToScope(realm.value, selected.value.client_scope_id, mapperId);
    pickerOpen.value = false;
    attached.value = await listScopeMappers(realm.value, selected.value.client_scope_id);
  } catch {
    // The request toast contains the refusal.
  }
}

async function removeMapper(mapperId: string) {
  if (!selected.value) return;
  try {
    await detachMapperFromScope(realm.value, selected.value.client_scope_id, mapperId);
    attached.value = await listScopeMappers(realm.value, selected.value.client_scope_id);
  } catch {
    // The request toast contains the refusal.
  }
}

function kindLabel(kind: string): string {
  const key = mapperKindKey(kind);
  return key === "mapper-kind-custom" ? kind : say(key);
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div class="min-w-0">
        <div class="flex items-center gap-2">
          <h1 class="text-lg font-semibold tracking-tight">{{ say("scopes-title") }}</h1>
          <span v-if="scopes.length" class="rounded-md bg-neutral-tint px-2 py-0.5 font-mono text-[10px] text-muted">
            {{ scopes.length }}
          </span>
        </div>
        <p class="mt-1 text-xs text-muted">{{ say("scopes-lede") }}</p>
      </div>
      <div class="flex items-center gap-2">
        <RouterLink :to="`/${realm}/protocol-mappers`" class="sf-button sf-button-secondary">
          {{ say("mappers-title") }}
        </RouterLink>
        <button type="button" class="sf-button sf-button-primary" @click="openScope()">
          {{ say("scope-new") }}
        </button>
      </div>
    </div>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="sf-list mt-4 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
            <th>{{ say("scopes-col-name") }}</th>
            <th>{{ say("scopes-col-description") }}</th>
            <th>{{ say("scopes-col-default") }}</th>
            <th><span class="sr-only">{{ say("authz-route-edit") }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="scope in scopes" :key="scope.client_scope_id" class="border-b border-border/60 last:border-0">
            <td class="font-mono text-[11.5px] text-ink">{{ scope.name }}</td>
            <td class="max-w-xl text-muted">{{ scope.description || say("value-none") }}</td>
            <td>
              <span v-if="scope.default_scope" class="rounded-md bg-accent/10 px-2 py-1 text-[10.5px] text-accent">
                {{ say("scopes-default") }}
              </span>
              <span v-else class="text-faint">{{ say("value-none") }}</span>
            </td>
            <td class="text-right">
              <button
                type="button"
                class="text-xs text-accent hover:underline"
                :aria-label="`${say('authz-route-edit')} ${scope.name}`"
                @click="openScope(scope)"
              >
                {{ say("authz-route-edit") }}
              </button>
            </td>
          </tr>
          <tr v-if="!scopes.length">
            <td colspan="4" class="text-muted">{{ say("client-scopes-none") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <AppDrawer
      v-if="editorOpen"
      wide
      :title="selected ? say('scope-edit') : say('scope-new')"
      :subtitle="selected?.name"
      @close="editorOpen = false"
    >
      <form class="flex flex-col gap-5" @submit.prevent="saveScope">
        <section class="grid gap-4 rounded-lg border border-border bg-bg p-4 sm:grid-cols-2">
          <label class="text-[11px] font-medium text-muted">
            {{ say("settings-name") }} <AppHint name="scope-name-help" />
            <input v-model="draft.name" required class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
          <label class="text-[11px] font-medium text-muted">
            {{ say("scope-sentence") }} <AppHint name="scope-sentence-help" />
            <input v-model="draft.description" class="sf-field mt-1" />
          </label>
          <div class="sm:col-span-2 rounded-md border border-border bg-surface px-3 py-2.5">
            <AppToggle v-model="draft.defaultScope">
              <span class="font-medium text-ink">{{ say("scope-default-title") }}</span>
              <span class="mt-0.5 block text-[10.5px] text-muted">{{ say("scope-default-help") }}</span>
            </AppToggle>
          </div>
        </section>

        <section v-if="selected" class="rounded-lg border border-border bg-bg p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 class="text-sm font-semibold">{{ say("client-tab-mappers") }}</h3>
              <p class="mt-1 text-[11px] text-muted">{{ say("scope-mappers-help") }}</p>
            </div>
            <div class="relative">
              <button type="button" class="sf-button sf-button-secondary" @click="openMapperPicker">
                {{ say("scope-attach-mapper") }}
              </button>
              <AppPicker
                v-if="pickerOpen"
                :rows="pickRows"
                :title="say('scope-attach-mapper')"
                @add="addMapper"
                @close="pickerOpen = false"
              />
            </div>
          </div>
          <div class="mt-4 overflow-x-auto rounded-md border border-border bg-surface">
            <table class="sf-table">
              <thead><tr><th>{{ say("mappers-col-name") }}</th><th>{{ say("mappers-col-type") }}</th><th></th></tr></thead>
              <tbody>
                <tr v-for="mapper in attached" :key="mapper.mapper_id" class="border-b border-border/60 last:border-0">
                  <td class="font-medium">{{ mapper.name }}</td>
                  <td>
                    <span class="block text-xs">{{ kindLabel(mapper.mapper_type) }}</span>
                    <span class="font-mono text-[10px] text-faint">{{ mapper.mapper_type }}</span>
                  </td>
                  <td class="text-right">
                    <button type="button" class="text-xs text-danger hover:underline" @click="removeMapper(mapper.mapper_id)">
                      {{ say("action-remove") }}
                    </button>
                  </td>
                </tr>
                <tr v-if="!attached.length"><td colspan="3" class="text-muted">{{ say("mappers-none") }}</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="selected" class="rounded-lg border border-danger/30 bg-danger-tint/30 p-4">
          <h3 class="text-sm font-semibold text-danger">{{ say("scope-danger-zone") }}</h3>
          <p class="mt-1 text-[11px] text-muted">{{ say("scope-delete-lede") }}</p>
          <button type="button" class="sf-button sf-button-danger mt-3" @click="pendingDelete = selected">
            {{ say("scope-delete") }}
          </button>
        </section>

        <div class="flex justify-end gap-2 border-t border-border pt-4">
          <button type="button" class="sf-button sf-button-secondary" @click="editorOpen = false">{{ say("action-cancel") }}</button>
          <button type="submit" class="sf-button sf-button-primary">{{ selected ? say("settings-save") : say("realm-create") }}</button>
        </div>
      </form>
    </AppDrawer>

    <DangerDialog
      :open="pendingDelete !== null"
      :title="say('scope-delete-title')"
      :named="pendingDelete?.name ?? ''"
      :lede="say('scope-delete-lede')"
      :facts="[{ value: String(attached.length), label: say('client-tab-mappers') }]"
      :warning="say('scope-delete-warning')"
      :confirm-label="say('scope-delete')"
      @close="pendingDelete = null"
      @confirm="confirmDelete"
    />
  </div>
</template>
