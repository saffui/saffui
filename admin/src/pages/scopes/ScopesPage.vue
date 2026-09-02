<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
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
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import type { ClientScope, ProtocolMapper } from "@/models/client";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const scopes = ref<ClientScope[]>([]);
const failed = ref("");
const unfolded = ref<string | null>(null);
const mappers = ref<Record<string, ProtocolMapper[]>>({});

onMounted(async () => {
  try {
    scopes.value = await listScopeCatalogue(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

const making = ref(false);
const newName = ref("");
const newSentence = ref("");
async function makeScope() {
  if (!newName.value.trim()) return;
  try {
    await createScope(realm.value, {
      name: newName.value.trim(),
      description: newSentence.value.trim(),
    });
    making.value = false;
    newName.value = "";
    newSentence.value = "";
    scopes.value = await listScopeCatalogue(realm.value);
  } catch {
    // The toast already said.
  }
}

const sentenceDraft = ref("");
async function saveSentence(scope: ClientScope) {
  try {
    await updateScope(realm.value, scope.client_scope_id, {
      name: scope.name,
      description: sentenceDraft.value,
    });
    scope.description = sentenceDraft.value;
  } catch {
    // The toast already said.
  }
}

async function dropScope(scope: ClientScope) {
  try {
    await deleteScope(realm.value, scope.client_scope_id);
    unfolded.value = null;
    scopes.value = await listScopeCatalogue(realm.value);
  } catch {
    // The toast already said.
  }
}

const picker = ref("");
const pickRows = ref<{ id: string; label: string; held: boolean }[]>([]);
async function openMapperPicker(scope: ClientScope) {
  picker.value = scope.client_scope_id;
  const catalogue = await listRealmMappers(realm.value);
  const held = new Set((mappers.value[scope.client_scope_id] ?? []).map((row) => row.mapper_id));
  pickRows.value = catalogue.map((row) => ({
    id: row.mapper_id,
    label: row.name,
    held: held.has(row.mapper_id),
  }));
}
async function pickMapper(scopeId: string, mapperId: string) {
  try {
    await attachMapperToScope(realm.value, scopeId, mapperId);
    picker.value = "";
    mappers.value[scopeId] = await listScopeMappers(realm.value, scopeId);
  } catch {
    // The toast already said.
  }
}
async function dropMapper(scopeId: string, mapperId: string) {
  await detachMapperFromScope(realm.value, scopeId, mapperId);
  mappers.value[scopeId] = await listScopeMappers(realm.value, scopeId);
}

async function unfold(scope: ClientScope) {
  if (unfolded.value === scope.client_scope_id) {
    unfolded.value = null;
    return;
  }
  unfolded.value = scope.client_scope_id;
  sentenceDraft.value = scope.description;
  picker.value = "";
  if (!mappers.value[scope.client_scope_id]) {
    mappers.value[scope.client_scope_id] = await listScopeMappers(
      realm.value,
      scope.client_scope_id,
    );
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("scopes-title") }}</h1>
      <button
        type="button"
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        @click="making = !making"
      >
        {{ say("scope-new") }}
      </button>
      <span v-if="scopes.length" class="font-mono text-[11px] text-faint">{{
        scopes.length
      }}</span>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("scopes-lede") }}</p>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <form
      v-if="making"
      class="mt-3 flex max-w-2xl items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeScope"
    >
      <label class="w-44 text-[11px] font-medium text-muted">
        {{ say("settings-name") }} <AppHint name="scope-name-help" />
        <input
          v-model="newName"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("scope-sentence") }} <AppHint name="scope-sentence-help" />
        <input
          v-model="newSentence"
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

    <div class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-description") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-default") }}</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="scope in scopes" :key="scope.client_scope_id">
            <tr
              class="cursor-pointer border-b border-border/60 hover:bg-surface-2"
              :class="unfolded === scope.client_scope_id && 'bg-surface-2'"
              @click="unfold(scope)"
            >
              <td class="px-3 py-2 font-mono text-[11.5px]">{{ scope.name }}</td>
              <td class="px-3 py-2 text-muted">{{ scope.description }}</td>
              <td class="px-3 py-2">
                <span v-if="scope.default_scope" class="text-[10.5px] text-accent-strong">{{
                  say("scopes-default")
                }}</span>
              </td>
            </tr>
            <tr v-if="unfolded === scope.client_scope_id" class="border-b border-border/60">
              <td colspan="3" class="bg-bg px-3 py-2.5">
                <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                  {{ say("client-tab-mappers") }}
                </div>
                <p
                  v-if="!(mappers[scope.client_scope_id] ?? []).length"
                  class="mt-1.5 text-xs text-muted"
                >
                  {{ say("mappers-none") }}
                </p>
                <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
                  <span
                    v-for="mapper in mappers[scope.client_scope_id] ?? []"
                    :key="mapper.mapper_id"
                    class="rounded border border-border px-1.5 py-0.5 text-[10.5px]"
                  >
                    {{ mapper.name }}
                    <span class="ml-1 font-mono text-faint">{{ mapper.mapper_type }}
                    <button
                      type="button"
                      class="text-faint hover:text-danger"
                      :aria-label="say('action-remove')"
                      @click.stop="dropMapper(scope.client_scope_id, mapper.mapper_id)"
                    >
                      &times;
                    </button></span>
                  </span>
                  <button
                    type="button"
                    class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
                    @click.stop="openMapperPicker(scope)"
                  >
                    {{ say("scope-attach-mapper") }}
                  </button>
                  <AppPicker
                    v-if="picker === scope.client_scope_id"
                    :rows="pickRows"
                    :title="say('scope-attach-mapper')"
                    @add="(id) => pickMapper(scope.client_scope_id, id)"
                    @close="picker = ''"
                  />
                </div>

                <form
                  class="mt-3 flex max-w-xl items-end gap-2"
                  @click.stop
                  @submit.prevent="saveSentence(scope)"
                >
                  <label class="flex-1 text-[11px] font-medium text-muted">
                    {{ say("scope-sentence") }} <AppHint name="scope-sentence-help" />
                    <input
                      v-model="sentenceDraft"
                      class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
                    />
                  </label>
                  <button
                    type="submit"
                    class="rounded-md bg-accent px-3 py-1.5 text-[11px] font-semibold text-accent-ink hover:bg-accent-strong"
                  >
                    {{ say("settings-save") }}
                  </button>
                  <button
                    type="button"
                    class="rounded-md border border-danger/40 px-3 py-1.5 text-[11px] text-danger hover:bg-surface-2"
                    @click="dropScope(scope)"
                  >
                    {{ say("scope-delete") }}
                  </button>
                </form>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>
