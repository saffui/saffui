<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import AppPaging from "@/components/AppPaging.vue";
import {
  createRole,
  deleteRole,
  listRoleHolders,
  listRoles,
  updateRole,
} from "@/services/directory";
import type { Page } from "@/models/paging";
import type { RoleHolders, RoleRow } from "@/models/directory";
import DirectoryTable from "./DirectoryTable.vue";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const page = ref<Page<RoleRow> | null>(null);
const first = ref(0);
const size = ref(25);
function resize(asked: number) {
  size.value = asked;
  first.value = 0;
  void turn();
}
async function turn() {
  try {
    page.value = await listRoles(realm.value, first.value, size.value);
  } catch {
    // The listing simply stays where it was.
  }
}

const failed = ref("");
const opened = ref<RoleRow | null>(null);
const holders = ref<RoleHolders | null>(null);

onMounted(async () => {
  try {
    page.value = await listRoles(realm.value, first.value, size.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function open(role: RoleRow) {
  opened.value = role;
  draft.value = { display_name: role.display_name, description: role.description };
  doomName.value = "";
  holders.value = null;
  holders.value = await listRoleHolders(realm.value, role.role_id);
}

const making = ref(false);
const newName = ref("");
const newDescription = ref("");
async function makeRole() {
  if (!newName.value.trim()) return;
  try {
    await createRole(realm.value, {
      name: newName.value.trim(),
      description: newDescription.value.trim(),
    });
    making.value = false;
    newName.value = "";
    newDescription.value = "";
    page.value = await listRoles(realm.value, first.value, size.value);
  } catch {
    // The toast already said.
  }
}

const draft = ref({ display_name: "", description: "" });
async function saveRole() {
  if (!opened.value) return;
  try {
    await updateRole(realm.value, opened.value.role_id, {
      name: opened.value.name,
      display_name: draft.value.display_name,
      description: draft.value.description,
    });
    opened.value.display_name = draft.value.display_name;
    opened.value.description = draft.value.description;
  } catch {
    // The toast already said.
  }
}

const doomName = ref("");
async function dropRole() {
  if (!opened.value) return;
  try {
    await deleteRole(realm.value, opened.value.role_id);
    opened.value = null;
    page.value = await listRoles(realm.value, first.value, size.value);
  } catch {
    // The toast already said: a role still granted refuses in words.
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("roles-title") }}</h1>
      <div class="flex items-center gap-3">
        <button
          type="button"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          @click="making = !making"
        >
          {{ say("role-new") }}
        </button>
      </div>
    </div>

    <form
      v-if="making"
      class="mt-3 flex max-w-xl items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeRole"
    >
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("settings-name") }} <AppHint name="role-name-help" />
        <input
          v-model="newName"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("scopes-col-description") }}
        <input
          v-model="newDescription"
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
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4">
      <DirectoryTable
        :items="page.items"
        :opened-key="opened?.role_id ?? null"
        :key-of="(row: RoleRow) => row.role_id"
        @open="open"
      >
        <template #extra="{ row }">
          <span
            v-if="row.client_id"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px] text-muted"
            >{{ row.client_id }}</span
          >
        </template>
      </DirectoryTable>
    <AppPaging
      v-if="page"
      :first="first"
      :count="page.items.length"
      :size="size"
      @update:first="(held) => { first = held; void turn(); }"
      @update:size="resize"
    />
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.name"
      @close="opened = null"
    >
      <form class="flex flex-col gap-2 text-xs" @submit.prevent="saveRole">
        <div class="grid grid-cols-2 gap-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("directory-col-display") }}
            <input
              v-model="draft.display_name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("scopes-col-description") }}
            <input
              v-model="draft.description"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
        </div>
        <div>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("settings-save") }}
          </button>
        </div>
      </form>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("role-held-by-users") }}
        </div>
        <p v-if="holders && !holders.users.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="user in holders?.users ?? []"
            :key="user"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            >{{ user }}</span
          >
        </div>
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("role-held-by-groups") }}
        </div>
        <p v-if="holders && !holders.groups.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="group in holders?.groups ?? []"
            :key="group"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            >{{ group }}</span
          >
        </div>
      </div>
      <div class="mt-4 rounded-lg border border-danger/40 p-3">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
          {{ say("settings-danger") }}
        </div>
        <p class="mt-1 text-[11px] text-muted">{{ say("role-delete-lede") }}</p>
        <div class="mt-2 flex items-center gap-2">
          <input
            v-model="doomName"
            :placeholder="opened.name"
            class="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          />
          <button
            type="button"
            class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
            :disabled="doomName !== opened.name"
            @click="dropRole"
          >
            {{ say("role-delete") }}
          </button>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
