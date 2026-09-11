<script setup lang="ts">
import PageTabs from "@/components/PageTabs.vue";
import { computed, onMounted, ref } from "vue";
import { afterWrites } from "@/services/writes";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import { say } from "@/i18n";
import AppPaging from "@/components/AppPaging.vue";
import {
  addCompositeRole,
  createRole,
  deleteRole,
  listCompositeRoles,
  listRoleHolders,
  listRoles,
  removeCompositeRole,
  updateRole,
} from "@/services/directory";
import type { Page } from "@/models/paging";
import type { RoleHolders, RoleRow } from "@/models/directory";
import DirectoryTable from "./DirectoryTable.vue";
import { compositeRolePickerRows } from "@/pages/adminActionPickers";

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
const composites = ref<RoleRow[] | null>(null);
const compositePickerOpen = ref(false);
const compositePickerRows = ref<{ id: string; label: string; held: boolean }[]>([]);
const heldUsers = computed(
  () =>
    holders.value?.user_details ??
    holders.value?.users.map((id) => ({ id, name: id })) ??
    [],
);
const heldGroups = computed(
  () =>
    holders.value?.group_details ??
    holders.value?.groups.map((id) => ({ id, name: id })) ??
    [],
);

async function load() {
  try {
    page.value = await listRoles(realm.value, first.value, size.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

async function open(role: RoleRow) {
  opened.value = role;
  draft.value = { display_name: role.display_name, description: role.description };
  doomName.value = "";
  holders.value = null;
  composites.value = null;
  compositePickerOpen.value = false;
  [holders.value, composites.value] = await Promise.all([
    listRoleHolders(realm.value, role.role_id),
    listCompositeRoles(realm.value, role.role_id),
  ]);
}

async function refreshRoleRelations() {
  if (!opened.value) return;
  [holders.value, composites.value] = await Promise.all([
    listRoleHolders(realm.value, opened.value.role_id),
    listCompositeRoles(realm.value, opened.value.role_id),
  ]);
}

async function openCompositePicker() {
  if (!opened.value) return;
  const catalogue = await listRoles(realm.value, 0, 200);
  compositePickerRows.value = compositeRolePickerRows(
    catalogue.items,
    opened.value.role_id,
    composites.value ?? [],
  );
  compositePickerOpen.value = true;
}

async function addComposite(childRoleId: string) {
  if (!opened.value) return;
  try {
    await addCompositeRole(realm.value, opened.value.role_id, childRoleId);
    compositePickerOpen.value = false;
    await refreshRoleRelations();
  } catch {
    // The toast already said.
  }
}

async function removeComposite(childRoleId: string) {
  if (!opened.value) return;
  try {
    await removeCompositeRole(realm.value, opened.value.role_id, childRoleId);
    await refreshRoleRelations();
  } catch {
    // The toast already said.
  }
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
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("roles-title") }}</h1>

      <div class="flex items-center gap-3">
        <button
          type="button"
          class="sf-button sf-button-primary"
          @click="making = !making"
        >
          {{ say("role-new") }}
        </button>
      </div>
    </div>

      <PageTabs class="mt-3" />

    <form
      v-if="making"
      class="mt-3 flex max-w-xl flex-wrap items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeRole"
    >
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("settings-name") }} <AppHint name="role-name-help" />
        <input
          v-model="newName"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("scopes-col-description") }}
        <input
          v-model="newDescription"
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
        <template #foot>
        <AppPaging
          v-if="page"
          :first="first"
          :count="page.items.length"
          :size="size"
          @update:first="(held) => { first = held; void turn(); }"
          @update:size="resize"
        />
        </template>
      </DirectoryTable>
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.name"
      @close="opened = null"
    >
      <form class="flex flex-col gap-2 text-xs" @submit.prevent="saveRole">
        <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("directory-col-display") }}
            <input
              v-model="draft.display_name"
              class="sf-field mt-1"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("scopes-col-description") }}
            <input
              v-model="draft.description"
              class="sf-field mt-1"
            />
          </label>
        </div>
        <div>
          <button
            type="submit"
            class="sf-button sf-button-primary"
          >
            {{ say("settings-save") }}
          </button>
        </div>
      </form>
      <div class="relative mt-4">
        <div class="flex items-center gap-2">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("role-composites") }}
          </div>
          <AppHint name="role-composites-help" />
          <button
            type="button"
            class="ml-auto sf-button sf-button-secondary"
            @click="openCompositePicker"
          >
            {{ say("role-composites-add") }}
          </button>
        </div>
        <p v-if="composites && !composites.length" class="mt-1.5 text-xs text-muted">
          {{ say("role-composites-none") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="child in composites ?? []"
            :key="child.role_id"
            class="inline-flex items-center gap-1.5 rounded border border-border px-1.5 py-0.5 text-[11px]"
            :title="child.description"
          >
            {{ child.display_name || child.name }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('role-composites-remove', { role: child.name })"
              @click="removeComposite(child.role_id)"
            >
              <AppIcon name="close" :size="11" />
            </button>
          </span>
        </div>
        <AppPicker
          v-if="compositePickerOpen"
          :rows="compositePickerRows"
          :title="say('role-composites-add')"
          @add="addComposite"
          @close="compositePickerOpen = false"
        />
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("role-held-by-users") }}
        </div>
        <p v-if="holders && !heldUsers.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="user in heldUsers"
            :key="user.id"
            :title="user.id"
            class="rounded border border-border px-1.5 py-0.5 text-[11px]"
            >{{ user.name }}</span
          >
        </div>
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("role-held-by-groups") }}
        </div>
        <p v-if="holders && !heldGroups.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="group in heldGroups"
            :key="group.id"
            :title="group.id"
            class="rounded border border-border px-1.5 py-0.5 text-[11px]"
            >{{ group.name }}</span
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
            class="sf-field font-mono"
            spellcheck="false"
          />
          <button
            type="button"
            class="sf-button sf-button-danger disabled:opacity-40"
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
