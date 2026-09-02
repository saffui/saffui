<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import {
  createGroup,
  deleteGroup,
  grantRoleToGroup,
  listGroupMembership,
  listGroups,
  listRoles,
  markGroupDefault,
  revokeRoleFromGroup,
  updateGroup,
} from "@/services/directory";
import { joinGroup, leaveGroup } from "@/services/users";
import { listUsers } from "@/services/users";
import AppPicker from "@/components/AppPicker.vue";
import type { Page } from "@/models/paging";
import type { GroupMembership, GroupRow } from "@/models/directory";
import DirectoryTable from "./DirectoryTable.vue";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const page = ref<Page<GroupRow> | null>(null);
const failed = ref("");
const opened = ref<GroupRow | null>(null);
const membership = ref<GroupMembership | null>(null);

onMounted(async () => {
  try {
    page.value = await listGroups(realm.value, 0, 50);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function open(group: GroupRow) {
  opened.value = group;
  draft.value = { name: group.name, description: group.description };
  doomName.value = "";
  picker.value = "";
  membership.value = null;
  membership.value = await listGroupMembership(realm.value, group.group_id);
}

/// The birth row and the drawer's editable half.
const making = ref(false);
const newName = ref("");
const newDescription = ref("");
async function makeGroup() {
  if (!newName.value.trim()) return;
  try {
    await createGroup(realm.value, newName.value.trim(), newDescription.value.trim());
    making.value = false;
    newName.value = "";
    newDescription.value = "";
    page.value = await listGroups(realm.value, 0, 50);
  } catch {
    // The toast already said.
  }
}

const draft = ref({ name: "", description: "" });
async function saveGroup() {
  if (!opened.value) return;
  try {
    await updateGroup(realm.value, {
      ...opened.value,
      name: draft.value.name.trim() || opened.value.name,
      description: draft.value.description,
    });
    opened.value.name = draft.value.name.trim() || opened.value.name;
    opened.value.description = draft.value.description;
  } catch {
    // The toast already said.
  }
}

const doomName = ref("");
async function dropGroup() {
  if (!opened.value) return;
  try {
    await deleteGroup(realm.value, opened.value.group_id);
    opened.value = null;
    page.value = await listGroups(realm.value, 0, 50);
  } catch {
    // The toast already said: a group still holding members refuses in words.
  }
}

const picker = ref<"" | "member" | "role">("");
const pickRows = ref<{ id: string; label: string; held: boolean }[]>([]);
async function openPicker(kind: "member" | "role") {
  picker.value = kind;
  if (!opened.value || !membership.value) return;
  if (kind === "member") {
    const people = await listUsers(realm.value, 0, 200);
    const held = new Set(membership.value.users);
    pickRows.value = people.items.map((row) => ({
      id: row.user_id,
      label: row.user_name,
      held: held.has(row.user_id) || held.has(row.user_name),
    }));
  } else {
    const roles = await listRoles(realm.value, 0, 200);
    const held = new Set(membership.value.roles);
    pickRows.value = roles.items.map((row) => ({
      id: row.role_id,
      label: row.name,
      held: held.has(row.role_id) || held.has(row.name),
    }));
  }
}
async function pickAdd(id: string) {
  if (!opened.value) return;
  try {
    if (picker.value === "member") await joinGroup(realm.value, opened.value.group_id, id);
    else await grantRoleToGroup(realm.value, opened.value.group_id, id);
    picker.value = "";
    membership.value = await listGroupMembership(realm.value, opened.value.group_id);
  } catch {
    // The toast already said.
  }
}
async function dropMember(userId: string) {
  if (!opened.value) return;
  await leaveGroup(realm.value, opened.value.group_id, userId);
  membership.value = await listGroupMembership(realm.value, opened.value.group_id);
}
async function dropGroupRole(roleId: string) {
  if (!opened.value) return;
  await revokeRoleFromGroup(realm.value, opened.value.group_id, roleId);
  membership.value = await listGroupMembership(realm.value, opened.value.group_id);
}

/// Birthright intake: flips the mark and keeps the row honest on refusal.
async function flipDefault(group: GroupRow) {
  const wanted = !group.is_default;
  try {
    await markGroupDefault(realm.value, group, wanted);
    group.is_default = wanted;
  } catch {
    // The toast already said; the switch stays where the server left it.
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("groups-title") }}</h1>
      <div class="flex items-center gap-3">
        <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
          page.total
        }}</span>
        <button
          type="button"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          @click="making = !making"
        >
          {{ say("group-new") }}
        </button>
      </div>
    </div>

    <form
      v-if="making"
      class="mt-3 flex max-w-xl items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeGroup"
    >
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("settings-name") }}
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
        :total="page.total"
        :opened-key="opened?.group_id ?? null"
        :key-of="(row: GroupRow) => row.group_id"
        @open="open"
      />
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.group_id"
      @close="opened = null"
    >
      <form class="flex flex-col gap-2 text-xs" @submit.prevent="saveGroup">
        <div class="grid grid-cols-2 gap-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("settings-name") }}
            <input
              v-model="draft.name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
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
      <div class="mt-3">
        <AppToggle
          :model-value="opened.is_default"
          @update:model-value="flipDefault(opened)"
        >
          {{ say("group-default") }} <AppHint name="group-default-help" />
          <span
            v-if="opened.is_default"
            class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted"
            >{{ say("group-default-chip") }}</span
          >
        </AppToggle>
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("group-members") }}
        </div>
        <p v-if="membership && !membership.users.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            v-for="user in membership?.users ?? []"
            :key="user"
            class="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
          >
            {{ user }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropMember(user)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('member')"
          >
            {{ say("group-add-member") }}
          </button>
          <AppPicker
            v-if="picker === 'member'"
            :rows="pickRows"
            :title="say('group-add-member')"
            @add="pickAdd"
            @close="picker = ''"
          />
        </div>
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("group-grants") }}
        </div>
        <p v-if="membership && !membership.roles.length" class="mt-1.5 text-xs text-muted">
          {{ say("group-grants-none") }}
        </p>
        <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            v-for="role in membership?.roles ?? []"
            :key="role"
            class="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
          >
            {{ role }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropGroupRole(role)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('role')"
          >
            {{ say("group-grant-role") }}
          </button>
          <AppPicker
            v-if="picker === 'role'"
            :rows="pickRows"
            :title="say('group-grant-role')"
            @add="pickAdd"
            @close="picker = ''"
          />
        </div>
      </div>

      <div class="mt-4 rounded-lg border border-danger/40 p-3">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
          {{ say("settings-danger") }}
        </div>
        <p class="mt-1 text-[11px] text-muted">{{ say("group-delete-lede") }}</p>
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
            @click="dropGroup"
          >
            {{ say("group-delete") }}
          </button>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
