<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import { listRoleHolders, listRoles } from "@/services/directory";
import type { Page } from "@/models/paging";
import type { RoleHolders, RoleRow } from "@/models/directory";
import DirectoryTable from "./DirectoryTable.vue";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const page = ref<Page<RoleRow> | null>(null);
const failed = ref("");
const opened = ref<RoleRow | null>(null);
const holders = ref<RoleHolders | null>(null);

onMounted(async () => {
  try {
    page.value = await listRoles(realm.value, 0, 50);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function open(role: RoleRow) {
  opened.value = role;
  holders.value = null;
  holders.value = await listRoleHolders(realm.value, role.role_id);
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("roles-title") }}</h1>
      <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
        page.total
      }}</span>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4">
      <DirectoryTable
        :items="page.items"
        :total="page.total"
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
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.role_id"
      @close="opened = null"
    >
      <p v-if="opened.description" class="text-xs text-muted">{{ opened.description }}</p>
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
    </AppDrawer>
  </div>
</template>
