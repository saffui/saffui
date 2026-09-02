<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import { listGroupMembership, listGroups } from "@/services/directory";
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
  membership.value = null;
  membership.value = await listGroupMembership(realm.value, group.group_id);
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("groups-title") }}</h1>
      <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
        page.total
      }}</span>
    </div>
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
      <p v-if="opened.description" class="text-xs text-muted">{{ opened.description }}</p>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("group-members") }}
        </div>
        <p v-if="membership && !membership.users.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="user in membership?.users ?? []"
            :key="user"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            >{{ user }}</span
          >
        </div>
      </div>
      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("group-grants") }}
        </div>
        <p v-if="membership && !membership.roles.length" class="mt-1.5 text-xs text-muted">
          {{ say("group-grants-none") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="role in membership?.roles ?? []"
            :key="role"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            >{{ role }}</span
          >
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
