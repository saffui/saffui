<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  getOrganization,
  listOrganizationMembers,
  listOrganizations,
} from "@/services/directory";
import type { Page } from "@/models/paging";
import type { OrganizationRow, OrgMember } from "@/models/directory";
import DirectoryTable from "./DirectoryTable.vue";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const page = ref<Page<OrganizationRow> | null>(null);
const failed = ref("");
const opened = ref<OrganizationRow | null>(null);
const members = ref<OrgMember[] | null>(null);

onMounted(async () => {
  try {
    page.value = await listOrganizations(realm.value, 0, 50);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function open(org: OrganizationRow) {
  opened.value = org;
  members.value = null;
  [opened.value, members.value] = await Promise.all([
    getOrganization(realm.value, org.org_id),
    listOrganizationMembers(realm.value, org.org_id),
  ]);
}

function joined(member: OrgMember): string {
  if (!member.joined_at) return "";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
    new Date(member.joined_at),
  );
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("organizations-title") }}</h1>
      <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
        page.total
      }}</span>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4">
      <DirectoryTable
        :items="page.items"
        :total="page.total"
        :opened-key="opened?.org_id ?? null"
        :key-of="(row: OrganizationRow) => row.org_id"
        @open="open"
      >
        <template #extra="{ row }">
          <span v-if="!row.enabled" class="text-[10.5px] text-danger">{{
            say("users-disabled")
          }}</span>
        </template>
      </DirectoryTable>
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.org_id"
      @close="opened = null"
    >
      <dl class="grid grid-cols-[140px_1fr] gap-y-2 text-xs">
        <dt class="text-muted">{{ say("org-slug") }}</dt>
        <dd class="font-mono text-[11.5px]">{{ opened.name }}</dd>
        <dt class="text-muted">{{ say("users-col-state") }}</dt>
        <dd>{{ opened.enabled ? say("users-active") : say("users-disabled") }}</dd>
        <dt v-if="opened.redirect_url" class="text-muted">{{ say("org-landing") }}</dt>
        <dd v-if="opened.redirect_url" class="font-mono text-[10.5px]">
          {{ opened.redirect_url }}
        </dd>
      </dl>

      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("org-domains") }}
        </div>
        <p v-if="!opened.domains.length" class="mt-1.5 text-xs text-muted">
          {{ say("org-no-domains") }}
        </p>
        <div class="mt-1.5 flex flex-col gap-1.5">
          <div
            v-for="domain in opened.domains"
            :key="domain.name"
            class="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-xs"
          >
            <span class="font-mono text-[11px]">{{ domain.name }}</span>
            <span
              class="ml-auto inline-flex items-center gap-1.5 text-[10.5px]"
              :class="domain.verified ? 'text-ok' : 'text-warn'"
            >
              <span
                class="size-1.5 rounded-full"
                :class="domain.verified ? 'bg-ok' : 'bg-warn'"
              ></span>
              {{ domain.verified ? say("org-domain-verified") : say("org-domain-pending") }}
            </span>
          </div>
        </div>
      </div>

      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("org-members") }}
        </div>
        <p v-if="members && !members.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-col gap-1.5">
          <div
            v-for="member in members ?? []"
            :key="member.user_id"
            class="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-xs"
          >
            <span class="font-mono text-[11px]">{{ member.user_id }}</span>
            <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">{{
              member.membership_type
            }}</span>
            <span class="ml-auto font-mono text-[10px] text-faint">{{ joined(member) }}</span>
          </div>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
