<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  claimDomain,
  createOrganization,
  deleteOrganization,
  dropDomain,
  getOrganization,
  listOrganizationMembers,
  listOrganizations,
  verifyDomain,
} from "@/services/directory";
import AppHint from "@/components/AppHint.vue";
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

const making = ref(false);
const newName = ref("");
const newDisplay = ref("");
async function makeOrg() {
  if (!newName.value.trim()) return;
  try {
    await createOrganization(realm.value, {
      name: newName.value.trim(),
      display_name: newDisplay.value.trim() || newName.value.trim(),
    });
    making.value = false;
    newName.value = "";
    newDisplay.value = "";
    page.value = await listOrganizations(realm.value, 0, 50);
  } catch {
    // The toast already said.
  }
}

/// The TXT challenge to publish, one copyable line, checked only when the
/// operator says so: a check that silently retries forever hides a typo.
const newDomain = ref("");
const challenge = ref<{ domain: string; line: string } | null>(null);
async function claim() {
  if (!opened.value || !newDomain.value.trim()) return;
  try {
    const answered = await claimDomain(realm.value, opened.value.org_id, newDomain.value.trim());
    challenge.value = {
      domain: answered.domain,
      line: `${answered.domain}. IN TXT "${answered.challenge}"`,
    };
    newDomain.value = "";
    opened.value = await getOrganization(realm.value, opened.value.org_id);
  } catch {
    // The toast already said.
  }
}
async function copyChallenge() {
  if (!challenge.value) return;
  try {
    await navigator.clipboard.writeText(challenge.value.line);
  } catch {
    // Selectable by hand.
  }
}
async function verify(domain: string) {
  if (!opened.value) return;
  try {
    await verifyDomain(realm.value, opened.value.org_id, domain);
    opened.value = await getOrganization(realm.value, opened.value.org_id);
  } catch {
    // The toast already said.
  }
}
async function drop(domain: string) {
  if (!opened.value) return;
  await dropDomain(realm.value, opened.value.org_id, domain);
  opened.value = await getOrganization(realm.value, opened.value.org_id);
}

const doomName = ref("");
async function dropOrg() {
  if (!opened.value) return;
  try {
    await deleteOrganization(realm.value, opened.value.org_id);
    opened.value = null;
    page.value = await listOrganizations(realm.value, 0, 50);
  } catch {
    // The toast already said.
  }
}

async function open(org: OrganizationRow) {
  challenge.value = null;
  doomName.value = "";
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
      <button
        type="button"
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        @click="making = !making"
      >
        {{ say("org-new") }}
      </button>
      <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
        page.total
      }}</span>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <form
      v-if="making"
      class="mt-3 flex max-w-xl items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeOrg"
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
        {{ say("directory-col-display") }}
        <input
          v-model="newDisplay"
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
              {{ domain.verified ? say("org-domain-verified") : say("org-domain-pending") }}
            </span>
            <button
              v-if="!domain.verified"
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2"
              @click="verify(domain.name)"
            >
              {{ say("org-domain-check") }}
            </button>
            <button
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
              @click="drop(domain.name)"
            >
              {{ say("action-remove") }}
            </button>
          </div>
        </div>

        <form class="mt-2 flex items-end gap-2 text-xs" @submit.prevent="claim">
          <label class="flex-1 text-[11px] font-medium text-muted">
            {{ say("org-claim-domain") }} <AppHint name="org-claim-help" />
            <input
              v-model="newDomain"
              placeholder="apps.example.com"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
            />
          </label>
          <button
            type="submit"
            class="rounded-md border border-border px-3 py-1.5 text-[11px] hover:bg-surface-2"
          >
            {{ say("org-claim") }}
          </button>
        </form>
        <div
          v-if="challenge"
          class="mt-2 flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2"
        >
          <code class="min-w-0 flex-1 truncate font-mono text-[10.5px]">{{ challenge.line }}</code>
          <button
            type="button"
            class="rounded border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-3"
            @click="copyChallenge"
          >
            {{ say("action-copy") }}
          </button>
        </div>
        <p v-if="challenge" class="mt-1 text-[10.5px] text-muted">
          {{ say("org-challenge-lede") }}
        </p>
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
      <div class="mt-4 rounded-lg border border-danger/40 p-3">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
          {{ say("settings-danger") }}
        </div>
        <p class="mt-1 text-[11px] text-muted">{{ say("org-delete-lede") }}</p>
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
            @click="dropOrg"
          >
            {{ say("org-delete") }}
          </button>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
