<script setup lang="ts">
// The subject-request register: what people asked of their data, each row
// on its statutory clock. Writing kinds cannot be fulfilled here at all
// until execution lands; this page lodges, proves, and refuses.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import GovernanceTabs from "@/pages/governance/GovernanceTabs.vue";
import {
  lodgeSubjectRequest,
  listSubjectRequests,
  refuseSubjectRequest,
  verifySubjectRequest,
  type SubjectRequest,
} from "@/services/compliance";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const rows = ref<SubjectRequest[]>([]);
const failed = ref("");

async function load() {
  try {
    rows.value = await listSubjectRequests(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

const KINDS = ["access", "rectification", "erasure", "objection", "portability"];
const JURISDICTIONS = ["eu", "ke", "ng", "za", "gh", "tg", "bj", "ci", "bf", "ga", "cm", "other"];

const lodging = ref(false);
const form = ref({ identifier: "", kind: "access", jurisdiction: "eu", due: "" });
async function lodge() {
  try {
    const due = form.value.due ? Math.floor(new Date(form.value.due).getTime() / 1000) : undefined;
    await lodgeSubjectRequest(realm.value, {
      subject_identifier: form.value.identifier.trim(),
      kind: form.value.kind,
      jurisdiction: form.value.jurisdiction,
      due_at: due,
    });
    lodging.value = false;
    form.value = { identifier: "", kind: "access", jurisdiction: "eu", due: "" };
    await load();
  } catch {
    // The toast already said.
  }
}

const opened = ref<SubjectRequest | null>(null);
const reason = ref("");
async function prove() {
  if (!opened.value) return;
  try {
    opened.value = await verifySubjectRequest(realm.value, opened.value.request_id);
    await load();
  } catch {
    // The toast already said.
  }
}
async function refuse() {
  if (!opened.value || !reason.value.trim()) return;
  try {
    opened.value = await refuseSubjectRequest(
      realm.value,
      opened.value.request_id,
      reason.value.trim(),
    );
    reason.value = "";
    await load();
  } catch {
    // The toast already said.
  }
}

const now = Math.floor(Date.now() / 1000);
function overdue(row: SubjectRequest): boolean {
  return row.closed_at === null && row.due_at < now;
}
function instant(epoch: number | null): string {
  if (!epoch) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}
</script>

<template>
  <div>
    <GovernanceTabs />
    <div class="flex max-w-4xl items-center">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("privacy-title") }}</h1>
        <p class="mt-1 text-xs text-muted">{{ say("privacy-lede") }}</p>
      </div>
      <button
        type="button"
        class="ml-auto rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        @click="lodging = true"
      >
        {{ say("privacy-lodge") }}
      </button>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 max-w-4xl overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("privacy-col-subject") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("privacy-col-kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("privacy-col-stage") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("privacy-col-jurisdiction") }}</th>
            <th class="px-3 py-2 text-right font-medium">{{ say("privacy-col-due") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in rows"
            :key="row.request_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            @click="opened = row; reason = ''"
          >
            <td class="px-3 py-2 font-mono text-[11px]">{{ row.subject_identifier }}</td>
            <td class="px-3 py-2">
              <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
                {{ row.kind }}
              </span>
            </td>
            <td class="px-3 py-2 text-[10.5px]">
              <span :class="row.stage === 'refused' ? 'text-danger' : row.stage === 'fulfilled' ? 'text-ok' : ''">
                {{ say(`privacy-stage-${row.stage}`) }}
              </span>
            </td>
            <td class="px-3 py-2 font-mono text-[10.5px] text-faint">{{ row.jurisdiction }}</td>
            <td class="px-3 py-2 text-right font-mono text-[10.5px]" :class="overdue(row) ? 'text-danger' : 'text-faint'">
              {{ instant(row.due_at) }}
              <span v-if="overdue(row)" class="ml-1 rounded border border-danger/40 px-1 text-[9.5px] uppercase">
                {{ say("privacy-overdue") }}
              </span>
            </td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="5" class="px-3 py-3 text-muted">{{ say("privacy-none") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <AppDrawer v-if="lodging" :title="say('privacy-lodge')" @close="lodging = false">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="lodge">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-identifier") }}
          <input
            v-model="form.identifier"
            required
            spellcheck="false"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          />
          <span class="mt-0.5 block font-normal text-faint">{{ say("privacy-identifier-hint") }}</span>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-col-kind") }}
          <select v-model="form.kind" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink">
            <option v-for="kind in KINDS" :key="kind" :value="kind">{{ say(`privacy-kind-${kind}`) }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-col-jurisdiction") }}
          <select v-model="form.jurisdiction" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink">
            <option v-for="held in JURISDICTIONS" :key="held" :value="held">{{ held }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-due") }}
          <input
            v-model="form.due"
            type="datetime-local"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
          <span class="mt-0.5 block font-normal text-faint">{{ say("privacy-due-hint") }}</span>
        </label>
        <button type="submit" class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink">
          {{ say("settings-save") }}
        </button>
      </form>
    </AppDrawer>

    <AppDrawer
      v-if="opened"
      :title="opened.subject_identifier"
      :subtitle="opened.request_id"
      @close="opened = null"
    >
      <div class="flex flex-col gap-3 text-xs">
        <div class="grid grid-cols-[140px_1fr] items-baseline gap-y-2">
          <span class="text-muted">{{ say("privacy-col-kind") }}</span>
          <span class="font-mono">{{ opened.kind }}</span>
          <span class="text-muted">{{ say("privacy-col-stage") }}</span>
          <span>{{ say(`privacy-stage-${opened.stage}`) }}</span>
          <span class="text-muted">{{ say("privacy-account") }}</span>
          <span class="font-mono">{{ opened.user_id || say("privacy-no-account") }}</span>
          <span class="text-muted">{{ say("privacy-received") }}</span>
          <span class="font-mono text-[11px]">{{ instant(opened.received_at) }}</span>
          <span class="text-muted">{{ say("privacy-col-due") }}</span>
          <span class="font-mono text-[11px]" :class="overdue(opened) ? 'text-danger' : ''">
            {{ instant(opened.due_at) }}
          </span>
          <span v-if="opened.reason" class="text-muted">{{ say("privacy-reason") }}</span>
          <span v-if="opened.reason">{{ opened.reason }}</span>
        </div>
        <p class="text-[10.5px] text-faint">{{ opened.deadline_source }}</p>

        <template v-if="opened.stage === 'received' || opened.stage === 'verified'">
          <button
            v-if="opened.stage === 'received'"
            type="button"
            class="self-start rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
            @click="prove"
          >
            {{ say("privacy-verify") }}
          </button>
          <div class="mt-2 rounded-lg border border-danger/40 p-3">
            <p class="text-[11px] text-muted">{{ say("privacy-refuse-lede") }}</p>
            <div class="mt-2 flex items-center gap-2">
              <input
                v-model="reason"
                :placeholder="say('privacy-reason')"
                class="w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
              />
              <button
                type="button"
                class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
                :disabled="!reason.trim()"
                @click="refuse"
              >
                {{ say("privacy-refuse") }}
              </button>
            </div>
          </div>
        </template>
      </div>
    </AppDrawer>
  </div>
</template>
