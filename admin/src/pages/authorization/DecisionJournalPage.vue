<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import DangerDialog from "@/components/DangerDialog.vue";
import { listDecisions, listDisagreements, pruneDecisionsBefore } from "@/services/authz";
import { toastOk } from "@/services/toasts";
import { afterWrites } from "@/services/writes";
import type { DecisionRow } from "@/models/authz";

const route = useRoute();
const realm = () => String(route.params.realm);
const decisions = ref<DecisionRow[]>([]);
const disagreements = ref<DecisionRow[]>([]);
const failed = ref("");
const loading = ref(false);
const pruneDate = ref("");
const pruneOpen = ref(false);
const pruneFailed = ref("");
const pruning = ref(false);

function instant(millis: number | null): string {
  return millis ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(millis)) : "";
}

async function load() {
  loading.value = true;
  failed.value = "";
  try {
    [decisions.value, disagreements.value] = await Promise.all([
      listDecisions(realm()),
      listDisagreements(realm()),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
afterWrites(load);

function openPruneDialog() {
  if (!pruneDate.value) return;
  pruneFailed.value = "";
  pruneOpen.value = true;
}

async function pruneDecisions() {
  if (!pruneDate.value || pruning.value) return;
  pruning.value = true;
  pruneFailed.value = "";
  try {
    const before = new Date(`${pruneDate.value}T00:00:00.000Z`);
    const result = await pruneDecisionsBefore(realm(), before);
    toastOk(say("decisions-prune-done", { count: result.removed }));
    pruneOpen.value = false;
    pruneDate.value = "";
    await load();
  } catch (refused) {
    pruneFailed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    pruning.value = false;
  }
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("decision-journal-title") }}</h1>
        <p class="mt-1 text-xs text-muted">{{ say("decision-journal-lede") }}</p>
      </div>
      <button type="button" class="sf-button sf-button-secondary ml-auto" :disabled="loading" @click="load">
        {{ loading ? say("decision-journal-refreshing") : say("decision-journal-refresh") }}
      </button>
    </div>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <section class="mt-5 rounded-lg border border-danger/35 bg-surface p-3">
      <div class="flex flex-wrap items-end gap-3">
        <label class="min-w-56 flex-1 text-[11px] font-medium text-muted">
          {{ say("decisions-prune-before") }} <AppHint name="decisions-prune-help" />
          <input v-model="pruneDate" type="date" class="sf-field mt-1 font-mono" />
        </label>
        <button
          type="button"
          class="sf-button sf-button-danger disabled:opacity-40"
          :disabled="!pruneDate"
          @click="openPruneDialog"
        >
          {{ say("decisions-prune") }}
        </button>
      </div>
    </section>

    <section class="mt-5">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-muted uppercase">
        {{ say("decision-journal-recent") }}
      </h2>
      <div v-if="!decisions.length" class="mt-2 rounded-lg border border-border bg-surface px-3 py-4 text-xs text-muted">
        {{ say("decision-journal-empty") }}
      </div>
      <div v-else class="sf-list mt-2 overflow-x-auto">
        <table class="sf-table">
          <thead>
            <tr>
              <th>{{ say("decision-col-when") }}</th>
              <th>{{ say("decision-col-subject") }}</th>
              <th>{{ say("decision-col-question") }}</th>
              <th>{{ say("decision-col-reported") }}</th>
              <th>{{ say("decision-col-computed") }}</th>
              <th>{{ say("decision-col-duration") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in decisions" :key="row.decision_id" class="border-b border-border/60 last:border-0">
              <td class="whitespace-nowrap text-[10.5px] text-muted">{{ instant(row.occurred_at_millis) }}</td>
              <td class="font-mono text-[11px]">{{ row.subject_id }}</td>
              <td class="max-w-96 font-mono text-[10.5px] break-all">
                {{ row.action }} {{ row.resource_kind }}<template v-if="row.resource_ref">:{{ row.resource_ref }}</template>
              </td>
              <td class="font-mono text-[10.5px]">{{ row.reported }}</td>
              <td>
                <span class="rounded px-1.5 py-0.5 text-[10.5px] font-semibold" :class="row.computed === 'permit' ? 'bg-ok/12 text-ok' : 'bg-danger/12 text-danger'">
                  {{ row.computed }}
                </span>
              </td>
              <td class="font-mono text-[10.5px] text-faint">{{ row.duration_us }}µs</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="mt-6">
      <h2 class="flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-muted uppercase">
        {{ say("decision-journal-disagreements") }}
        <span class="rounded bg-warn/12 px-1.5 py-0.5 text-[10px] text-warn">{{ disagreements.length }}</span>
      </h2>
      <p v-if="!disagreements.length" class="mt-2 text-xs text-muted">{{ say("decision-journal-no-disagreements") }}</p>
      <div v-else class="sf-list mt-2 overflow-x-auto">
        <table class="sf-table">
          <thead>
            <tr>
              <th>{{ say("decision-col-subject") }}</th>
              <th>{{ say("decision-col-question") }}</th>
              <th>{{ say("decision-col-reported") }}</th>
              <th>{{ say("decision-col-computed") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in disagreements" :key="row.decision_id" class="border-b border-border/60 last:border-0">
              <td class="font-mono text-[11px]">{{ row.subject_id }}</td>
              <td class="font-mono text-[10.5px] break-all">{{ row.action }} {{ row.resource_kind }}<template v-if="row.resource_ref">:{{ row.resource_ref }}</template></td>
              <td class="font-mono text-[10.5px]">{{ row.reported }}</td>
              <td class="font-mono text-[10.5px] font-semibold text-danger">{{ row.computed }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <DangerDialog
      :open="pruneOpen"
      :title="say('decisions-prune-title')"
      :named="pruneDate"
      :lede="say('decisions-prune-lede')"
      :facts="[{ value: pruneDate, label: say('decisions-prune-limit') }]"
      :aside="say('decisions-prune-aside')"
      :confirm-label="say('decisions-prune-confirm')"
      :failed="pruneFailed"
      @close="pruneOpen = false"
      @confirm="pruneDecisions"
    />
  </div>
</template>
