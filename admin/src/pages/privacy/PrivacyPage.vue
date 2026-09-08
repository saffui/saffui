<script setup lang="ts">
// The subject-request register: what people asked of their data, each row
// on its statutory clock. Writing kinds cannot be fulfilled here at all
// until execution lands; this page lodges, proves, and refuses.
import { computed, onMounted, ref } from "vue";
import { afterWrites } from "@/services/writes";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import GovernanceTabs from "@/pages/governance/GovernanceTabs.vue";
import { JURISDICTIONS,
  advanceBreach,
  assembleEvidencePack,
  breachNotificationDraft,
  discoverBreach,
  listBreaches,
  type BreachRecord,
  fulfilSubjectRequest,
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

const breaches = ref<BreachRecord[]>([]);
async function load() {
  try {
    [rows.value, breaches.value] = await Promise.all([
      listSubjectRequests(realm.value),
      listBreaches(realm.value),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

const KINDS = ["access", "rectification", "erasure", "objection", "portability"];

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
const correction = ref({ email: "", given_name: "", family_name: "", phone_number: "" });
const objectedClient = ref("");
async function prove() {
  if (!opened.value) return;
  try {
    opened.value = await verifySubjectRequest(realm.value, opened.value.request_id);
    await load();
  } catch {
    // The toast already said.
  }
}
async function fulfil() {
  if (!opened.value) return;
  try {
    const held = correction.value;
    const spec =
      opened.value.kind === "rectification"
        ? {
            email: held.email.trim() || undefined,
            given_name: held.given_name.trim() || undefined,
            family_name: held.family_name.trim() || undefined,
            phone_number: held.phone_number.trim() || undefined,
          }
        : opened.value.kind === "objection"
          ? { client_id: objectedClient.value.trim() || undefined }
          : {};
    const done = await fulfilSubjectRequest(realm.value, opened.value.request_id, spec);
    // The copy rides this one answer and is never stored: hand it to the
    // operator as a file the moment it exists.
    if (done.bundle !== undefined) {
      const held = new Blob([JSON.stringify(done.bundle, null, 2)], {
        type: "application/json",
      });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(held);
      link.download = `subject-${done.kind}-${done.request_id}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    }
    opened.value = done;
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

const packPeriod = ref({ from: "", to: "" });
const packVerdict = ref("");
async function drawEvidencePack() {
  const from = Math.floor(new Date(packPeriod.value.from).getTime() / 1000);
  const to = Math.floor(new Date(packPeriod.value.to).getTime() / 1000);
  if (!Number.isFinite(from) || !Number.isFinite(to)) return;
  try {
    const pack = await assembleEvidencePack(realm.value, from, to);
    packVerdict.value = String(pack.verdict ?? "");
    const held = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(held);
    link.download = `evidence-pack-${realm.value}-${from}-${to}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch {
    // The toast already said.
  }
}

const SEVERITIES = ["low", "medium", "high", "critical"];
const finding = ref(false);
const breachDraft = ref({
  description: "",
  categories: "",
  severity: "medium",
  jurisdiction: "eu",
});
async function recordFound() {
  try {
    await discoverBreach(realm.value, {
      description: breachDraft.value.description.trim(),
      data_categories: breachDraft.value.categories
        .split(",")
        .map((held) => held.trim())
        .filter(Boolean),
      severity: breachDraft.value.severity,
      jurisdiction: breachDraft.value.jurisdiction,
    });
    finding.value = false;
    breachDraft.value = { description: "", categories: "", severity: "medium", jurisdiction: "eu" };
    await load();
  } catch {
    // The toast already said.
  }
}

const openedBreach = ref<BreachRecord | null>(null);
const assessment = ref({ severity: "high", subjects: "" });
const filing = ref({ notified_to: "", filed_by: "" });
const notificationDraft = ref<Record<string, unknown> | null>(null);
async function stepBreach(step: "assess" | "filing" | "not-notifiable" | "close") {
  if (!openedBreach.value) return;
  try {
    const body =
      step === "assess"
        ? {
            severity: assessment.value.severity,
            subjects_affected: assessment.value.subjects
              ? Number(assessment.value.subjects)
              : undefined,
          }
        : step === "filing"
          ? { notified_to: filing.value.notified_to.trim(), filed_by: filing.value.filed_by.trim() }
          : {};
    openedBreach.value = await advanceBreach(
      realm.value,
      openedBreach.value.breach_id,
      step,
      body,
    );
    await load();
  } catch {
    // The toast already said.
  }
}
async function showNotificationDraft() {
  if (!openedBreach.value) return;
  try {
    notificationDraft.value = await breachNotificationDraft(
      realm.value,
      openedBreach.value.breach_id,
    );
  } catch {
    // The toast already said.
  }
}
function breachOverdue(held: BreachRecord): boolean {
  return (
    (held.status === "discovered" || held.status === "assessed") &&
    held.notify_by !== null &&
    held.notify_by < now
  );
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
        class="ml-auto sf-button sf-button-primary"
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

    <div class="mt-8 flex max-w-4xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("breach-title") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="finding = true"
      >
        {{ say("breach-record") }}
      </button>
    </div>
    <div class="mt-2 max-w-4xl overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("breach-col-what") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("breach-col-severity") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("privacy-col-stage") }}</th>
            <th class="px-3 py-2 text-right font-medium">{{ say("breach-col-notify-by") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="held in breaches"
            :key="held.breach_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            @click="openedBreach = held; notificationDraft = null"
          >
            <td class="px-3 py-2">{{ held.description }}</td>
            <td class="px-3 py-2">
              <span
                class="rounded border px-1.5 py-0.5 font-mono text-[10px]"
                :class="
                  held.severity === 'critical' || held.severity === 'high'
                    ? 'border-danger/40 text-danger'
                    : 'border-border text-muted'
                "
              >
                {{ held.severity }}
              </span>
            </td>
            <td class="px-3 py-2 text-[10.5px]">{{ say(`breach-status-${held.status}`) }}</td>
            <td
              class="px-3 py-2 text-right font-mono text-[10.5px]"
              :class="breachOverdue(held) ? 'text-danger' : 'text-faint'"
            >
              {{ held.notify_by ? instant(held.notify_by) : say("breach-no-window") }}
              <span
                v-if="breachOverdue(held)"
                class="ml-1 rounded border border-danger/40 px-1 text-[9.5px] uppercase"
              >
                {{ say("privacy-overdue") }}
              </span>
            </td>
          </tr>
          <tr v-if="!breaches.length">
            <td colspan="4" class="px-3 py-3 text-muted">{{ say("breach-none") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <AppDrawer v-if="finding" :title="say('breach-record')" @close="finding = false">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="recordFound">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("breach-col-what") }}
          <textarea
            v-model="breachDraft.description"
            required
            rows="3"
            class="sf-field mt-1"
          ></textarea>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("breach-categories") }}
          <input
            v-model="breachDraft.categories"
            spellcheck="false"
            :placeholder="say('breach-categories-hint')"
            class="sf-field mt-1"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("breach-col-severity") }}
          <select v-model="breachDraft.severity" class="sf-field mt-1">
            <option v-for="held in SEVERITIES" :key="held" :value="held">{{ held }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-col-jurisdiction") }}
          <select v-model="breachDraft.jurisdiction" class="sf-field mt-1">
            <option v-for="held in JURISDICTIONS" :key="held" :value="held">{{ held }}</option>
          </select>
        </label>
        <button type="submit" class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink">
          {{ say("settings-save") }}
        </button>
      </form>
    </AppDrawer>

    <AppDrawer
      v-if="openedBreach"
      :title="openedBreach.description"
      :subtitle="openedBreach.breach_id"
      @close="openedBreach = null"
    >
      <div class="flex flex-col gap-3 text-xs">
        <div class="grid grid-cols-[140px_1fr] items-baseline gap-y-2">
          <span class="text-muted">{{ say("privacy-col-stage") }}</span>
          <span>{{ say(`breach-status-${openedBreach.status}`) }}</span>
          <span class="text-muted">{{ say("breach-col-severity") }}</span>
          <span class="font-mono">{{ openedBreach.severity }}</span>
          <span class="text-muted">{{ say("breach-discovered") }}</span>
          <span class="font-mono text-[11px]">{{ instant(openedBreach.discovered_at) }}</span>
          <span class="text-muted">{{ say("breach-col-notify-by") }}</span>
          <span class="font-mono text-[11px]" :class="breachOverdue(openedBreach) ? 'text-danger' : ''">
            {{ openedBreach.notify_by ? instant(openedBreach.notify_by) : say("breach-no-window") }}
          </span>
          <span v-if="openedBreach.filed_by" class="text-muted">{{ say("breach-filed") }}</span>
          <span v-if="openedBreach.filed_by">
            {{ openedBreach.filed_by }} → {{ openedBreach.notified_to }}
          </span>
        </div>

        <div v-if="openedBreach.status === 'discovered'" class="flex flex-col gap-2 rounded-lg border border-border p-3">
          <p class="text-[11px] text-muted">{{ say("breach-assess-lede") }}</p>
          <select v-model="assessment.severity" class="sf-field">
            <option v-for="held in SEVERITIES" :key="held" :value="held">{{ held }}</option>
          </select>
          <input
            v-model="assessment.subjects"
            type="number"
            :placeholder="say('breach-subjects')"
            class="sf-field"
          />
          <button type="button" class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink" @click="stepBreach('assess')">
            {{ say("breach-assess") }}
          </button>
        </div>

        <div v-if="openedBreach.status === 'assessed'" class="flex flex-col gap-2 rounded-lg border border-border p-3">
          <p class="text-[11px] text-muted">{{ say("breach-filing-lede") }}</p>
          <input v-model="filing.notified_to" :placeholder="say('breach-notified-to')" class="sf-field" />
          <input v-model="filing.filed_by" :placeholder="say('breach-filed-by')" class="sf-field" />
          <div class="flex gap-2">
            <button type="button" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink" @click="stepBreach('filing')">
              {{ say("breach-file") }}
            </button>
            <button type="button" class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2" @click="stepBreach('not-notifiable')">
              {{ say("breach-not-notifiable") }}
            </button>
          </div>
        </div>

        <button
          v-if="openedBreach.status === 'notified' || openedBreach.status === 'not-notifiable'"
          type="button"
          class="self-start rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
          @click="stepBreach('close')"
        >
          {{ say("breach-close") }}
        </button>

        <button type="button" class="self-start rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2" @click="showNotificationDraft">
          {{ say("breach-draft") }}
        </button>
        <pre
          v-if="notificationDraft"
          class="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-[10.5px]"
        >{{ JSON.stringify(notificationDraft, null, 2) }}</pre>
      </div>
    </AppDrawer>

    <div class="mt-8 max-w-4xl rounded-lg border border-border bg-surface px-4 py-3">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("evidence-title") }}
      </h2>
      <p class="mt-1 text-xs text-muted">{{ say("evidence-lede") }}</p>
      <div class="mt-2 flex flex-wrap items-center gap-2 text-xs">
        <input v-model="packPeriod.from" type="datetime-local" class="sf-field" />
        <span class="text-faint">→</span>
        <input v-model="packPeriod.to" type="datetime-local" class="sf-field" />
        <button type="button" class="sf-button sf-button-primary" @click="drawEvidencePack">
          {{ say("evidence-draw") }}
        </button>
        <span v-if="packVerdict" class="rounded border px-1.5 py-0.5 font-mono text-[10px]" :class="packVerdict === 'sound' ? 'border-border text-ok' : 'border-danger/40 text-danger'">
          {{ packVerdict }}
        </span>
      </div>
    </div>

    <AppDrawer v-if="lodging" :title="say('privacy-lodge')" @close="lodging = false">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="lodge">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-identifier") }}
          <input
            v-model="form.identifier"
            required
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
          <span class="mt-0.5 block font-normal text-faint">{{ say("privacy-identifier-hint") }}</span>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-col-kind") }}
          <select v-model="form.kind" class="sf-field mt-1">
            <option v-for="kind in KINDS" :key="kind" :value="kind">{{ say(`privacy-kind-${kind}`) }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-col-jurisdiction") }}
          <select v-model="form.jurisdiction" class="sf-field mt-1">
            <option v-for="held in JURISDICTIONS" :key="held" :value="held">{{ held }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("privacy-due") }}
          <input
            v-model="form.due"
            type="datetime-local"
            class="sf-field mt-1"
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
          <span v-if="opened.outcome" class="text-muted">{{ say("privacy-outcome") }}</span>
          <span v-if="opened.outcome">{{ opened.outcome }}</span>
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
          <div
            v-if="opened.stage === 'verified' && opened.kind === 'erasure'"
            class="rounded-lg border border-danger/40 p-3"
          >
            <p class="text-[11px] text-muted">{{ say("privacy-fulfil-lede") }}</p>
            <button
              type="button"
              class="mt-2 rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white"
              @click="fulfil"
            >
              {{ say("privacy-fulfil") }}
            </button>
          </div>
          <div
            v-if="opened.stage === 'verified' && opened.kind === 'rectification'"
            class="flex flex-col gap-2 rounded-lg border border-border p-3"
          >
            <p class="text-[11px] text-muted">{{ say("privacy-correct-lede") }}</p>
            <input
              v-for="field in (['email', 'given_name', 'family_name', 'phone_number'] as const)"
              :key="field"
              v-model="correction[field]"
              :placeholder="say(`privacy-correct-${field}`)"
              spellcheck="false"
              class="sf-field"
            />
            <button
              type="button"
              class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink"
              @click="fulfil"
            >
              {{ say("privacy-correct") }}
            </button>
          </div>
          <div
            v-if="opened.stage === 'verified' && opened.kind === 'objection'"
            class="flex flex-col gap-2 rounded-lg border border-border p-3"
          >
            <p class="text-[11px] text-muted">{{ say("privacy-object-lede") }}</p>
            <input
              v-model="objectedClient"
              :placeholder="say('privacy-object-client')"
              spellcheck="false"
              class="sf-field font-mono"
            />
            <button
              type="button"
              class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink"
              @click="fulfil"
            >
              {{ say("privacy-object") }}
            </button>
          </div>
          <button
            v-if="
              opened.stage === 'verified' &&
              (opened.kind === 'access' || opened.kind === 'portability')
            "
            type="button"
            class="self-start sf-button sf-button-primary"
            @click="fulfil"
          >
            {{ say("privacy-produce") }}
          </button>
          <div class="mt-2 rounded-lg border border-danger/40 p-3">
            <p class="text-[11px] text-muted">{{ say("privacy-refuse-lede") }}</p>
            <div class="mt-2 flex items-center gap-2">
              <input
                v-model="reason"
                :placeholder="say('privacy-reason')"
                class="w-full sf-field"
              />
              <button
                type="button"
                class="sf-button sf-button-danger disabled:opacity-40"
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
