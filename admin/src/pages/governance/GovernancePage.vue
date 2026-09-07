<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { listIgaGrants, listIgaRules } from "@/services/federation";
import { afterWrites } from "@/services/writes";
import {
  convergeRules,
  createRule,
  deleteRule,
  deleteSodException,
  deleteSodRule,
  handGrant,
  listSodExceptions,
  listSodRules,
  approveRequest,
  denyRequest,
  listRequests,
  listSodViolations,
  lodgeRequest,
  putSodException,
  putSodRule,
  revokeGrant,
  updateRule,
  withdrawRequest,
} from "@/services/governance";
import type { AccessRequest, SodException, SodRule, SodViolation } from "@/services/governance";
import AppHint from "@/components/AppHint.vue";
import GovernanceTabs from "./GovernanceTabs.vue";
import AppToggle from "@/components/AppToggle.vue";
import type { IgaGrant, IgaRule } from "@/models/federation";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const rules = ref<IgaRule[]>([]);
const failed = ref("");
const askedUser = ref("");
const ledger = ref<IgaGrant[] | null>(null);

const making = ref(false);
const ruleDraft = ref({
  mode: "attribute" as "attribute" | "expr",
  when_attribute: "",
  when_value: "",
  when_expr: "",
  roles: "",
  enabled: true,
});
async function makeRule() {
  const held = ruleDraft.value;
  const roles = held.roles
    .split(/[\n,]/)
    .map((row) => row.trim())
    .filter(Boolean);
  if (!roles.length) return;
  try {
    await createRule(realm.value, {
      when_attribute: held.mode === "attribute" ? held.when_attribute.trim() : undefined,
      when_value: held.mode === "attribute" ? held.when_value.trim() : "",
      when_expr: held.mode === "expr" ? held.when_expr.trim() : undefined,
      roles,
      enabled: held.enabled,
    });
    making.value = false;
    rules.value = await listIgaRules(realm.value);
  } catch {
    // The toast already said.
  }
}
async function flipRule(rule: { rule_id: string; enabled: boolean } & Record<string, unknown>) {
  try {
    await updateRule(realm.value, rule.rule_id, { ...rule, enabled: !rule.enabled });
    rule.enabled = !rule.enabled;
  } catch {
    // The toast already said.
  }
}
async function dropRule(ruleId: string) {
  try {
    await deleteRule(realm.value, ruleId);
    rules.value = await listIgaRules(realm.value);
  } catch {
    // The toast already said.
  }
}
async function converge() {
  try {
    await convergeRules(realm.value);
  } catch {
    // The toast already said.
  }
}

const grantDraft = ref({ user_id: "", role_id: "", expires_at: "" });
async function giveGrant() {
  const held = grantDraft.value;
  if (!held.user_id.trim() || !held.role_id.trim()) return;
  try {
    await handGrant(realm.value, {
      user_id: held.user_id.trim(),
      role_id: held.role_id.trim(),
      expires_at: held.expires_at.trim() || undefined,
    });
    grantDraft.value = { user_id: "", role_id: "", expires_at: "" };
    if (askedUser.value.trim() === held.user_id.trim()) await consult();
  } catch {
    // The toast already said.
  }
}

/// Hand-given grants only: what a rule gave, the rule takes away.
async function takeGrant(roleId: string) {
  if (!askedUser.value.trim()) return;
  try {
    await revokeGrant(realm.value, askedUser.value.trim(), roleId);
    await consult();
  } catch {
    // The toast already said.
  }
}

async function load() {
  try {
    rules.value = await listIgaRules(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

function condition(rule: IgaRule): string {
  if (rule.when_expr) return rule.when_expr;
  if (rule.when_attribute) return `${rule.when_attribute}=${rule.when_value ?? ""}`;
  return "";
}

async function consult() {
  ledger.value = null;
  if (!askedUser.value.trim()) return;
  try {
    ledger.value = await listIgaGrants(realm.value, askedUser.value.trim());
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function until(grant: IgaGrant): string {
  if (!grant.expires_at) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(grant.expires_at));
}

const sodRules = ref<SodRule[]>([]);
const sodViolations = ref<SodViolation[]>([]);
const sodExceptions = ref<SodException[]>([]);
const makingSod = ref(false);
const sodDraft = ref({ rule_id: "", roles: "", min_conflicting: "", enabled: true });

async function loadSod() {
  try {
    sodRules.value = await listSodRules(realm.value);
    sodExceptions.value = await listSodExceptions(realm.value);
    sodViolations.value = await listSodViolations(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(loadSod);
afterWrites(loadSod);

async function makeSodRule() {
  const held = sodDraft.value;
  const roles = held.roles
    .split(/[\n,]/)
    .map((row) => row.trim())
    .filter(Boolean);
  if (!held.rule_id.trim() || !roles.length) return;
  try {
    await putSodRule(realm.value, held.rule_id.trim(), {
      roles,
      min_conflicting: held.min_conflicting.trim() ? Number(held.min_conflicting) : undefined,
      enabled: held.enabled,
    });
    makingSod.value = false;
    sodDraft.value = { rule_id: "", roles: "", min_conflicting: "", enabled: true };
  } catch {
    // The toast already said.
  }
}
async function flipSodRule(rule: SodRule) {
  try {
    await putSodRule(realm.value, rule.rule_id, {
      roles: rule.roles,
      min_conflicting: rule.min_conflicting,
      enabled: !rule.enabled,
    });
  } catch {
    // The toast already said.
  }
}
async function dropSodRule(ruleId: string) {
  try {
    await deleteSodRule(realm.value, ruleId);
  } catch {
    // The toast already said.
  }
}

/// Pre-filled from the standing combination: the excuse covers exactly
/// what stands, nothing wider.
const excusing = ref<SodViolation | null>(null);
const excuseDraft = ref({ justification: "", valid_until: "" });
function openExcuse(violation: SodViolation) {
  excusing.value = violation;
  excuseDraft.value = { justification: "", valid_until: "" };
}
async function giveExcuse() {
  const target = excusing.value;
  if (!target) return;
  if (!excuseDraft.value.justification.trim() || !excuseDraft.value.valid_until.trim()) return;
  try {
    await putSodException(realm.value, target.rule_id, target.user_id, {
      covered_roles: target.roles,
      justification: excuseDraft.value.justification.trim(),
      valid_until: excuseDraft.value.valid_until.trim(),
    });
    excusing.value = null;
  } catch {
    // The toast already said.
  }
}
async function withdrawExcuse(ruleId: string, userId: string) {
  try {
    await deleteSodException(realm.value, ruleId, userId);
  } catch {
    // The toast already said.
  }
}

function untilShort(spelled: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(spelled),
  );
}

const requests = ref<AccessRequest[]>([]);
const makingRequest = ref(false);
const requestDraft = ref({ user_id: "", role_id: "", reason: "", expires_at: "" });
const denying = ref("");
const denialWords = ref("");

async function loadRequests() {
  try {
    requests.value = await listRequests(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(loadRequests);
afterWrites(loadRequests);

async function makeRequest() {
  const held = requestDraft.value;
  if (!held.user_id.trim() || !held.role_id.trim() || !held.reason.trim()) return;
  try {
    await lodgeRequest(realm.value, {
      user_id: held.user_id.trim(),
      role_id: held.role_id.trim(),
      reason: held.reason.trim(),
      expires_at: held.expires_at.trim() || undefined,
    });
    makingRequest.value = false;
    requestDraft.value = { user_id: "", role_id: "", reason: "", expires_at: "" };
  } catch {
    // The toast already said.
  }
}
async function approve(requestId: string) {
  try {
    await approveRequest(realm.value, requestId);
  } catch {
    // The toast already said.
  }
}
async function deny(requestId: string) {
  if (!denialWords.value.trim()) return;
  try {
    await denyRequest(realm.value, requestId, denialWords.value.trim());
    denying.value = "";
    denialWords.value = "";
  } catch {
    // The toast already said.
  }
}
async function withdraw(requestId: string) {
  try {
    await withdrawRequest(realm.value, requestId);
  } catch {
    // The toast already said.
  }
}
</script>

<template>
  <div>
    <GovernanceTabs />
    <h1 class="text-lg font-semibold tracking-tight">{{ say("iga-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ say("iga-lede") }}</p>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("iga-rules") }}
      <button
        type="button"
        class="ml-3 rounded-md bg-accent px-2.5 py-1 text-[11px] font-semibold text-accent-ink normal-case tracking-normal hover:bg-accent-strong"
        @click="making = !making"
      >
        {{ say("rule-new") }}
      </button>
      <button
        type="button"
        class="ml-2 rounded-md border border-border px-2.5 py-1 text-[11px] font-medium text-muted normal-case tracking-normal hover:bg-surface-2"
        @click="converge"
      >
        {{ say("rule-converge") }} <AppHint name="rule-converge-help" />
      </button>
    </h2>

    <form
      v-if="making"
      class="mt-3 flex max-w-3xl flex-col gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeRule"
    >
      <div class="flex items-center gap-3">
        <label class="flex items-center gap-1.5 text-[11px]">
          <input v-model="ruleDraft.mode" type="radio" value="attribute" class="accent-(--sf-accent)" />
          {{ say("rule-mode-attribute") }}
        </label>
        <label class="flex items-center gap-1.5 text-[11px]">
          <input v-model="ruleDraft.mode" type="radio" value="expr" class="accent-(--sf-accent)" />
          {{ say("rule-mode-expr") }} <AppHint name="rule-mode-expr-help" />
        </label>
      </div>
      <div v-if="ruleDraft.mode === 'attribute'" class="grid grid-cols-2 gap-3">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("rule-attribute") }}
          <input v-model="ruleDraft.when_attribute" placeholder="department" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("rule-value") }}
          <input v-model="ruleDraft.when_value" placeholder="finance" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
        </label>
      </div>
      <label v-else class="block text-[11px] font-medium text-muted">
        {{ say("rule-expr") }}
        <input v-model="ruleDraft.when_expr" placeholder='department == "finance" && seniority > 2' class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("rule-roles") }} <AppHint name="rule-roles-help" />
        <input v-model="ruleDraft.roles" :placeholder="say('policy-blacklist-hint')" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <div class="flex items-center gap-3">
        <AppToggle v-model="ruleDraft.enabled">{{ say("users-active") }}</AppToggle>
        <button type="submit" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong">
          {{ say("realm-create") }}
        </button>
        <span class="text-[10.5px] text-faint">{{ say("rule-boundary") }}</span>
      </div>
    </form>
    <p v-if="!rules.length" class="mt-2 text-xs text-muted">{{ say("iga-no-rules") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("iga-col-when") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("user-roles") }}</th>
            <th class="px-3 py-2 font-medium"></th>
            <th class="px-3 py-2 font-medium">{{ say("flow-priority") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="rule in rules"
            :key="rule.rule_id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2">
              <code
                class="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px]"
                >{{ condition(rule) }}</code
              >
            </td>
            <td class="px-3 py-2 font-mono text-[10.5px] text-muted">
              {{ rule.roles.length }}
            </td>
            <td class="px-3 py-2 font-mono text-[10.5px]">{{ rule.priority }}</td>
            <td class="px-3 py-2 text-[10.5px]">
              {{ rule.enabled ? say("users-active") : say("users-disabled") }}
            </td>
            <td class="px-3 py-2">
              <span class="flex justify-end gap-1.5">
                <button
                  type="button"
                  class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2"
                  @click="flipRule(rule)"
                >
                  {{ rule.enabled ? say("rule-pause") : say("rule-enable") }}
                </button>
                <button
                  type="button"
                  class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
                  @click="dropRule(rule.rule_id)"
                >
                  {{ say("action-remove") }}
                </button>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("iga-ledger") }}
    </h2>
    <form class="mt-2 flex max-w-3xl items-end gap-2 text-xs" @submit.prevent="giveGrant">
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("authz-subject") }}
        <input
          v-model="grantDraft.user_id"
          placeholder="ada"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("iga-grant-role") }}
        <input
          v-model="grantDraft.role_id"
          placeholder="role-..."
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="w-52 text-[11px] font-medium text-muted">
        {{ say("iga-grant-until") }} <AppHint name="iga-grant-until-help" />
        <input
          v-model="grantDraft.expires_at"
          placeholder="2026-12-31T00:00:00Z"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink"
          spellcheck="false"
        />
      </label>
      <button
        type="submit"
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
      >
        {{ say("iga-grant-give") }}
      </button>
    </form>
    <form class="mt-2 flex max-w-md items-end gap-2" @submit.prevent="consult">
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("authz-subject") }}
        <input
          v-model="askedUser"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <button
        type="submit"
        class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface-2"
      >
        {{ say("iga-consult") }}
      </button>
    </form>
    <p v-if="ledger && !ledger.length" class="mt-2 text-xs text-muted">
      {{ say("iga-no-grants") }}
    </p>
    <div v-if="ledger?.length" class="mt-2 grid max-w-2xl gap-2">
      <div
        v-for="grant in ledger"
        :key="grant.role_id"
        class="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-xs"
      >
        <span class="font-mono text-[11px]">{{ grant.role_id }}</span>
        <span
          class="rounded border px-1.5 py-0.5 text-[10px]"
          :class="grant.rule_id ? 'border-info/40 text-info' : 'border-border text-muted'"
        >
          {{ grant.rule_id ? say("iga-rule-born") : say("iga-hand-given") }}
        </span>
        <span v-if="grant.expires_at" class="ml-auto font-mono text-[10px] text-warn">
          {{ say("iga-until") }} {{ until(grant) }}
        </span>
        <button
          v-if="!grant.rule_id"
          type="button"
          class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
          :class="!grant.expires_at && 'ml-auto'"
          @click="takeGrant(grant.role_id)"
        >
          {{ say("action-remove") }}
        </button>
      </div>
    </div>

    <h2 class="mt-8 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("sod-section") }}
      <button
        type="button"
        class="ml-3 rounded-md bg-accent px-2.5 py-1 text-[11px] font-semibold text-accent-ink normal-case tracking-normal hover:bg-accent-strong"
        @click="makingSod = !makingSod"
      >
        {{ say("sod-new") }}
      </button>
    </h2>
    <p class="mt-1 text-xs text-muted">{{ say("sod-lede") }}</p>

    <form
      v-if="makingSod"
      class="mt-3 flex max-w-3xl items-end gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeSodRule"
    >
      <label class="w-40 text-[11px] font-medium text-muted">
        {{ say("sod-rule-name") }}
        <input v-model="sodDraft.rule_id" placeholder="payments" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("sod-roles") }}
        <input v-model="sodDraft.roles" placeholder="payer, approver" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="w-32 text-[11px] font-medium text-muted">
        {{ say("sod-threshold") }} <AppHint name="sod-threshold-help" />
        <input v-model="sodDraft.min_conflicting" placeholder="2" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <button type="submit" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong">
        {{ say("realm-create") }}
      </button>
    </form>

    <p v-if="!sodRules.length" class="mt-2 text-xs text-muted">{{ say("sod-no-rules") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("sod-rule-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("sod-roles") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("sod-threshold") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-state") }}</th>
            <th class="px-3 py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="rule in sodRules" :key="rule.rule_id" class="border-b border-border/60 last:border-0">
            <td class="px-3 py-2 font-mono text-[10.5px]">{{ rule.rule_id }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px] text-muted">{{ rule.roles.join(", ") }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px]">{{ rule.min_conflicting }}</td>
            <td class="px-3 py-2 text-[10.5px]">
              {{ rule.enabled ? say("users-active") : say("users-disabled") }}
            </td>
            <td class="px-3 py-2">
              <span class="flex justify-end gap-1.5">
                <button type="button" class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2" @click="flipSodRule(rule)">
                  {{ rule.enabled ? say("rule-pause") : say("rule-enable") }}
                </button>
                <button type="button" class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2" @click="dropSodRule(rule.rule_id)">
                  {{ say("action-remove") }}
                </button>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <template v-if="sodRules.length">
      <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("sod-violations") }}
      </h2>
      <p v-if="!sodViolations.length" class="mt-2 text-xs text-muted">
        {{ say("sod-no-violations") }}
      </p>
      <div v-else class="mt-2 grid max-w-3xl gap-2">
        <div
          v-for="violation in sodViolations"
          :key="violation.user_id + violation.rule_id"
          class="rounded-lg border border-border bg-surface px-3 py-2 text-xs"
        >
          <div class="flex items-center gap-2">
            <span class="font-mono text-[11px]">{{ violation.user_name }}</span>
            <span class="text-muted">{{ violation.rule_id }}</span>
            <span class="font-mono text-[10.5px] text-muted">{{ violation.roles.join(", ") }}</span>
            <span
              class="ml-auto rounded border px-1.5 py-0.5 text-[10px]"
              :class="violation.excused ? 'border-border text-muted' : 'border-warn/40 text-warn'"
            >
              {{ violation.excused ? say("sod-excused") : say("sod-standing") }}
            </span>
            <button
              v-if="!violation.excused"
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2"
              @click="openExcuse(violation)"
            >
              {{ say("sod-excuse") }}
            </button>
          </div>
          <form
            v-if="excusing?.user_id === violation.user_id && excusing?.rule_id === violation.rule_id"
            class="mt-2 flex items-end gap-2 border-t border-border/60 pt-2"
            @submit.prevent="giveExcuse"
          >
            <label class="flex-1 text-[11px] font-medium text-muted">
              {{ say("sod-justification") }}
              <input v-model="excuseDraft.justification" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink" />
            </label>
            <label class="w-52 text-[11px] font-medium text-muted">
              {{ say("sod-valid-until") }}
              <input v-model="excuseDraft.valid_until" placeholder="2026-12-31T00:00:00Z" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink" spellcheck="false" />
            </label>
            <button type="submit" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong">
              {{ say("sod-excuse") }}
            </button>
          </form>
        </div>
      </div>

      <template v-if="sodExceptions.length">
        <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("sod-exceptions") }}
        </h2>
        <div class="mt-2 grid max-w-3xl gap-2">
          <div
            v-for="exception in sodExceptions"
            :key="exception.rule_id + exception.user_id"
            class="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-xs"
          >
            <span class="font-mono text-[11px]">{{ exception.user_id }}</span>
            <span class="text-muted">{{ exception.rule_id }}</span>
            <span class="font-mono text-[10.5px] text-muted">
              {{ say("sod-covers") }} {{ exception.covered_roles.join(", ") }}
            </span>
            <span class="ml-auto font-mono text-[10px] text-warn">
              {{ say("iga-until") }} {{ untilShort(exception.valid_until) }}
            </span>
            <button
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
              @click="withdrawExcuse(exception.rule_id, exception.user_id)"
            >
              {{ say("sod-withdraw") }}
            </button>
          </div>
        </div>
      </template>
    </template>

    <h2 class="mt-8 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("req-section") }}
      <button
        type="button"
        class="ml-3 rounded-md bg-accent px-2.5 py-1 text-[11px] font-semibold text-accent-ink normal-case tracking-normal hover:bg-accent-strong"
        @click="makingRequest = !makingRequest"
      >
        {{ say("req-new") }}
      </button>
    </h2>
    <p class="mt-1 text-xs text-muted">{{ say("req-lede") }}</p>

    <form
      v-if="makingRequest"
      class="mt-3 flex max-w-4xl items-end gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeRequest"
    >
      <label class="w-36 text-[11px] font-medium text-muted">
        {{ say("authz-subject") }}
        <input v-model="requestDraft.user_id" placeholder="ada" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="w-36 text-[11px] font-medium text-muted">
        {{ say("iga-grant-role") }}
        <input v-model="requestDraft.role_id" placeholder="role-..." class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("req-reason") }}
        <input v-model="requestDraft.reason" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink" />
      </label>
      <label class="w-48 text-[11px] font-medium text-muted">
        {{ say("iga-grant-until") }} <AppHint name="iga-grant-until-help" />
        <input v-model="requestDraft.expires_at" placeholder="2026-12-31T00:00:00Z" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[10.5px] text-ink" spellcheck="false" />
      </label>
      <button type="submit" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong">
        {{ say("realm-create") }}
      </button>
    </form>

    <p v-if="!requests.length" class="mt-2 text-xs text-muted">{{ say("req-no-requests") }}</p>
    <div v-else class="mt-2 grid max-w-4xl gap-2">
      <div
        v-for="request in requests"
        :key="request.request_id"
        class="rounded-lg border border-border bg-surface px-3 py-2 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="font-mono text-[11px]">{{ request.user_id }}</span>
          <span class="font-mono text-[10.5px] text-muted">{{ request.role_id }}</span>
          <span class="text-[10.5px] text-muted">{{ request.reason }}</span>
          <span
            class="ml-auto rounded border px-1.5 py-0.5 text-[10px]"
            :class="{
              'border-warn/40 text-warn': request.state === 'pending',
              'border-ok/40 text-ok': request.state === 'granted',
              'border-danger/40 text-danger': request.state === 'denied',
              'border-border text-muted': request.state === 'withdrawn',
            }"
          >
            {{ say(`req-state-${request.state}`) }}
          </span>
          <template v-if="request.state === 'pending'">
            <button type="button" class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2" @click="approve(request.request_id)">
              {{ say("req-approve") }}
            </button>
            <button type="button" class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2" @click="denying = denying === request.request_id ? '' : request.request_id">
              {{ say("req-deny") }}
            </button>
            <button type="button" class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-muted hover:bg-surface-2" @click="withdraw(request.request_id)">
              {{ say("req-withdraw") }}
            </button>
          </template>
        </div>
        <p class="mt-1 text-[10px] text-faint">
          {{ say("req-asked-by") }} {{ request.asked_by }}<template v-if="request.decided_by">
            · {{ say("req-decided-by") }} {{ request.decided_by }}</template
          ><template v-if="request.decided_reason"> · {{ request.decided_reason }}</template
          ><template v-if="request.expires_at"> · {{ say("iga-until") }} {{ untilShort(request.expires_at) }}</template>
        </p>
        <form
          v-if="denying === request.request_id"
          class="mt-2 flex items-end gap-2 border-t border-border/60 pt-2"
          @submit.prevent="deny(request.request_id)"
        >
          <label class="flex-1 text-[11px] font-medium text-muted">
            {{ say("req-deny-reason") }}
            <input v-model="denialWords" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink" />
          </label>
          <button type="submit" class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2">
            {{ say("req-deny") }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>
