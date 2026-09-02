<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { listIgaGrants, listIgaRules } from "@/services/federation";
import {
  convergeRules,
  createRule,
  deleteRule,
  handGrant,
  revokeGrant,
  updateRule,
} from "@/services/governance";
import AppHint from "@/components/AppHint.vue";
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

onMounted(async () => {
  try {
    rules.value = await listIgaRules(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

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
</script>

<template>
  <div>
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
  </div>
</template>
