<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { listIgaGrants, listIgaRules } from "@/services/federation";
import type { IgaGrant, IgaRule } from "@/models/federation";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const rules = ref<IgaRule[]>([]);
const failed = ref("");
const askedUser = ref("");
const ledger = ref<IgaGrant[] | null>(null);

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
    </h2>
    <p v-if="!rules.length" class="mt-2 text-xs text-muted">{{ say("iga-no-rules") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("iga-col-when") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("user-roles") }}</th>
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
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("iga-ledger") }}
    </h2>
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
      </div>
    </div>
  </div>
</template>
