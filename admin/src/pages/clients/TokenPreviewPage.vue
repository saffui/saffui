<script setup lang="ts">
// What a token would carry, claim by claim with its author. Mints nothing:
// the evaluation is issuance's own, reported instead of signed.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { listClients, previewToken, type PreviewedClaim } from "@/services/clients";
import type { ClientBrief } from "@/models/client";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const clients = ref<ClientBrief[]>([]);
const failed = ref("");
const userId = ref("");
const clientId = ref("");
const scope = ref("openid profile");
const claims = ref<PreviewedClaim[] | null>(null);
const askedScope = ref("");

onMounted(async () => {
  try {
    clients.value = (await listClients(realm.value, 0, 100)).items;
    clientId.value = clients.value[0]?.client_id ?? "";
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function ask() {
  failed.value = "";
  claims.value = null;
  if (!userId.value.trim() || !clientId.value) return;
  try {
    const answered = await previewToken(realm.value, {
      user_id: userId.value.trim(),
      client_id: clientId.value,
      scope: scope.value.trim() || undefined,
    });
    claims.value = answered.claims;
    askedScope.value = answered.scope;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function landsIn(row: PreviewedClaim): string {
  return say(`preview-lands-${row.lands_in}`);
}
function worded(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("preview-title") }}</h1>
    <p class="mt-1 max-w-2xl text-xs text-muted">
      {{ say("preview-lede") }} <AppHint name="preview-lede-help" />
    </p>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <form class="mt-4 flex max-w-3xl items-end gap-2 text-xs" @submit.prevent="ask">
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("signin-col-who") }}
        <input
          v-model="userId"
          placeholder="ada"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("clients-title") }}
        <select
          v-model="clientId"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
        >
          <option v-for="held in clients" :key="held.client_id" :value="held.client_id">
            {{ held.client_id }}
          </option>
        </select>
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("preview-scope") }} <AppHint name="preview-scope-help" />
        <input
          v-model="scope"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <button
        type="submit"
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
      >
        {{ say("preview-ask") }}
      </button>
    </form>

    <p v-if="claims && !claims.length" class="mt-4 text-xs text-muted">
      {{ say("preview-none") }}
    </p>
    <div v-if="claims?.length" class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("preview-col-claim") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("preview-col-value") }}</th>
            <th class="px-3 py-2 font-medium">
              {{ say("preview-col-origin") }} <AppHint name="preview-origin-help" />
            </th>
            <th class="px-3 py-2 font-medium">{{ say("preview-col-lands") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in claims"
            :key="row.claim + row.origin"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2 font-mono text-[11.5px]">{{ row.claim }}</td>
            <td class="max-w-96 px-3 py-2 font-mono text-[10.5px] break-all">
              {{ worded(row.value) }}
            </td>
            <td class="px-3 py-2">
              <span class="rounded border border-info/40 px-1.5 py-0.5 text-[10px] text-info"
                >{{ say("preview-by") }} {{ row.origin }}</span
              >
            </td>
            <td class="px-3 py-2 text-[10.5px] text-muted">{{ landsIn(row) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
