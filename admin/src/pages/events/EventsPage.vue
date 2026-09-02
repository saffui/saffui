<script setup lang="ts">
// Security-event receivers and outbound connectors are provider rows wearing
// a kind; this page reads them apart from the sign-in brokers.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { kindOf, listIdps } from "@/services/federation";
import type { IdpRow } from "@/models/federation";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const idps = ref<IdpRow[]>([]);
const failed = ref("");

onMounted(async () => {
  try {
    idps.value = await listIdps(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

const receivers = computed(() => idps.value.filter((row) => kindOf(row).startsWith("caep")));
const connectors = computed(() => idps.value.filter((row) => kindOf(row) === "scim-outbound"));

function bagText(row: IdpRow, key: string): string {
  const held = row.configs?.[key];
  if (held === undefined) return "";
  if (typeof held === "string") return held;
  return held.Str ?? "";
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("events-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ say("events-lede") }}</p>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("events-receivers") }}
    </h2>
    <p v-if="!receivers.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-receivers") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in receivers"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="font-medium">{{ row.display_name || row.name }}</span>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
            {{ bagText(row, "delivery") || "push" }}
          </span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">
          {{ bagText(row, "endpoint") || bagText(row, "audience") }}
        </div>
      </div>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("events-connectors") }}
    </h2>
    <p v-if="!connectors.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-connectors") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in connectors"
        :key="row.internal_id"
        class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <span class="font-medium">{{ row.display_name || row.name }}</span>
        <span class="font-mono text-[10.5px] text-faint">{{ bagText(row, "base_url") }}</span>
        <span
          class="ml-auto text-[10.5px]"
          :class="row.enabled === false ? 'text-danger' : 'text-faint'"
        >
          {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
        </span>
      </div>
    </div>
  </div>
</template>
