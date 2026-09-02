<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import { listFlows } from "@/services/flows";
import type { FlowRow } from "@/models/flows";

const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const flows = ref<FlowRow[]>([]);
const failed = ref("");

onMounted(async () => {
  try {
    flows.value = await listFlows(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

function open(flow: FlowRow) {
  router.push(`/${realm.value}/authentication/${flow.flow_id}`);
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("flows-title") }}</h1>
      <span v-if="flows.length" class="font-mono text-[11px] text-faint">{{ flows.length }}</span>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("flows-lede") }}</p>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("flows-col-alias") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-description") }}</th>
            <th class="px-3 py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="flow in flows"
            :key="flow.flow_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            @click="open(flow)"
          >
            <td class="px-3 py-2 font-mono text-[11.5px]">{{ flow.alias }}</td>
            <td class="px-3 py-2 text-muted">{{ flow.description }}</td>
            <td class="px-3 py-2">
              <span class="flex justify-end gap-1.5">
                <span
                  v-if="flow.top_level"
                  class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted"
                  >{{ say("flows-top-level") }}</span
                >
                <span
                  v-if="flow.built_in"
                  class="rounded border border-accent/40 px-1.5 py-0.5 text-[10px] text-accent-strong"
                  >{{ say("flows-built-in") }}</span
                >
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
