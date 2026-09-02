<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { kindOf, listDirectories, listIdps } from "@/services/federation";
import type { DirectoryRow, IdpRow } from "@/models/federation";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const idps = ref<IdpRow[]>([]);
const directories = ref<DirectoryRow[]>([]);
const failed = ref("");

onMounted(async () => {
  try {
    [idps.value, directories.value] = await Promise.all([
      listIdps(realm.value),
      listDirectories(realm.value),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

// Event receivers and outbound connectors live on the events page; here
// stay the providers people sign in through.
const brokers = computed(() =>
  idps.value.filter((row) => {
    const kind = kindOf(row);
    return !kind.startsWith("caep") && kind !== "scim-outbound";
  }),
);
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("federation-title") }}</h1>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("federation-idps") }}
    </h2>
    <p v-if="!brokers.length" class="mt-2 text-xs text-muted">{{ say("federation-no-idps") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("clients-col-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("federation-col-alias") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("federation-col-trust") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in brokers"
            :key="row.internal_id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2">{{ row.display_name || row.name }}</td>
            <td class="px-3 py-2 font-mono text-[11.5px]">{{ row.provider_id }}</td>
            <td class="px-3 py-2">
              <span
                v-if="row.trust_email"
                class="inline-flex items-center gap-1.5 text-[10.5px] text-ok"
              >
                <span class="size-1.5 rounded-full bg-ok"></span>
                {{ say("federation-trusted") }}
              </span>
            </td>
            <td class="px-3 py-2 text-[10.5px]">
              {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("federation-directories") }}
    </h2>
    <p v-if="!directories.length" class="mt-2 text-xs text-muted">
      {{ say("federation-no-directories") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in directories"
        :key="row.alias"
        class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <span class="font-mono text-[11.5px]">{{ row.alias }}</span>
        <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">
          {{ say("federation-priority") }} {{ row.priority }}
        </span>
        <span class="ml-auto text-[10.5px]" :class="row.enabled === false ? 'text-danger' : 'text-faint'">
          {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
        </span>
      </div>
    </div>
  </div>
</template>
