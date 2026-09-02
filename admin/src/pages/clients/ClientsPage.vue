<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import { listClients } from "@/services/clients";
import type { Page } from "@/models/paging";
import type { ClientBrief } from "@/models/client";
import ClientDrawer from "./ClientDrawer.vue";

const PAGE_SIZE = 25;
const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const first = ref(0);
const page = ref<Page<ClientBrief> | null>(null);
const failed = ref("");

const opened = computed(() => {
  const asked = route.query.client;
  return typeof asked === "string" && asked !== "" ? asked : null;
});

async function load() {
  failed.value = "";
  try {
    page.value = await listClients(realm.value, first.value, PAGE_SIZE);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
watch(first, load);

function open(client: ClientBrief) {
  router.replace({ query: { ...route.query, client: client.client_id } });
}
function close() {
  const { client: _, ...rest } = route.query;
  router.replace({ query: rest });
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("clients-title") }}</h1>
      <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
        page.total
      }}</span>
    </div>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("clients-col-id") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("clients-col-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("clients-col-kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="client in page.items"
            :key="client.client_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            :class="opened === client.client_id && 'bg-surface-2'"
            @click="open(client)"
          >
            <td class="px-3 py-2 font-mono text-[11.5px]">{{ client.client_id }}</td>
            <td class="px-3 py-2">{{ client.name }}</td>
            <td class="px-3 py-2">
              <span class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-muted">
                {{ client.confidential ? say("clients-confidential") : say("clients-public") }}
              </span>
            </td>
            <td class="px-3 py-2">
              <span v-if="client.enabled" class="text-[10.5px] text-faint">{{
                say("users-active")
              }}</span>
              <span
                v-else
                class="rounded border border-danger/40 px-1.5 py-0.5 text-[10.5px] text-danger"
                >{{ say("users-disabled") }}</span
              >
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="page" class="mt-3 flex items-center gap-2 text-[11px] text-muted">
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
        :disabled="first === 0"
        @click="first = Math.max(0, first - PAGE_SIZE)"
      >
        {{ say("paging-previous") }}
      </button>
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
        :disabled="page.items.length < PAGE_SIZE"
        @click="first = first + PAGE_SIZE"
      >
        {{ say("paging-next") }}
      </button>
    </div>

    <ClientDrawer v-if="opened" :realm="realm" :client-id="opened" @close="close" />
  </div>
</template>
