<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import { getClient, listAttachedScopes, listClientMappers } from "@/services/clients";
import type { ClientBrief, ClientScope, ProtocolMapper } from "@/models/client";

const props = defineProps<{ realm: string; clientId: string }>();
const emit = defineEmits<{ close: [] }>();

const TABS = ["overview", "scopes", "mappers"] as const;
const tab = ref<(typeof TABS)[number]>("overview");

const client = ref<ClientBrief | null>(null);
const scopes = ref<ClientScope[]>([]);
const mappers = ref<ProtocolMapper[]>([]);
const failed = ref("");

async function load() {
  failed.value = "";
  try {
    [client.value, scopes.value, mappers.value] = await Promise.all([
      getClient(props.realm, props.clientId),
      listAttachedScopes(props.realm, props.clientId),
      listClientMappers(props.realm, props.clientId),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

// Required is granted without being asked for; offered waits to be asked.
const required = computed(() => scopes.value.filter((held) => !held.optional));
const offered = computed(() => scopes.value.filter((held) => held.optional));
</script>

<template>
  <AppDrawer
    :title="client?.name || props.clientId"
    :subtitle="props.clientId"
    @close="emit('close')"
  >
    <p v-if="failed" class="text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="flex gap-1 border-b border-border pb-2">
      <button
        v-for="held in TABS"
        :key="held"
        type="button"
        class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
        :class="tab === held && 'bg-surface-2 font-medium text-ink'"
        @click="tab = held"
      >
        {{ say(`client-tab-${held}`) }}
      </button>
    </div>

    <div v-if="tab === 'overview' && client" class="mt-4 flex flex-col gap-4">
      <dl class="grid grid-cols-[140px_1fr] gap-y-2 text-xs">
        <dt class="text-muted">{{ say("clients-col-kind") }}</dt>
        <dd>{{ client.confidential ? say("clients-confidential") : say("clients-public") }}</dd>
        <dt class="text-muted">{{ say("users-col-state") }}</dt>
        <dd>{{ client.enabled ? say("users-active") : say("users-disabled") }}</dd>
      </dl>
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-redirects") }}
        </div>
        <p v-if="!client.redirect_uris.length" class="mt-1.5 text-xs text-muted">
          {{ say("client-no-redirects") }}
        </p>
        <ul class="mt-1.5 flex flex-col gap-1">
          <li
            v-for="uri in client.redirect_uris"
            :key="uri"
            class="rounded border border-border bg-surface-2 px-2 py-1 font-mono text-[10.5px]"
          >
            {{ uri }}
          </li>
        </ul>
      </div>
      <div v-if="client.post_logout_redirect_uris.length">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-post-logout") }}
        </div>
        <ul class="mt-1.5 flex flex-col gap-1">
          <li
            v-for="uri in client.post_logout_redirect_uris"
            :key="uri"
            class="rounded border border-border bg-surface-2 px-2 py-1 font-mono text-[10.5px]"
          >
            {{ uri }}
          </li>
        </ul>
      </div>
    </div>

    <div v-if="tab === 'scopes'" class="mt-4 flex flex-col gap-5">
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-scopes-required") }}
        </div>
        <p v-if="!required.length" class="mt-1.5 text-xs text-muted">
          {{ say("client-scopes-none") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="scope in required"
            :key="scope.client_scope_id"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]"
            :title="scope.description"
            >{{ scope.name }}</span
          >
        </div>
      </div>
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-scopes-offered") }}
        </div>
        <p v-if="!offered.length" class="mt-1.5 text-xs text-muted">
          {{ say("client-scopes-none") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="scope in offered"
            :key="scope.client_scope_id"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted"
            :title="scope.description"
            >{{ scope.name }}</span
          >
        </div>
      </div>
    </div>

    <div v-if="tab === 'mappers'" class="mt-4">
      <p v-if="!mappers.length" class="text-xs text-muted">{{ say("mappers-none") }}</p>
      <div v-else class="overflow-x-auto rounded-lg border border-border">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-border text-[11px] text-muted">
              <th class="px-3 py-2 font-medium">{{ say("mappers-col-name") }}</th>
              <th class="px-3 py-2 font-medium">{{ say("mappers-col-type") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="mapper in mappers"
              :key="mapper.mapper_id"
              class="border-b border-border/60 last:border-0"
            >
              <td class="px-3 py-2">{{ mapper.name }}</td>
              <td class="px-3 py-2 font-mono text-[10.5px] text-muted">
                {{ mapper.mapper_type }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </AppDrawer>
</template>
