<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { listScopeCatalogue, listScopeMappers } from "@/services/scopes";
import type { ClientScope, ProtocolMapper } from "@/models/client";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const scopes = ref<ClientScope[]>([]);
const failed = ref("");
const unfolded = ref<string | null>(null);
const mappers = ref<Record<string, ProtocolMapper[]>>({});

onMounted(async () => {
  try {
    scopes.value = await listScopeCatalogue(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function unfold(scope: ClientScope) {
  if (unfolded.value === scope.client_scope_id) {
    unfolded.value = null;
    return;
  }
  unfolded.value = scope.client_scope_id;
  if (!mappers.value[scope.client_scope_id]) {
    mappers.value[scope.client_scope_id] = await listScopeMappers(
      realm.value,
      scope.client_scope_id,
    );
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("scopes-title") }}</h1>
      <span v-if="scopes.length" class="font-mono text-[11px] text-faint">{{
        scopes.length
      }}</span>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("scopes-lede") }}</p>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-description") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("scopes-col-default") }}</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="scope in scopes" :key="scope.client_scope_id">
            <tr
              class="cursor-pointer border-b border-border/60 hover:bg-surface-2"
              :class="unfolded === scope.client_scope_id && 'bg-surface-2'"
              @click="unfold(scope)"
            >
              <td class="px-3 py-2 font-mono text-[11.5px]">{{ scope.name }}</td>
              <td class="px-3 py-2 text-muted">{{ scope.description }}</td>
              <td class="px-3 py-2">
                <span v-if="scope.default_scope" class="text-[10.5px] text-accent-strong">{{
                  say("scopes-default")
                }}</span>
              </td>
            </tr>
            <tr v-if="unfolded === scope.client_scope_id" class="border-b border-border/60">
              <td colspan="3" class="bg-bg px-3 py-2.5">
                <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                  {{ say("client-tab-mappers") }}
                </div>
                <p
                  v-if="!(mappers[scope.client_scope_id] ?? []).length"
                  class="mt-1.5 text-xs text-muted"
                >
                  {{ say("mappers-none") }}
                </p>
                <div class="mt-1.5 flex flex-wrap gap-1.5">
                  <span
                    v-for="mapper in mappers[scope.client_scope_id] ?? []"
                    :key="mapper.mapper_id"
                    class="rounded border border-border px-1.5 py-0.5 text-[10.5px]"
                  >
                    {{ mapper.name }}
                    <span class="ml-1 font-mono text-faint">{{ mapper.mapper_type }}</span>
                  </span>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>
