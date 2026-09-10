<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { listFlows } from "@/services/flows";
import { getRealmSettings, reshapeRealm } from "@/services/settings";
import { afterWrites } from "@/services/writes";
import type { FlowRow } from "@/models/flows";

const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const flows = ref<FlowRow[]>([]);
const failed = ref("");

/// The realm's browser binding: which top-level flow answers /authorize for
/// clients binding none. Empty is the built default, the alias "browser".
const browserFlow = ref("");

async function load() {
  try {
    flows.value = await listFlows(realm.value);
    browserFlow.value = (await getRealmSettings(realm.value)).browser_flow ?? "";
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

const topLevel = computed(() => flows.value.filter((flow) => flow.top_level));

async function bindBrowser() {
  failed.value = "";
  try {
    await reshapeRealm(
      realm.value,
      { browser_flow: browserFlow.value },
      say("flows-binding-subject"),
    );
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function open(flow: FlowRow) {
  router.push(`/${realm.value}/authentication/${flow.flow_id}`);
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("flows-title") }}</h1>
      <router-link
        :to="`/${realm}/authentication/actions`"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-xs text-muted hover:bg-surface-2"
      >
        {{ say("actions-title") }}
      </router-link>
      <span v-if="flows.length" class="font-mono text-[11px] text-faint">{{ flows.length }}</span>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("flows-lede") }}</p>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <form
      class="mt-4 flex max-w-xl flex-wrap items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5"
      @submit.prevent="bindBrowser"
    >
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("flows-binding") }} <AppHint name="flows-binding-help" />
        <select
          v-model="browserFlow"
          class="sf-field mt-1 font-mono"
        >
          <option value="">{{ say("flows-binding-default") }}</option>
          <option v-for="flow in topLevel" :key="flow.flow_id" :value="flow.alias">
            {{ flow.alias }}
          </option>
        </select>
      </label>
      <button
        type="submit"
        class="sf-button sf-button-primary"
      >
        {{ say("settings-save") }}
      </button>
    </form>
    <p class="mt-2 max-w-xl text-[10.5px] text-faint">{{ say("flows-hooks-note") }}</p>

    <div class="sf-list mt-4 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
            <th>{{ say("flows-col-alias") }}</th>
            <th>{{ say("scopes-col-description") }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="flow in flows"
            :key="flow.flow_id"
            class="cursor-pointer hover:bg-surface-2"
            @click="open(flow)"
          >
            <td class="font-mono text-[11.5px]">{{ flow.alias }}</td>
            <td class="text-muted">{{ flow.description }}</td>
            <td>
              <span class="flex justify-end gap-1.5">
                <span
                  v-if="flow.top_level"
                  class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted"
                  >{{ say("flows-top-level") }}</span
                >
                <span
                  v-if="flow.built_in"
                  class="rounded border border-accent/40 px-1.5 py-0.5 text-[10px] text-accent"
                  >{{ say("flows-built-in") }}</span
                >
                <span
                  v-if="flow.alias === browserFlow"
                  class="rounded border border-ok/40 px-1.5 py-0.5 text-[10px] text-ok"
                  >{{ say("flows-signs-browser") }}</span
                >
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
