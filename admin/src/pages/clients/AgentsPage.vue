<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import {
  listAgents,
  registerAgent,
  reshapeAgent,
  type AgentBrief,
} from "@/services/clients";
import { afterWrites } from "@/services/writes";
import {
  agentDraft,
  agentDraftIsWritable,
  agentRegistration,
  agentReshape,
  emptyAgentDraft,
  type AgentDraft,
} from "./agentForms";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const agents = ref<AgentBrief[]>([]);
const failed = ref("");
const opened = ref(false);
const editing = ref<AgentBrief | null>(null);
const draft = ref<AgentDraft>(emptyAgentDraft());
const saving = ref(false);

async function load() {
  try {
    agents.value = await listAgents(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

function openCreate() {
  editing.value = null;
  draft.value = emptyAgentDraft();
  opened.value = true;
}

function openEdit(agent: AgentBrief) {
  editing.value = agent;
  draft.value = agentDraft(agent);
  opened.value = true;
}

async function save() {
  if (!agentDraftIsWritable(draft.value)) return;
  saving.value = true;
  failed.value = "";
  try {
    if (editing.value) await reshapeAgent(realm.value, editing.value.client_id, agentReshape(editing.value, draft.value));
    else await registerAgent(realm.value, agentRegistration(draft.value));
    opened.value = false;
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("agents-title") }}</h1>
        <p class="mt-1 text-xs text-muted">{{ say("agents-lede") }}</p>
      </div>
      <button type="button" class="sf-button sf-button-secondary" @click="openCreate">
        {{ say("agents-new") }}
      </button>
    </div>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>
    <p v-if="!agents.length" class="mt-5 text-xs text-muted">{{ say("agents-none") }}</p>
    <div v-else class="sf-list mt-5 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
            <th>{{ say("agents-col-client") }}</th>
            <th>{{ say("agents-col-capabilities") }}</th>
            <th>{{ say("agents-col-session") }}</th>
            <th>{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="agent in agents"
            :key="agent.client_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            @click="openEdit(agent)"
          >
            <td class="font-mono text-[11.5px]">{{ agent.client_id }}</td>
            <td>
              <span class="line-clamp-2 text-[11px] text-muted">{{ agent.capabilities.join(" · ") }}</span>
            </td>
            <td class="font-mono text-[11px]">{{ agent.session_seconds ?? say("agents-session-default") }}</td>
            <td>
              <span :class="agent.enabled ? 'text-ok' : 'text-danger'">
                {{ agent.enabled ? say("users-active") : say("users-disabled") }}
              </span>
              <span class="ml-2 text-[10px] text-faint">{{ agent.keyed ? say("agents-keyed") : say("agents-platform") }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <AppDrawer
      v-if="opened"
      :title="editing?.client_id ?? say('agents-new')"
      subtitle="agent"
      @close="opened = false"
    >
      <form class="flex flex-col gap-4 text-xs" @submit.prevent="save">
        <label class="text-[11px] font-medium text-muted">
          {{ say("agents-client-id") }}
          <input v-model="draft.clientId" :disabled="Boolean(editing)" required class="sf-field mt-1 font-mono disabled:opacity-60" />
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("agents-capabilities") }}
          <textarea v-model="draft.capabilities" rows="5" required class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[11px] text-ink" />
          <span class="mt-1 block font-normal text-faint">{{ say("agents-capabilities-help") }}</span>
        </label>
        <label class="text-[11px] font-medium text-muted">
          {{ say("agents-session") }}
          <input v-model.number="draft.sessionSeconds" type="number" min="1" max="86400" class="sf-field mt-1 font-mono" />
          <span class="mt-1 block font-normal text-faint">{{ say("agents-session-help") }}</span>
        </label>
        <p v-if="editing" class="text-[11px] text-muted">
          {{ say("agents-platform-note") }} <AppHint name="agents-platform-help" />
        </p>
        <p v-if="!agentDraftIsWritable(draft)" class="text-[11px] text-warn" role="alert">
          {{ say("agents-invalid") }}
        </p>
        <button type="submit" :disabled="saving || !agentDraftIsWritable(draft)" class="self-start sf-button sf-button-primary">
          {{ say("settings-save") }}
        </button>
      </form>
    </AppDrawer>
  </div>
</template>
