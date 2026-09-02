<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import { createClient, listClients } from "@/services/clients";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
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

/// The two-step birth: identity and the one choice that matters, then the
/// addresses; a confidential client's secret is answered exactly once.
const making = ref(false);
const step = ref(1);
const draft = ref({
  client_id: "",
  name: "",
  confidential: false,
  redirects: "",
  logouts: "",
});
const bornSecret = ref("");
function openMaking() {
  making.value = true;
  step.value = 1;
  bornSecret.value = "";
  draft.value = { client_id: "", name: "", confidential: false, redirects: "", logouts: "" };
}
function lines(held: string): string[] {
  return held
    .split(/\n/)
    .map((row) => row.trim())
    .filter(Boolean);
}
async function makeClient() {
  const asked = draft.value;
  if (!asked.client_id.trim()) return;
  try {
    const made = await createClient(realm.value, {
      client_id: asked.client_id.trim(),
      name: asked.name.trim() || asked.client_id.trim(),
      confidential: asked.confidential,
      redirect_uris: lines(asked.redirects),
      post_logout_redirect_uris: lines(asked.logouts),
    });
    await load();
    if (made.client_secret) {
      bornSecret.value = made.client_secret;
      step.value = 3;
    } else {
      making.value = false;
      router.replace({ query: { ...route.query, client: asked.client_id.trim() } });
    }
  } catch {
    // The toast already said.
  }
}
async function copyBornSecret() {
  try {
    await navigator.clipboard.writeText(bornSecret.value);
  } catch {
    // Selectable by hand.
  }
}
function finishMaking() {
  const id = draft.value.client_id.trim();
  making.value = false;
  bornSecret.value = "";
  router.replace({ query: { ...route.query, client: id } });
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("clients-title") }}</h1>
      <div class="flex items-center gap-3">
        <span v-if="page?.total != null" class="font-mono text-[11px] text-faint">{{
          page.total
        }}</span>
        <button
          type="button"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          @click="openMaking"
        >
          {{ say("client-new") }}
        </button>
      </div>
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

    <AppDrawer
      v-if="making"
      :title="say('client-new')"
      :subtitle="realm"
      @close="making = false"
    >
      <form v-if="step === 1" class="flex flex-col gap-3 text-xs" @submit.prevent="step = 2">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-id") }} <AppHint name="client-id-help" />
          <input
            v-model="draft.client_id"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("directory-col-display") }}
          <input
            v-model="draft.name"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-kind") }} <AppHint name="client-kind-help" />
        </div>
        <label class="flex items-start gap-2 rounded-lg border p-2.5"
          :class="!draft.confidential ? 'border-accent/60' : 'border-border'">
          <input v-model="draft.confidential" type="radio" :value="false" class="mt-0.5 accent-(--sf-accent)" />
          <span>
            <span class="block font-medium">{{ say("client-kind-public") }}</span>
            <span class="block text-[10.5px] text-muted">{{ say("client-kind-public-lede") }}</span>
          </span>
        </label>
        <label class="flex items-start gap-2 rounded-lg border p-2.5"
          :class="draft.confidential ? 'border-accent/60' : 'border-border'">
          <input v-model="draft.confidential" type="radio" :value="true" class="mt-0.5 accent-(--sf-accent)" />
          <span>
            <span class="block font-medium">{{ say("client-kind-confidential") }}</span>
            <span class="block text-[10.5px] text-muted">{{ say("client-kind-confidential-lede") }}</span>
          </span>
        </label>
        <div>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
            :disabled="!draft.client_id.trim()"
          >
            {{ say("client-next") }}
          </button>
        </div>
      </form>

      <form v-else-if="step === 2" class="flex flex-col gap-3 text-xs" @submit.prevent="makeClient">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-redirects") }} <AppHint name="client-redirects-help" />
          <textarea
            v-model="draft.redirects"
            rows="3"
            :placeholder="say('policy-blacklist-hint')"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          ></textarea>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("client-logouts") }} <AppHint name="client-logouts-help" />
          <textarea
            v-model="draft.logouts"
            rows="2"
            :placeholder="say('policy-blacklist-hint')"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          ></textarea>
        </label>
        <p v-if="draft.confidential" class="text-[10.5px] text-warn">
          {{ say("client-secret-coming") }}
        </p>
        <div class="flex gap-2">
          <button
            type="button"
            class="rounded-md border border-border px-3 py-1.5 text-xs text-muted hover:bg-surface-2"
            @click="step = 1"
          >
            {{ say("client-back") }}
          </button>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("realm-create") }}
          </button>
        </div>
      </form>

      <div v-else class="flex flex-col gap-3 text-xs">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("client-secret-title") }}
        </div>
        <div class="flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2">
          <code class="min-w-0 flex-1 truncate font-mono text-[11px]">{{ bornSecret }}</code>
          <button
            type="button"
            class="rounded border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-3"
            @click="copyBornSecret"
          >
            {{ say("action-copy") }}
          </button>
        </div>
        <p class="text-[10.5px] text-warn">{{ say("settings-secret-once") }}</p>
        <div>
          <button
            type="button"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
            @click="finishMaking"
          >
            {{ say("client-done") }}
          </button>
        </div>
      </div>
    </AppDrawer>

    <ClientDrawer v-if="opened" :realm="realm" :client-id="opened" @close="close" />
  </div>
</template>
