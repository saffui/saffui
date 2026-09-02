<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppPaging from "@/components/AppPaging.vue";
import { listJournal, verifyChain } from "@/services/journal";
import { getRealmSettings, reshapeRealm } from "@/services/settings";
import AppToggle from "@/components/AppToggle.vue";
import AppHint from "@/components/AppHint.vue";
import { adminPath, api } from "@/services/http";
import type { ChainVerified, JournalPage as Held } from "@/models/journal";


const route = useRoute();
const realm = computed(() => String(route.params.realm));
const first = ref(0);
const size = ref(25);
function resize(asked: number) {
  size.value = asked;
  first.value = 0;
  void load();
}
const page = ref<Held | null>(null);
const chain = ref<ChainVerified | null>(null);
const anchors = ref<{ seq: number; witness: string; receipt: string; anchored_at: number }[]>([]);
const failed = ref("");
const witness = ref("");
const receipt = ref("");

/// Forensic mode: reads land in the chain too. Writes always do.
const readsToo = ref(false);
async function flipReads() {
  const wanted = !readsToo.value;
  try {
    await reshapeRealm(
      realm.value,
      { admin_events_enabled: wanted },
      say("journal-title"),
    );
    readsToo.value = wanted;
  } catch {
    // The toast already said; the switch stays where the server left it.
  }
}

async function load() {
  failed.value = "";
  try {
    readsToo.value = (await getRealmSettings(realm.value)).admin_events_enabled ?? false;
    [page.value, chain.value] = await Promise.all([
      listJournal(realm.value, first.value, size.value),
      verifyChain(realm.value),
    ]);
    const held = await api<{ anchors: typeof anchors.value }>(
      adminPath(realm.value, "journal/anchors"),
    );
    anchors.value = held.anchors;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
watch(first, load);

async function anchor() {
  if (!witness.value.trim() || !receipt.value.trim()) return;
  try {
    await api<unknown>(adminPath(realm.value, "journal/anchors"), {
      method: "POST",
      json: { witness: witness.value.trim(), receipt: receipt.value.trim() },
      subject: say("journal-anchors"),
    });
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
    await load();
    return;
  }
  witness.value = "";
  receipt.value = "";
  await load();
}

function instant(epoch: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}
</script>

<template>
  <div>
    <div class="flex items-center gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("journal-title") }}</h1>
      <span
        v-if="chain"
        class="inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10.5px]"
        :class="chain.holds ? 'border-ok/40 text-ok' : 'border-danger/40 text-danger'"
      >
        {{
          chain.holds
            ? say("overview-chain-holds", { count: chain.entries })
            : say("overview-chain-broken", { seq: chain.broken_at ?? 0 })
        }}
      </span>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("journal-lede") }}</p>
    <div class="mt-2">
      <AppToggle :model-value="readsToo" @update:model-value="flipReads">
        {{ say("journal-reads-too") }} <AppHint name="journal-reads-too-help" />
      </AppToggle>
    </div>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">#</th>
            <th class="px-3 py-2 font-medium">{{ say("journal-col-actor") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("journal-col-what") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("journal-col-status") }}</th>
            <th class="px-3 py-2 text-right font-medium">{{ say("journal-col-when") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="held in page.items"
            :key="held.seq"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2 font-mono text-[10.5px] text-faint">{{ held.seq }}</td>
            <td class="px-3 py-2">{{ held.entry.actor }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px]" :title="held.entry.pattern ?? ''">
              {{ held.entry.method }} {{ held.entry.path || held.entry.pattern }}
            </td>
            <td class="px-3 py-2">
              <span
                class="font-mono text-[10.5px]"
                :class="held.entry.status < 400 ? 'text-ok' : 'text-danger'"
                >{{ held.entry.status }}</span
              >
            </td>
            <td class="px-3 py-2 text-right font-mono text-[10.5px] text-faint">
              {{ instant(held.recorded_at) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPaging
      v-if="page"
      :first="first"
      :count="page.items.length"
      :size="size"
      @update:first="first = $event"
      @update:size="resize"
    />

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("journal-anchors") }}
    </h2>
    <p class="mt-1 text-xs text-muted">{{ say("journal-anchors-lede") }}</p>
    <form class="mt-2 flex max-w-2xl items-end gap-2" @submit.prevent="anchor">
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("journal-witness") }}
        <input
          v-model="witness"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("journal-receipt") }}
        <input
          v-model="receipt"
          class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
      </label>
      <button
        type="submit"
        class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
      >
        {{ say("journal-anchor") }}
      </button>
    </form>
    <div v-if="anchors.length" class="mt-2 grid max-w-2xl gap-1.5">
      <div
        v-for="held in anchors"
        :key="held.seq"
        class="flex items-center gap-2 rounded border border-border bg-surface px-2.5 py-1.5 text-[11px]"
      >
        <span class="font-mono text-[10.5px] text-faint">#{{ held.seq }}</span>
        <span class="font-mono text-[10.5px]">{{ held.witness }}</span>
        <span class="text-muted">{{ held.receipt }}</span>
        <span class="ml-auto font-mono text-[10px] text-faint">{{ instant(held.anchored_at) }}</span>
      </div>
    </div>
  </div>
</template>
