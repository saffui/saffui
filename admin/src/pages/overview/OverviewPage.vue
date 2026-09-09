<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import { readOverview, type OverviewTold } from "@/services/overview";
import { afterWrites } from "@/services/writes";
import { useStanding } from "@/stores/standing";

const route = useRoute();
const standing = useStanding();
const told = ref<OverviewTold | null>(null);
const failed = ref("");

async function load() {
  const realm = String(route.params.realm);
  try {
    // The status bar has already asked, or is asking; either way this waits
    // on that one reading rather than paying for a second.
    await standing.read(realm, true);
    if (!standing.held || !standing.settings) throw new Error(say("overview-unread"));
    told.value = await readOverview(realm, {
      strip: standing.held,
      settings: standing.settings,
    });
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

function shown(count: number | null | undefined): string {
  if (count === null || count === undefined) return "··";
  return new Intl.NumberFormat().format(count);
}

function instant(epoch: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}

const CARDS = [
  { name: "users", title: () => say("overview-users"), icon: "users" },
  { name: "clients", title: () => say("overview-clients"), icon: "clients" },
  { name: "sessions", title: () => say("overview-sessions"), icon: "sessions" },
  { name: "pendingRequests", title: () => say("overview-pending"), icon: "governance" },
] as const;

const BADGE = {
  unset: "",
  incomplete: "sf-badge-danger",
  set: "sf-badge-ok",
} as const;

function needs(held: string[]): string {
  return held.map((named) => say(`gateway-needs-${named}`)).join(", ");
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("overview-title") }}</h1>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 grid grid-cols-2 gap-3 xl:grid-cols-4">
      <div
        v-for="card in CARDS"
        :key="card.name"
        class="rounded-lg border border-border bg-surface p-4"
      >
        <div class="flex items-center gap-2 text-[11px] font-medium text-muted">
          <AppIcon :name="card.icon" :size="13" class="text-faint" />
          {{ card.title() }}
        </div>
        <div class="mt-2 font-mono text-2xl tabular-nums" :class="told ? 'text-ink' : 'text-faint'">
          {{ shown(told?.numbers[card.name]) }}
        </div>
      </div>
    </div>

    <div class="mt-6 flex flex-col gap-4 xl:flex-row">
      <div class="min-w-0 flex-1">
    <section v-if="told && told.journal.length" class="mt-6">
      <div class="flex items-center gap-2">
        <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("overview-journal") }}
        </h2>
        <span
          v-if="told.chain"
          class="inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10.5px]"
          :class="told.chain.holds ? 'border-ok/40 text-ok' : 'border-danger/40 text-danger'"
        >
          {{
            told.chain.holds
              ? say("overview-chain-holds", { count: told.chain.entries })
              : say("overview-chain-broken", { seq: told.chain.broken_at ?? 0 })
          }}
        </span>
      </div>
      <div class="sf-list mt-2 overflow-x-auto">
        <table class="sf-table">
          <tbody>
            <tr
              v-for="held in told.journal"
              :key="held.seq"
              class="border-b border-border/60 last:border-0"
            >
              <td class="font-mono text-[10.5px] text-faint">#{{ held.seq }}</td>
              <td>{{ held.entry.actor }}</td>
              <td class="font-mono text-[10.5px]">
                {{ held.entry.method }} {{ held.entry.path || held.entry.pattern }}
              </td>
              <td>
                <span
                  class="font-mono text-[10.5px]"
                  :class="held.entry.status < 400 ? 'text-ok' : 'text-danger'"
                  >{{ held.entry.status }}</span
                >
              </td>
              <td class="text-right font-mono text-[10.5px] text-faint">
                {{ instant(held.recorded_at) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
      </div>

      <div class="flex w-full shrink-0 flex-col gap-4 xl:w-[360px]">
        <section class="rounded-lg border border-border bg-surface">
          <h2 class="px-4 pt-3 pb-2 text-[13px] text-ink">{{ say("overview-gateways") }}</h2>
          <div
            v-for="held in told?.gateways ?? []"
            :key="held.which"
            class="flex items-center gap-3 border-t border-border px-4 py-3"
          >
            <span class="flex min-w-0 flex-1 flex-col gap-0.5">
              <span class="flex items-center gap-1.5 text-[12.5px] text-ink">
                {{ say(`gateway-${held.which}`) }}
                <span v-if="held.clear_text" class="sf-badge sf-badge-warn">{{
                  say("gateway-clear-text")
                }}</span>
              </span>
              <span
                v-if="held.at || held.state === 'unset'"
                class="truncate font-mono text-[11px] text-faint"
                >{{ held.at ?? say("gateway-nowhere") }}</span
              >
              <span
                v-if="held.needed_by.length"
                class="truncate text-[11px]"
                :class="held.state === 'set' ? 'text-faint' : 'text-danger'"
                >{{ say("gateway-needed-by", { held: needs(held.needed_by) }) }}</span
              >
            </span>
            <span class="sf-badge shrink-0" :class="BADGE[held.state]">{{
              say(`gateway-${held.state}`)
            }}</span>
          </div>
        </section>

        <section class="rounded-lg border border-border bg-surface">
          <h2 class="flex items-center gap-2 px-4 pt-3 pb-2 text-[13px] text-ink">
            {{ say("overview-attention") }}
            <span v-if="told?.attention.length" class="sf-badge sf-badge-warn">{{
              told.attention.length
            }}</span>
          </h2>
          <p v-if="told && !told.attention.length" class="px-4 pb-3 text-[11.5px] text-muted">
            {{ say("overview-quiet") }}
          </p>
          <router-link
            v-for="held in told?.attention ?? []"
            :key="held.what"
            :to="`/${route.params.realm}/${held.where}`"
            class="flex items-center gap-2.5 border-t border-border px-4 py-2.5 hover:bg-neutral-tint"
          >
            <AppIcon name="danger" :size="14" class="shrink-0 text-warn" />
            <span class="min-w-0 flex-1 text-[11.5px] text-muted">{{
              say(`attention-${held.what}`)
            }}</span>
            <span class="shrink-0 text-[11px] text-accent">{{ say("overview-fix") }}</span>
          </router-link>
        </section>
      </div>
    </div>
  </div>
</template>
