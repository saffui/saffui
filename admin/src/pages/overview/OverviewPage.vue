<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import { readOverview, type OverviewTold } from "@/services/overview";

const route = useRoute();
const told = ref<OverviewTold | null>(null);
const failed = ref("");

onMounted(async () => {
  try {
    told.value = await readOverview(String(route.params.realm));
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

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
  { name: "organizations", title: () => say("overview-organizations"), icon: "directory" },
  { name: "signingKeys", title: () => say("overview-keys"), icon: "key" },
] as const;
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

    <section v-if="told && told.attention.length" class="mt-6">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("overview-attention") }}
      </h2>
      <div class="mt-2 flex flex-col gap-2">
        <router-link
          v-for="held in told.attention"
          :key="held.what"
          :to="`/${route.params.realm}/${held.where}`"
          class="group flex items-center gap-3 rounded-lg border border-warn/40 bg-surface px-4 py-3 hover:bg-surface-2"
        >
          <span class="size-1.5 shrink-0 rounded-full bg-warn"></span>
          <span class="text-xs text-ink">{{ say(`attention-${held.what}`) }}</span>
          <span class="ml-auto flex items-center gap-1 text-[11px] text-muted group-hover:text-ink">
            {{ say("overview-fix") }}
            <AppIcon name="chevron" :size="12" />
          </span>
        </router-link>
      </div>
    </section>

    <p v-if="told && !told.attention.length" class="mt-6 text-xs text-muted">
      {{ say("overview-quiet") }}
    </p>

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
          <span
            class="size-1.5 rounded-full"
            :class="told.chain.holds ? 'bg-ok' : 'bg-danger'"
          ></span>
          {{
            told.chain.holds
              ? say("overview-chain-holds", { count: told.chain.entries })
              : say("overview-chain-broken", { seq: told.chain.broken_at ?? 0 })
          }}
        </span>
      </div>
      <div class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
        <table class="w-full text-left text-xs">
          <tbody>
            <tr
              v-for="held in told.journal"
              :key="held.seq"
              class="border-b border-border/60 last:border-0"
            >
              <td class="px-3 py-2 font-mono text-[10.5px] text-faint">#{{ held.seq }}</td>
              <td class="px-3 py-2">{{ held.entry.actor }}</td>
              <td class="px-3 py-2 font-mono text-[10.5px]">
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
    </section>
  </div>
</template>
