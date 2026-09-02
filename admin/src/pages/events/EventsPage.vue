<script setup lang="ts">
// Security-event receivers and outbound connectors are provider rows wearing
// a kind; this page reads them apart from the sign-in brokers.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppPaging from "@/components/AppPaging.vue";
import { kindOf, listIdps } from "@/services/federation";
import { getRealmSettings, listSignInEvents } from "@/services/settings";
import type { IdpRow } from "@/models/federation";
import type { SignInEvent } from "@/models/events";
import type { Page } from "@/models/paging";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const idps = ref<IdpRow[]>([]);
const failed = ref("");

/// The sign-in log, when the realm switched it on; null says it is off.
const signIns = ref<Page<SignInEvent> | null>(null);
const recording = ref(false);
const first = ref(0);
const size = ref(25);
async function turn() {
  try {
    signIns.value = await listSignInEvents(realm.value, first.value, size.value);
  } catch {
    // The listing simply stays where it was.
  }
}
function resize(asked: number) {
  size.value = asked;
  first.value = 0;
  void turn();
}

onMounted(async () => {
  try {
    idps.value = await listIdps(realm.value);
    recording.value = (await getRealmSettings(realm.value)).events_enabled ?? false;
    if (recording.value) {
      signIns.value = await listSignInEvents(realm.value, first.value, size.value);
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

function instant(epoch: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}

const receivers = computed(() => idps.value.filter((row) => kindOf(row).startsWith("caep")));
const connectors = computed(() => idps.value.filter((row) => kindOf(row) === "scim-outbound"));

function bagText(row: IdpRow, key: string): string {
  const held = row.configs?.[key];
  if (held === undefined) return "";
  if (typeof held === "string") return held;
  return held.Str ?? "";
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("events-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ say("events-lede") }}</p>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("signin-events-title") }}
    </h2>
    <p v-if="!recording" class="mt-1.5 text-xs text-muted">
      {{ say("signin-events-off") }}
      <router-link :to="`/${realm}/settings`" class="text-accent hover:text-accent-strong">{{
        say("signin-events-off-link")
      }}</router-link>
    </p>
    <div
      v-else-if="signIns"
      class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface"
    >
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("signin-col-kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-who") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-client") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-from") }}</th>
            <th class="px-3 py-2 text-right font-medium">{{ say("journal-col-when") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="held in signIns.items"
            :key="held.id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2">
              <span
                class="rounded border px-1.5 py-0.5 font-mono text-[10.5px]"
                :class="
                  held.kind === 'sign_in_failed'
                    ? 'border-danger/40 text-danger'
                    : 'border-border text-muted'
                "
                >{{ held.kind }}</span
              >
            </td>
            <td class="px-3 py-2 font-mono text-[11px]">{{ held.user_id || "·" }}</td>
            <td class="px-3 py-2 font-mono text-[11px]">{{ held.client_id || "·" }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px] text-faint">{{ held.ip || "·" }}</td>
            <td class="px-3 py-2 text-right font-mono text-[10.5px] text-faint">
              {{ instant(held.recorded_at) }}
            </td>
          </tr>
          <tr v-if="!signIns.items.length">
            <td colspan="5" class="px-3 py-3 text-muted">{{ say("signin-events-none") }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPaging
      v-if="signIns"
      :first="first"
      :count="signIns.items.length"
      :size="size"
      @update:first="(held) => { first = held; void turn(); }"
      @update:size="resize"
    />

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("events-receivers") }}
    </h2>
    <p v-if="!receivers.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-receivers") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in receivers"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="font-medium">{{ row.display_name || row.name }}</span>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
            {{ bagText(row, "delivery") || "push" }}
          </span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">
          {{ bagText(row, "endpoint") || bagText(row, "audience") }}
        </div>
      </div>
    </div>

    <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("events-connectors") }}
    </h2>
    <p v-if="!connectors.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-connectors") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in connectors"
        :key="row.internal_id"
        class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <span class="font-medium">{{ row.display_name || row.name }}</span>
        <span class="font-mono text-[10.5px] text-faint">{{ bagText(row, "base_url") }}</span>
        <span
          class="ml-auto text-[10.5px]"
          :class="row.enabled === false ? 'text-danger' : 'text-faint'"
        >
          {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
        </span>
      </div>
    </div>
  </div>
</template>
