<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import AppPaging from "@/components/AppPaging.vue";
import { endRealmSessions, listRealmSessions } from "@/services/sessions";
import { getRealmSettings, reshapeRealm } from "@/services/settings";
import type { RealmSessionBrief } from "@/models/session";

const route = useRoute();
const realm = computed(() => String(route.params.realm));

const sessions = ref<RealmSessionBrief[]>([]);
const first = ref(0);
const size = ref(25);
const failed = ref("");

/// The realm's own cut, as an instant. Read back after every write so the
/// screen shows what the door will read rather than what was just typed.
const cutAt = ref<number | null>(null);
/// Typed to arm each of the two dangerous buttons, which name different
/// things: ending logins is not the same act as refusing tokens.
const doomEndAll = ref("");
const doomCut = ref("");

async function loadSessions() {
  failed.value = "";
  try {
    const page = await listRealmSessions(realm.value, first.value, size.value);
    sessions.value = page.items;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function loadCut() {
  try {
    const held = await getRealmSettings(realm.value);
    cutAt.value = held.not_before ?? null;
  } catch {
    // The toast already said; the listing still stands on its own.
  }
}

watch([realm, first, size], loadSessions, { immediate: true });
watch(realm, loadCut, { immediate: true });

async function endEveryLogin() {
  try {
    await endRealmSessions(realm.value);
    doomEndAll.value = "";
    first.value = 0;
    await loadSessions();
  } catch {
    // The toast already said.
  }
}

async function refuseEveryTokenMintedSoFar() {
  try {
    await reshapeRealm(
      realm.value,
      { not_before: Math.floor(Date.now() / 1000) },
      say("subject-realm-cut", { realm: realm.value }),
    );
    doomCut.value = "";
    await loadCut();
  } catch {
    // The toast already said.
  }
}

async function liftTheCut() {
  try {
    await reshapeRealm(realm.value, { not_before: 0 }, say("subject-realm-cut", { realm: realm.value }));
    await loadCut();
  } catch {
    // The toast already said.
  }
}

function instant(epoch: number | null | undefined): string {
  if (!epoch) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("realm-sessions-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ say("realm-sessions-lede") }}</p>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("realm-sessions-open") }}
    </h2>
    <p v-if="!sessions.length" class="mt-2 text-xs text-muted">{{ say("realm-sessions-none") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("realm-sessions-col-who") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("realm-sessions-col-where") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("realm-sessions-col-how") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("user-session-started") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="held in sessions"
            :key="held.session_id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2">
              <div class="font-medium">{{ held.login_username }}</div>
              <div class="mt-0.5 font-mono text-[10.5px] text-faint">{{ held.user_id }}</div>
            </td>
            <td class="px-3 py-2">
              <span v-if="held.ip_address" class="font-mono text-[10.5px]">{{
                held.ip_address
              }}</span>
              <div class="mt-0.5 text-[10.5px] text-faint">
                {{ [held.browser, held.system].filter(Boolean).join(" · ") }}
              </div>
            </td>
            <td class="px-3 py-2">{{ held.auth_method || say("user-session-unknown") }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px]">{{ instant(held.started_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPaging
      v-model:first="first"
      v-model:size="size"
      :count="sessions.length"
    />

    <div class="mt-6 rounded-lg border border-danger/40 p-3">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
        {{ say("realm-sessions-danger") }} <AppHint name="realm-sessions-danger-help" />
      </div>

      <p class="mt-2 text-[11px] text-muted">{{ say("realm-sessions-end-lede") }}</p>
      <div class="mt-2 flex items-center gap-2">
        <input
          v-model="doomEndAll"
          :placeholder="realm"
          class="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
        <button
          type="button"
          class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
          :disabled="doomEndAll !== realm"
          @click="endEveryLogin"
        >
          {{ say("realm-sessions-end") }}
        </button>
      </div>

      <p class="mt-4 text-[11px] text-muted">{{ say("realm-cut-lede") }}</p>
      <p v-if="cutAt" class="mt-1 text-[11px]">
        {{ say("realm-cut-standing") }} <span class="font-mono">{{ instant(cutAt) }}</span>
        <button
          type="button"
          class="ml-2 rounded-md border border-border px-2 py-1 text-[11px] hover:bg-surface-2"
          @click="liftTheCut"
        >
          {{ say("realm-cut-lift") }}
        </button>
      </p>
      <div class="mt-2 flex items-center gap-2">
        <input
          v-model="doomCut"
          :placeholder="realm"
          class="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
          spellcheck="false"
        />
        <button
          type="button"
          class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
          :disabled="doomCut !== realm"
          @click="refuseEveryTokenMintedSoFar"
        >
          {{ say("realm-cut-strike") }}
        </button>
      </div>
    </div>
  </div>
</template>
