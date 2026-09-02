<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import { useSession } from "@/stores/session";
import { listRealms } from "@/services/realms";
import type { RealmBrief } from "@/models/realm";
import CommandPalette from "./CommandPalette.vue";

const session = useSession();
const route = useRoute();
const router = useRouter();
const dark = ref(document.documentElement.classList.contains("dark"));
const paletteOpen = ref(false);
const realmsOpen = ref(false);
const realms = ref<RealmBrief[]>([]);

const current = computed(() => String(route.params.realm ?? session.realm ?? "main"));

function flipTheme() {
  dark.value = !dark.value;
  document.documentElement.classList.toggle("dark", dark.value);
  localStorage.setItem("sf-console-theme", dark.value ? "dark" : "light");
}

function signOut() {
  session.signOut();
  router.push("/login");
}

async function openRealms() {
  realmsOpen.value = !realmsOpen.value;
  if (realmsOpen.value) {
    try {
      realms.value = await listRealms();
    } catch {
      realms.value = [];
    }
  }
}

function switchTo(realm: RealmBrief) {
  realmsOpen.value = false;
  router.push(`/${realm.name}/overview`);
}

function onAway(event: MouseEvent) {
  if (!(event.target as HTMLElement).closest("[data-realm-menu]")) realmsOpen.value = false;
}
onMounted(() => document.addEventListener("click", onAway));
onUnmounted(() => document.removeEventListener("click", onAway));

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase() || "?";
}
</script>

<template>
  <header class="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
    <div class="relative" data-realm-menu>
      <button
        type="button"
        class="flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs hover:bg-surface-3"
        @click.stop="openRealms"
      >
        <span class="text-faint">{{ say("topbar-realm") }}</span>
        <span class="font-mono text-[11.5px] font-medium">{{ current }}</span>
        <AppIcon name="chevron" :size="11" class="rotate-90 text-faint" />
      </button>
      <div
        v-if="realmsOpen"
        class="absolute top-9 left-0 z-40 w-56 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
      >
        <button
          v-for="realm in realms"
          :key="realm.realm_id"
          type="button"
          class="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-surface-2"
          :class="realm.name === current && 'bg-surface-2 font-medium'"
          @click="switchTo(realm)"
        >
          <span class="font-mono text-[11px]">{{ realm.name }}</span>
          <span class="ml-auto truncate text-[10.5px] text-faint">{{ realm.display_name }}</span>
          <span v-if="!realm.enabled" class="text-[10px] text-danger">{{
            say("users-disabled")
          }}</span>
        </button>
        <p v-if="!realms.length" class="px-2 py-2 text-[11px] text-muted">
          {{ say("palette-nothing") }}
        </p>
      </div>
    </div>

    <button
      type="button"
      class="flex min-w-56 items-center gap-2 rounded-md border border-border px-2 py-1 text-xs text-faint hover:bg-surface-2"
      @click="paletteOpen = true"
    >
      <AppIcon name="search" :size="13" />
      <span>{{ say("topbar-search") }}</span>
      <kbd class="ml-auto rounded border border-border bg-surface-2 px-1 font-mono text-[10px]"
        >&#8984;K</kbd
      >
    </button>

    <div class="ml-auto flex items-center gap-2">
      <button
        type="button"
        class="grid size-7 place-items-center rounded-md text-muted hover:bg-surface-2"
        :aria-label="dark ? 'Light' : 'Dark'"
        @click="flipTheme"
      >
        <AppIcon :name="dark ? 'sun' : 'moon'" :size="14" />
      </button>
      <button
        type="button"
        class="rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2"
        @click="signOut"
      >
        {{ say("action-sign-out") }}
      </button>
      <div
        class="grid size-7 place-items-center rounded-full border border-border bg-surface-2 text-[10.5px] font-semibold"
      >
        {{ initials(session.displayName) }}
      </div>
    </div>

    <CommandPalette v-model="paletteOpen" />
  </header>
</template>
