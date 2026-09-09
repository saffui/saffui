<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { offeredTongues, pinTongue, say, tongueInForce } from "@/i18n";
import { useSession } from "@/stores/session";
import CommandPalette from "./CommandPalette.vue";

const session = useSession();
const route = useRoute();
const router = useRouter();
const dark = ref(document.documentElement.classList.contains("dark"));
const paletteOpen = ref(false);
const profileOpen = ref(false);
const tongues = offeredTongues();
const tongue = tongueInForce();

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

/// Where the reader is, said from the route rather than kept in step by
/// hand: the section, then the record when one is open.
const trail = computed(() => {
  const named = route.matched.at(-1)?.name;
  const leaf = typeof named === "string" ? named : String(route.path.split("/")[2] ?? "");
  const held = [say(`nav-${leaf}`)];
  const record = route.params.id ?? route.params.user ?? route.params.client;
  if (typeof record === "string" && record) held.push(record);
  return held;
});

function onAway(event: MouseEvent) {
  const target = event.target as HTMLElement;
  if (!target.closest("[data-profile-menu]")) profileOpen.value = false;
}
onMounted(() => document.addEventListener("click", onAway));
onUnmounted(() => document.removeEventListener("click", onAway));

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase() || "?";
}
</script>

<template>
  <header
    class="flex h-[46px] shrink-0 items-center gap-[18px] border-b border-border bg-surface px-[18px]"
  >
    <div class="flex min-w-0 flex-1 items-center gap-1.5 text-[12px]">
      <span class="shrink-0 text-faint">{{ current }}</span>
      <span v-for="crumb in trail" :key="crumb" class="flex items-center gap-1.5">
        <span class="text-faint">/</span>
        <span class="truncate text-ink">{{ crumb }}</span>
      </span>
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

    <div class="relative ml-auto flex items-center gap-2" data-profile-menu>
      <button
        type="button"
        class="grid size-7 place-items-center rounded-full border border-border bg-surface-2 text-[10.5px] font-semibold hover:border-accent/50"
        :aria-label="say('profile-open')"
        @click.stop="profileOpen = !profileOpen"
      >
        {{ initials(session.displayName) }}
      </button>

      <div
        v-if="profileOpen"
        class="absolute top-9 right-0 z-40 w-60 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
      >
        <div class="px-2.5 pt-2 pb-1.5">
          <p class="text-xs font-semibold">{{ session.displayName }}</p>
          <p class="font-mono text-[10.5px] text-faint">{{ say("profile-realm") }} {{ current }}</p>
        </div>
        <div class="my-1 border-t border-border"></div>
        <div class="flex items-center gap-1 px-2.5 py-1.5 text-[11px] text-muted">
          {{ say("profile-tongue") }}
          <span class="ml-auto flex gap-1">
            <button
              v-for="held in tongues"
              :key="held"
              type="button"
              class="rounded border px-1.5 py-0.5 font-mono text-[10.5px]"
              :class="
                held === tongue
                  ? 'border-accent/60 text-accent'
                  : 'border-border text-muted hover:text-ink'
              "
              @click="pinTongue(held)"
            >
              {{ held }}
            </button>
          </span>
        </div>
        <button
          type="button"
          class="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left text-xs hover:bg-surface-2"
          @click="flipTheme"
        >
          <AppIcon :name="dark ? 'sun' : 'moon'" :size="13" class="text-faint" />
          {{ dark ? say("profile-light") : say("profile-dark") }}
        </button>
        <div class="my-1 border-t border-border"></div>
        <button
          type="button"
          class="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left text-xs text-danger hover:bg-surface-2"
          @click="signOut"
        >
          {{ say("action-sign-out") }}
        </button>
      </div>
    </div>

    <CommandPalette v-model="paletteOpen" />
  </header>
</template>
