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
    <div class="flex min-w-0 flex-1 items-center gap-1.5 text-[13px]">
      <span class="shrink-0 text-faint">{{ current }}</span>
      <span v-for="crumb in trail" :key="crumb" class="flex items-center gap-1.5">
        <span class="text-faint">/</span>
        <span class="truncate text-ink">{{ crumb }}</span>
      </span>
    </div>

    <button
      type="button"
      class="flex h-7 w-[320px] shrink-0 items-center gap-[7px] rounded bg-surface-2 px-2.5 text-left text-[13px] text-faint hover:bg-surface-3"
      @click="paletteOpen = true"
    >
      <AppIcon name="search" :size="13" />
      <span class="truncate">{{ say("topbar-search") }}</span>
    </button>

    <div class="relative ml-auto flex shrink-0 items-center gap-2.5" data-profile-menu>
      <button
        type="button"
        class="grid size-7 place-items-center rounded text-muted hover:bg-neutral-tint hover:text-ink"
        :aria-label="dark ? say('profile-light') : say('profile-dark')"
        @click="flipTheme"
      >
        <AppIcon :name="dark ? 'sun' : 'moon'" :size="14" />
      </button>
      <button
        type="button"
        class="flex h-7 items-center rounded px-2 text-[12px] text-muted uppercase hover:bg-neutral-tint hover:text-ink"
        :aria-label="say('profile-tongue')"
        @click="pinTongue(tongues.find((held) => held !== tongue) ?? tongue)"
      >
        {{ tongue }}
      </button>
      <button
        type="button"
        class="flex h-[22px] items-center gap-[7px] rounded px-1 text-[13px] text-muted hover:bg-neutral-tint"
        :aria-label="say('profile-open')"
        @click.stop="profileOpen = !profileOpen"
      >
        <span
          class="grid size-[22px] shrink-0 place-items-center rounded-[3px] bg-surface-3 text-[11px] font-semibold text-ink"
          >{{ initials(session.displayName) }}</span
        >
        <span class="max-w-24 truncate">{{ session.displayName }}</span>
        <AppIcon name="chevron" :size="13" class="rotate-90 text-faint" />
      </button>

      <div
        v-if="profileOpen"
        class="absolute top-9 right-0 z-40 w-60 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
      >
        <div class="px-2.5 pt-2 pb-1.5">
          <p class="text-xs font-semibold">{{ session.displayName }}</p>
          <p class="font-mono text-[11.5px] text-faint">{{ say("profile-realm") }} {{ current }}</p>
        </div>
        <div class="my-1 border-t border-border"></div>
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
