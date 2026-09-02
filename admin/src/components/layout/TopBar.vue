<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import { useSession } from "@/stores/session";

const session = useSession();
const router = useRouter();
const dark = ref(document.documentElement.classList.contains("dark"));

function flipTheme() {
  dark.value = !dark.value;
  document.documentElement.classList.toggle("dark", dark.value);
  localStorage.setItem("sf-console-theme", dark.value ? "dark" : "light");
}

function signOut() {
  session.signOut();
  router.push("/login");
}

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase() || "?";
}
</script>

<template>
  <header
    class="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-surface px-4"
  >
    <div
      class="flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs"
    >
      <span class="text-faint">{{ say("topbar-realm") }}</span>
      <span class="font-mono text-[11.5px] font-medium">{{ session.realm || "main" }}</span>
      <AppIcon name="chevron" :size="11" class="rotate-90 text-faint" />
    </div>
    <button
      type="button"
      class="flex min-w-56 items-center gap-2 rounded-md border border-border px-2 py-1 text-xs text-faint hover:bg-surface-2"
    >
      <AppIcon name="search" :size="13" />
      <span>{{ say("topbar-search") }}</span>
      <kbd
        class="ml-auto rounded border border-border bg-surface-2 px-1 font-mono text-[10px]"
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
  </header>
</template>
