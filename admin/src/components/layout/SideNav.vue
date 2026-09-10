<script setup lang="ts">
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import RealmSelector from "./RealmSelector.vue";
import { say } from "@/i18n";

defineProps<{ open: boolean }>();
const emit = defineEmits<{ close: [] }>();

const route = useRoute();
const realm = () => String(route.params.realm ?? "main");

// The domain map of the whole console. Entries without a page yet still
// belong on the map: they route to overview until their slice lands.
// The deck's four captions and its order. Every leaf the console serves is
// placed in the group the deck implies rather than dropped: the boards fold
// several of them into tabs on a neighbour, and none of those hosts exists
// yet, so folding now would leave pages reachable only by typing a URL.
const GROUPS: { label: string; items: { label: string; icon: any; leaf: string }[] }[] = [
  {
    label: say("nav-cap-manage"),
    items: [
      { label: say("nav-overview"), icon: "overview", leaf: "overview" },
      { label: say("nav-users"), icon: "users", leaf: "users" },
      { label: say("nav-roles"), icon: "roles", leaf: "roles" },
      { label: say("nav-groups"), icon: "groups", leaf: "groups" },
      { label: say("nav-organizations"), icon: "organizations", leaf: "organizations" },
      { label: say("nav-clients"), icon: "clients", leaf: "clients" },
      { label: say("nav-scopes"), icon: "scopes", leaf: "client-scopes" },
    ],
  },
  {
    label: say("nav-cap-configure"),
    items: [
      { label: say("nav-authentication"), icon: "authentication", leaf: "authentication" },
      { label: say("nav-authorization"), icon: "authorization", leaf: "authorization" },
      { label: say("nav-evaluator"), icon: "evaluator", leaf: "evaluator" },
      { label: say("nav-federation"), icon: "federation", leaf: "federation" },
      { label: say("nav-appearance"), icon: "appearance", leaf: "theme" },
      { label: say("nav-pages"), icon: "pages", leaf: "pages" },
      { label: say("nav-settings"), icon: "settings", leaf: "settings" },
    ],
  },
  {
    label: say("nav-cap-operate"),
    items: [
      { label: say("nav-events"), icon: "events", leaf: "events" },
      { label: say("nav-journal"), icon: "journal", leaf: "journal" },
      { label: say("nav-keys"), icon: "key", leaf: "keys" },
      { label: say("nav-governance"), icon: "governance", leaf: "governance" },
      { label: say("nav-realm-sessions"), icon: "sessions", leaf: "sessions" },
    ],
  },
  {
    label: say("nav-cap-tools"),
    items: [{ label: say("nav-preview"), icon: "preview", leaf: "token-preview" }],
  },
];

function target(leaf: string): string {
  return `/${realm()}/${leaf}`;
}
function active(leaf: string): boolean {
  return route.path === target(leaf);
}
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-40 bg-black/30 md:hidden"
    aria-hidden="true"
    @click="emit('close')"
  ></div>
  <nav
    class="fixed inset-y-0 left-0 z-50 flex w-rail shrink-0 -translate-x-full flex-col border-r border-border bg-surface transition-transform duration-200 md:relative md:z-auto md:translate-x-0"
    :class="open && 'translate-x-0'"
  >
    <div class="flex h-[52px] shrink-0 items-center gap-2.5 px-3">
      <div
        class="grid size-6 shrink-0 place-items-center rounded bg-accent-tint text-[13px] font-semibold text-accent"
      >
        S
      </div>
      <span class="text-[13.5px] text-ink">{{ say("console-name") }}</span>
    </div>

    <RealmSelector />

    <div class="min-h-0 flex-1 overflow-y-auto py-2">
      <div v-for="(group, at) in GROUPS" :key="at" class="mb-2">
        <div
          v-if="group.label"
          class="px-3 pt-2.5 pb-1 text-[10px] font-semibold tracking-[0.09em] text-faint uppercase"
        >
          {{ group.label }}
        </div>
        <router-link
          v-for="item in group.items"
          :key="item.leaf"
          :to="target(item.leaf)"
          class="group flex h-[31px] items-center gap-2.5 pr-3 hover:bg-neutral-tint"
          :class="active(item.leaf) && 'bg-accent-tint'"
          @click="emit('close')"
        >
          <span
            class="h-[29px] w-0.5 shrink-0"
            :class="active(item.leaf) ? 'bg-accent' : 'bg-transparent'"
          ></span>
          <AppIcon
            :name="item.icon"
            :size="14"
            :class="active(item.leaf) ? 'text-accent' : 'text-faint'"
          />
          <span
            class="truncate text-[13.5px]"
            :class="active(item.leaf) ? 'font-medium text-ink' : 'text-muted'"
            >{{ item.label }}</span
          >
        </router-link>
      </div>
    </div>

    <div class="flex h-[34px] shrink-0 items-center gap-1.5 px-3">
      <AppIcon name="server" :size="13" class="shrink-0 text-ok" />
      <span class="truncate text-[11.5px] text-faint">{{ say("console-footprint") }}</span>
    </div>
  </nav>
</template>
