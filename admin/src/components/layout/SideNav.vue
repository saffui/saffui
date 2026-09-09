<script setup lang="ts">
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import RealmSelector from "./RealmSelector.vue";
import { say } from "@/i18n";

const route = useRoute();
const realm = () => String(route.params.realm ?? "main");

// The domain map of the whole console. Entries without a page yet still
// belong on the map: they route to overview until their slice lands.
const GROUPS: { label: string; items: { label: string; icon: any; leaf: string }[] }[] = [
  {
    label: "",
    items: [{ label: say("nav-overview"), icon: "overview", leaf: "overview" }],
  },
  {
    label: say("nav-directory"),
    items: [
      { label: say("nav-users"), icon: "users", leaf: "users" },
      { label: say("nav-roles"), icon: "roles", leaf: "roles" },
      { label: say("nav-groups"), icon: "directory", leaf: "groups" },
      { label: say("nav-organizations"), icon: "directory", leaf: "organizations" },
    ],
  },
  {
    label: say("nav-clients"),
    items: [
      { label: say("nav-clients"), icon: "clients", leaf: "clients" },
      { label: say("nav-scopes"), icon: "scopes", leaf: "client-scopes" },
      { label: say("nav-preview"), icon: "key", leaf: "token-preview" },
    ],
  },
  {
    label: "",
    items: [
      { label: say("nav-authentication"), icon: "authentication", leaf: "authentication" },
      { label: say("nav-authorization"), icon: "authorization", leaf: "authorization" },
      { label: say("nav-evaluator"), icon: "authorization", leaf: "evaluator" },
      { label: say("nav-federation"), icon: "federation", leaf: "federation" },
      { label: say("nav-governance"), icon: "governance", leaf: "governance" },
      { label: say("nav-events"), icon: "events", leaf: "events" },
      { label: say("nav-journal"), icon: "directory", leaf: "journal" },
    ],
  },
  {
    label: say("nav-settings"),
    items: [
      { label: say("nav-settings"), icon: "settings", leaf: "settings" },
      { label: say("nav-keys"), icon: "key", leaf: "keys" },
      { label: say("nav-realm-sessions"), icon: "users", leaf: "sessions" },
      { label: say("nav-theme"), icon: "scopes", leaf: "theme" },
      { label: say("nav-pages"), icon: "events", leaf: "pages" },
    ],
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
  <nav class="flex w-[210px] shrink-0 flex-col border-r border-border bg-surface">
    <div class="flex h-[52px] shrink-0 items-center gap-2.5 px-3">
      <div
        class="grid size-6 shrink-0 place-items-center rounded bg-accent-tint text-[13px] font-semibold text-accent"
      >
        S
      </div>
      <span class="text-[12.5px] text-ink">{{ say("console-name") }}</span>
    </div>

    <RealmSelector />

    <div class="min-h-0 flex-1 overflow-y-auto py-2">
      <div v-for="(group, at) in GROUPS" :key="at">
        <div
          v-if="group.label"
          class="px-3 pt-2.5 pb-1 text-[9px] font-semibold tracking-[0.09em] text-faint uppercase"
        >
          {{ group.label }}
        </div>
        <router-link
          v-for="item in group.items"
          :key="item.leaf"
          :to="target(item.leaf)"
          class="flex h-[29px] items-center gap-2.5 pr-3 hover:bg-neutral-tint"
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
            class="truncate text-[12.5px]"
            :class="active(item.leaf) ? 'text-ink' : 'text-muted'"
            >{{ item.label }}</span
          >
        </router-link>
      </div>
    </div>

    <div class="flex h-[34px] shrink-0 items-center gap-1.5 px-3">
      <span class="size-[7px] shrink-0 rounded-full bg-ok"></span>
      <span class="truncate text-[10.5px] text-faint">{{ say("console-footprint") }}</span>
    </div>
  </nav>
</template>
