<script setup lang="ts">
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
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
    ],
  },
  {
    label: "",
    items: [
      { label: say("nav-authentication"), icon: "authentication", leaf: "authentication" },
      { label: say("nav-authorization"), icon: "authorization", leaf: "authorization" },
      { label: say("nav-federation"), icon: "federation", leaf: "federation" },
      { label: say("nav-governance"), icon: "governance", leaf: "governance" },
      { label: say("nav-events"), icon: "events", leaf: "events" },
    ],
  },
  {
    label: say("nav-settings"),
    items: [
      { label: say("nav-settings"), icon: "settings", leaf: "settings" },
      { label: say("nav-keys"), icon: "key", leaf: "keys" },
      { label: say("nav-theme"), icon: "scopes", leaf: "theme" },
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
  <nav class="flex w-60 shrink-0 flex-col border-r border-border bg-surface">
    <div class="flex items-center gap-2.5 px-4 py-3.5">
      <div
        class="grid size-7 place-items-center rounded-md bg-accent font-semibold text-accent-ink"
      >
        S
      </div>
      <span class="text-sm font-semibold tracking-tight">{{ say("console-name") }}</span>
    </div>
    <div class="min-h-0 flex-1 overflow-y-auto px-2 pb-4">
      <div v-for="(group, at) in GROUPS" :key="at" class="mt-3 first:mt-0">
        <div
          v-if="group.label"
          class="px-2 pb-1 text-[10.5px] font-semibold tracking-[0.08em] text-faint uppercase"
        >
          {{ group.label }}
        </div>
        <router-link
          v-for="item in group.items"
          :key="item.leaf"
          :to="target(item.leaf)"
          class="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-muted hover:bg-surface-2 hover:text-ink"
          :class="active(item.leaf) && 'bg-surface-2 font-medium text-ink'"
        >
          <AppIcon :name="item.icon" :size="15" :class="active(item.leaf) && 'text-accent'" />
          <span>{{ item.label }}</span>
        </router-link>
      </div>
    </div>
  </nav>
</template>
