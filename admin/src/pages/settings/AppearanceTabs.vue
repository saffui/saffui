<script setup lang="ts">
// The bar over the screens that decide how a realm looks. Only those: the
// message templates live in settings because they are wording, not looks, and
// a console's own theme has nowhere to be stored yet, so it is not offered
// here as a tab that leads nowhere.
import { computed } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";

defineProps<{ current: "theme" | "login" }>();

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const tabs = computed(
  () =>
    [
      { key: "theme", to: `/${realm.value}/theme` },
      { key: "login", to: `/${realm.value}/pages` },
    ] as const,
);
</script>

<template>
  <nav
    class="flex h-8 min-w-0 items-center gap-0.5 overflow-x-auto border-b border-border"
    aria-label="Appearance"
  >
    <RouterLink
      v-for="tab in tabs"
      :key="tab.key"
      :to="tab.to"
      class="flex h-8 shrink-0 items-center whitespace-nowrap border-b-2 px-3 text-[13px]"
      :class="current === tab.key ? 'border-accent text-ink' : 'border-transparent text-muted hover:text-ink'"
    >
      {{ say(`appearance-tab-${tab.key}`) }}
    </RouterLink>
  </nav>
</template>
