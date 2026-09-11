<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";

defineProps<{ current: "theme" | "email" | "sms" | "login" }>();

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const tabs = computed(() => [
  { key: "theme", to: `/${realm.value}/theme`, enabled: true },
  { key: "email", to: `/${realm.value}/settings?group=email#templates`, enabled: true },
  { key: "sms", to: `/${realm.value}/settings?group=phone#templates`, enabled: true },
  { key: "login", to: `/${realm.value}/pages`, enabled: true },
  { key: "account", to: "", enabled: false },
  { key: "admin", to: "", enabled: false },
] as const);
</script>

<template>
  <nav class="flex h-8 min-w-0 items-center gap-0.5 overflow-x-auto border-b border-border" aria-label="Appearance">
    <template v-for="tab in tabs" :key="tab.key">
      <RouterLink
        v-if="tab.enabled"
        :to="tab.to"
        class="flex h-8 shrink-0 items-center whitespace-nowrap border-b-2 px-3 text-[13px]"
        :class="current === tab.key ? 'border-accent text-ink' : 'border-transparent text-muted hover:text-ink'"
      >
        {{ say(`appearance-tab-${tab.key}`) }}
      </RouterLink>
      <span
        v-else
        class="flex h-8 shrink-0 cursor-not-allowed items-center whitespace-nowrap border-b-2 border-transparent px-3 text-[13px] text-faint opacity-55"
        :title="say('appearance-not-wired')"
      >
        {{ say(`appearance-tab-${tab.key}`) }}
      </span>
    </template>
  </nav>
</template>
