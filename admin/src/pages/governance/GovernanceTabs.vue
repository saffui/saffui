<script setup lang="ts">
// One sidebar entry serves both registers; these tabs tell them apart.
import { computed } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const leaf = computed(() => String(route.path.split("/").pop()));
</script>

<template>
  <div class="mb-4 flex gap-1 border-b border-border pb-2">
    <router-link
      :to="`/${realm}/governance`"
      class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
      :class="leaf === 'governance' && 'bg-surface-2 font-medium text-ink'"
    >
      {{ say("nav-governance") }}
    </router-link>
    <router-link
      :to="`/${realm}/privacy`"
      class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
      :class="leaf === 'privacy' && 'bg-surface-2 font-medium text-ink'"
    >
      {{ say("nav-privacy") }}
    </router-link>
  </div>
</template>
