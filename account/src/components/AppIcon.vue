<script setup lang="ts">
import { BadgeCheck, CircleAlert, Info, LogOut, UserRound, type LucideProps } from "lucide-vue-next";
import type { FunctionalComponent } from "vue";

// Pages name icons by role, never by the library's vocabulary, so swapping the
// set later touches this file alone.
const GLYPHS: Record<string, FunctionalComponent<LucideProps>> = {
  profile: UserRound,
  "sign-out": LogOut,
  verified: BadgeCheck,
  unverified: CircleAlert,
  hint: Info,
};

const props = defineProps<{ name: keyof typeof GLYPHS; size?: number }>();
</script>

<template>
  <component
    :is="GLYPHS[props.name]"
    :size="props.size ?? 16"
    :stroke-width="1.75"
    aria-hidden="true"
  />
</template>
