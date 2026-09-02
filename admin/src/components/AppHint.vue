<script setup lang="ts">
// The little question mark beside a label. Hover or focus opens a short
// explanation; the name is a Fluent key, so every hint is translated where
// every other string is.
import { ref } from "vue";
import { Info } from "lucide-vue-next";
import { say } from "@/i18n";

const props = defineProps<{ name: string }>();
const open = ref(false);
const text = () => say(props.name);
</script>

<template>
  <span class="relative inline-flex align-middle">
    <button
      type="button"
      class="grid size-4 place-items-center rounded-full text-faint hover:text-muted focus:text-muted focus:outline-none"
      :aria-label="text()"
      tabindex="-1"
      @mouseenter="open = true"
      @mouseleave="open = false"
      @focus="open = true"
      @blur="open = false"
      @click.prevent="open = !open"
    >
      <Info :size="12" :stroke-width="1.6" />
    </button>
    <span
      v-if="open"
      class="absolute bottom-5 left-1/2 z-50 w-56 -translate-x-1/2 rounded-md border border-border bg-surface-3 px-2.5 py-1.5 text-[10.5px] leading-relaxed font-normal text-ink normal-case shadow-(--sf-shadow)"
      role="tooltip"
    >
      {{ text() }}
    </span>
  </span>
</template>
