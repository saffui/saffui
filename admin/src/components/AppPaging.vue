<script setup lang="ts">
// The one paging foot every listing shares: previous, next, the visible
// range, and how many rows a page holds. No total: the server only counts
// when asked, and the next button already knows a short page is the last.
//
// It sits inside the list rather than under it, which is where the deck puts
// it: a 34 band on the quiet surface, closing the frame the rows opened.
import { say } from "@/i18n";

defineProps<{ first: number; count: number; size: number }>();
const emit = defineEmits<{ "update:first": [held: number]; "update:size": [held: number] }>();

const SIZES = [10, 25, 50, 100] as const;
</script>

<template>
  <div
    class="flex min-h-10 flex-wrap items-center gap-2 border-t border-border bg-surface-2 px-3 py-1.5 text-xs text-muted"
  >
    <button
      type="button"
      class="sf-button sf-button-secondary h-7 min-h-7 px-2.5 disabled:opacity-40"
      :disabled="first === 0"
      @click="emit('update:first', Math.max(0, first - size))"
    >
      {{ say("paging-previous") }}
    </button>
    <button
      type="button"
      class="sf-button sf-button-secondary h-7 min-h-7 px-2.5 disabled:opacity-40"
      :disabled="count < size"
      @click="emit('update:first', first + size)"
    >
      {{ say("paging-next") }}
    </button>
    <span class="font-mono">{{ count ? first + 1 : 0 }}&ndash;{{ first + count }}</span>
    <label class="ml-auto inline-flex items-center gap-1.5">
      {{ say("paging-size") }}
      <select
        :value="size"
        class="sf-field h-7 min-h-7 w-auto py-0 pr-7 pl-2 text-xs"
        @change="emit('update:size', Number(($event.target as HTMLSelectElement).value))"
      >
        <option v-for="held in SIZES" :key="held" :value="held">{{ held }}</option>
      </select>
    </label>
  </div>
</template>
