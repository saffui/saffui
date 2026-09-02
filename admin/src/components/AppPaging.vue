<script setup lang="ts">
// The one paging foot every listing shares: previous, next, the visible
// range, and how many rows a page holds. No total: the server only counts
// when asked, and the next button already knows a short page is the last.
import { say } from "@/i18n";

defineProps<{ first: number; count: number; size: number }>();
const emit = defineEmits<{ "update:first": [held: number]; "update:size": [held: number] }>();

const SIZES = [10, 25, 50, 100] as const;
</script>

<template>
  <div class="mt-3 flex items-center gap-2 text-[11px] text-muted">
    <button
      type="button"
      class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
      :disabled="first === 0"
      @click="emit('update:first', Math.max(0, first - size))"
    >
      {{ say("paging-previous") }}
    </button>
    <button
      type="button"
      class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
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
        class="rounded-md border border-border bg-surface-2 px-1.5 py-1 text-[11px] text-ink"
        @change="emit('update:size', Number(($event.target as HTMLSelectElement).value))"
      >
        <option v-for="held in SIZES" :key="held" :value="held">{{ held }}</option>
      </select>
    </label>
  </div>
</template>
