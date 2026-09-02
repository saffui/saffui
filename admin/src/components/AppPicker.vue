<script setup lang="ts">
// The compact picker popover: a filter over rows the caller already holds,
// each row addable unless already held. Filters this list only; the server
// does not search, and a search box that lies is worse than none.
import { computed, ref } from "vue";
import { say } from "@/i18n";

const props = defineProps<{
  rows: { id: string; label: string; held: boolean }[];
  title: string;
}>();
const emit = defineEmits<{ add: [id: string]; close: [] }>();
const typed = ref("");
const shown = computed(() => {
  const needle = typed.value.trim().toLowerCase();
  const rows = needle
    ? props.rows.filter((row) => row.label.toLowerCase().includes(needle))
    : props.rows;
  return rows.slice(0, 8);
});
</script>

<template>
  <div
    class="absolute top-full left-0 z-40 mt-1 w-64 rounded-md border border-border bg-surface p-1.5 shadow-(--sf-shadow)"
  >
    <p class="px-1 pb-1 text-[10.5px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ title }}
    </p>
    <input
      v-model="typed"
      :placeholder="say('picker-filter')"
      class="w-full rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-[11px] text-ink"
      spellcheck="false"
    />
    <div class="mt-1 max-h-48 overflow-y-auto">
      <div
        v-for="row in shown"
        :key="row.id"
        class="flex items-center gap-2 rounded px-1.5 py-1 text-[11.5px]"
        :class="row.held ? 'text-faint' : 'hover:bg-surface-2'"
      >
        <span class="min-w-0 flex-1 truncate font-mono">{{ row.label }}</span>
        <span v-if="row.held" class="text-[10px]">{{ say("picker-held") }}</span>
        <button
          v-else
          type="button"
          class="rounded border border-border px-1.5 text-[10.5px] text-accent hover:bg-surface-3"
          @click="emit('add', row.id)"
        >
          {{ say("picker-add") }}
        </button>
      </div>
      <p v-if="!shown.length" class="px-1.5 py-2 text-[11px] text-muted">
        {{ say("palette-nothing") }}
      </p>
    </div>
    <button
      type="button"
      class="mt-1 w-full rounded border border-border px-2 py-1 text-[10.5px] text-muted hover:bg-surface-2"
      @click="emit('close')"
    >
      {{ say("action-cancel") }}
    </button>
  </div>
</template>
