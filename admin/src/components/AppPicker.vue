<script setup lang="ts">
import { computed, ref, useId } from "vue";
import { say } from "@/i18n";

const props = defineProps<{
  rows: { id: string; label: string; held: boolean }[];
  title: string;
}>();
const emit = defineEmits<{ add: [id: string]; close: [] }>();
const typed = ref("");
const titleId = useId();
const shown = computed(() => {
  const needle = typed.value.trim().toLowerCase();
  const rows = needle
    ? props.rows.filter((row) => row.label.toLowerCase().includes(needle))
    : props.rows;
  return rows.slice(0, 12);
});
</script>

<template>
  <div
    role="dialog"
    :aria-labelledby="titleId"
    class="sf-popover absolute top-full left-0 z-40 mt-1 w-80 max-w-[calc(100vw-2rem)] p-2"
  >
    <p :id="titleId" class="sf-section-label px-1 pb-1.5">
      {{ title }}
    </p>
    <input
      v-model="typed"
      :placeholder="say('picker-filter')"
      class="sf-field font-mono"
      autofocus
      spellcheck="false"
    />
    <div class="mt-1.5 max-h-64 overflow-y-auto">
      <div
        v-for="row in shown"
        :key="row.id"
        class="flex min-h-9 items-center gap-2 rounded px-2 text-xs"
        :class="row.held ? 'text-faint' : 'hover:bg-surface-2'"
      >
        <span class="min-w-0 flex-1 truncate font-mono">{{ row.label }}</span>
        <span v-if="row.held" class="text-[11px]">{{ say("picker-held") }}</span>
        <button
          v-else
          type="button"
          class="sf-button min-h-7 px-2 text-[11.5px] text-accent hover:bg-surface-3"
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
      class="sf-button sf-button-secondary mt-1.5 w-full justify-center"
      @click="emit('close')"
    >
      {{ say("action-cancel") }}
    </button>
  </div>
</template>
