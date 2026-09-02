<script setup lang="ts" generic="T extends { name: string; display_name: string; description: string }">
// The one table the three directory listings share: name in the monospace,
// the human name, the description, and whatever extra column the caller
// renders through the slot. Rows open whatever the caller decides.
import { say } from "@/i18n";

defineProps<{
  items: T[];
  total: number | null;
  openedKey?: string | null;
  keyOf: (row: T) => string;
}>();
const emit = defineEmits<{ open: [row: T] }>();
</script>

<template>
  <div class="overflow-x-auto rounded-lg border border-border bg-surface">
    <table class="w-full text-left text-xs">
      <thead>
        <tr class="border-b border-border text-[11px] text-muted">
          <th class="px-3 py-2 font-medium">{{ say("scopes-col-name") }}</th>
          <th class="px-3 py-2 font-medium">{{ say("directory-col-display") }}</th>
          <th class="px-3 py-2 font-medium">{{ say("scopes-col-description") }}</th>
          <th class="px-3 py-2 font-medium"><slot name="extra-head" /></th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in items"
          :key="keyOf(row)"
          class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
          :class="openedKey === keyOf(row) && 'bg-surface-2'"
          @click="emit('open', row)"
        >
          <td class="px-3 py-2 font-mono text-[11.5px]">{{ row.name }}</td>
          <td class="px-3 py-2">{{ row.display_name }}</td>
          <td class="px-3 py-2 text-muted">{{ row.description }}</td>
          <td class="px-3 py-2"><slot name="extra" :row="row" /></td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
