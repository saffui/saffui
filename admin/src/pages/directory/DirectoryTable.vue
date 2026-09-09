<script setup lang="ts" generic="T extends { name: string; display_name: string; description: string }">
// The one table the three directory listings share: name in the monospace,
// the human name, the description, and whatever extra column the caller
// renders through the slot. Rows open whatever the caller decides.
import { CornerDownRight } from "lucide-vue-next";
import { say } from "@/i18n";

defineProps<{
  items: T[];
  openedKey?: string | null;
  keyOf: (row: T) => string;
  /// Tree depth per row, when the listing is a hierarchy. Zero stays flat.
  indentOf?: (row: T) => number;
}>();
const emit = defineEmits<{ open: [row: T] }>();
</script>

<template>
  <div class="sf-list overflow-x-auto">
    <table class="sf-table">
      <thead>
        <tr>
          <th>{{ say("scopes-col-name") }}</th>
          <th>{{ say("directory-col-display") }}</th>
          <th>{{ say("scopes-col-description") }}</th>
          <th><slot name="extra-head" /></th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in items"
          :key="keyOf(row)"
          class="cursor-pointer"
          :class="openedKey === keyOf(row) && 'bg-surface-3'"
          @click="emit('open', row)"
        >
          <td class="font-mono text-[11.5px]">
            <span
              class="inline-flex items-center gap-1"
              :style="{ paddingLeft: `${(indentOf?.(row) ?? 0) * 16}px` }"
            >
              <CornerDownRight
                v-if="(indentOf?.(row) ?? 0) > 0"
                :size="11"
                :stroke-width="1.6"
                class="text-faint"
              />
              {{ row.name }}
            </span>
          </td>
          <td>{{ row.display_name }}</td>
          <td class="text-muted">{{ row.description }}</td>
          <td><slot name="extra" :row="row" /></td>
        </tr>
      </tbody>
    </table>
    <slot name="foot" />
  </div>
</template>
