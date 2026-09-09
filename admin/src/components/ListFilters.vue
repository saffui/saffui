<script setup lang="ts">
// The bar above a listing: what to look for, what to narrow by, and what is
// currently narrowing it. Each control names itself in its own value, the way
// the deck writes them, so no labels sit above the row.
import { computed } from "vue";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";

export interface Choice {
  /// What the server calls it, and what the pill says it is.
  name: string;
  label: string;
  /// The first is what "any" means, and it never becomes a pill.
  options: { value: string; label: string }[];
}

const props = defineProps<{
  search: string;
  placeholder: string;
  choices?: Choice[];
  chosen?: Record<string, string>;
}>();

const emit = defineEmits<{
  "update:search": [held: string];
  "update:chosen": [held: Record<string, string>];
}>();

const held = computed(() => props.chosen ?? {});

const pills = computed(() =>
  (props.choices ?? [])
    .map((choice) => {
      const value = held.value[choice.name] ?? "";
      const option = choice.options.find((one) => one.value === value);
      return value && option ? { name: choice.name, label: `${choice.label}: ${option.label}` } : null;
    })
    .filter((one): one is { name: string; label: string } => one !== null),
);

function pick(name: string, value: string) {
  emit("update:chosen", { ...held.value, [name]: value });
}

function clearAll() {
  emit("update:chosen", {});
  emit("update:search", "");
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <div class="relative">
      <input
        :value="search"
        class="h-[31px] w-[300px] rounded bg-surface-2 pr-8 pl-2.5 text-[12.5px] text-ink placeholder:text-faint"
        :placeholder="placeholder"
        spellcheck="false"
        @input="emit('update:search', ($event.target as HTMLInputElement).value)"
      />
      <AppIcon
        name="search"
        :size="13"
        class="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 text-faint"
      />
    </div>

    <select
      v-for="choice in choices ?? []"
      :key="choice.name"
      :value="held[choice.name] ?? ''"
      class="h-[31px] min-w-[150px] rounded bg-surface-2 px-2.5 text-[12.5px] text-ink"
      @change="pick(choice.name, ($event.target as HTMLSelectElement).value)"
    >
      <option v-for="one in choice.options" :key="one.value" :value="one.value">
        {{ choice.label }}: {{ one.label }}
      </option>
    </select>

    <span class="flex-1"></span>

    <button
      v-for="pill in pills"
      :key="pill.name"
      type="button"
      class="sf-badge sf-badge-accent"
      @click="pick(pill.name, '')"
    >
      {{ pill.label }}
      <AppIcon name="close" :size="11" />
    </button>
    <button
      v-if="pills.length || search"
      type="button"
      class="sf-badge hover:text-ink"
      @click="clearAll"
    >
      {{ say("filters-clear") }}
    </button>
  </div>
</template>
