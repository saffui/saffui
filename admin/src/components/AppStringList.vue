<script setup lang="ts">
const props = defineProps<{
  modelValue: string[];
  inputLabel: string;
  addLabel: string;
  removeLabel: string;
  placeholder?: string;
}>();

const emit = defineEmits<{ "update:modelValue": [value: string[]] }>();

function replace(at: number, value: string) {
  const rows = props.modelValue.length ? [...props.modelValue] : [""];
  rows[at] = value;
  emit("update:modelValue", rows);
}

function remove(at: number) {
  emit("update:modelValue", props.modelValue.filter((_, index) => index !== at));
}
</script>

<template>
  <div class="mt-1.5 grid gap-1.5">
    <div
      v-for="(value, at) in modelValue.length ? modelValue : ['']"
      :key="at"
      class="flex min-w-0 gap-1.5"
    >
      <input
        :value="value"
        :aria-label="`${inputLabel} ${at + 1}`"
        :placeholder="placeholder"
        class="min-w-0 flex-1 sf-field font-mono"
        spellcheck="false"
        @input="replace(at, ($event.target as HTMLInputElement).value)"
      />
      <button
        type="button"
        class="grid w-8 shrink-0 place-items-center rounded-md border border-border text-sm text-muted hover:border-danger/40 hover:text-danger"
        :aria-label="`${removeLabel}: ${inputLabel} ${at + 1}`"
        @click="remove(at)"
      >
        &times;
      </button>
    </div>
    <button
      type="button"
      class="w-fit rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
      @click="emit('update:modelValue', [...modelValue, ''])"
    >
      + {{ addLabel }}
    </button>
  </div>
</template>
