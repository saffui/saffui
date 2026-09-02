<script setup lang="ts">
// The switch a boolean setting deserves: a track and a knob, brass when on,
// the label and its hint riding beside it through the slot.
const on = defineModel<boolean>({ required: true });
</script>

<template>
  <label class="flex cursor-pointer items-center gap-2 text-xs">
    <button
      type="button"
      role="switch"
      :aria-checked="on"
      class="relative h-4.5 w-8 shrink-0 rounded-full border transition-colors"
      :class="on ? 'border-accent bg-accent' : 'border-border bg-surface-2'"
      @click="on = !on"
    >
      <span
        class="absolute top-1/2 size-3 -translate-y-1/2 rounded-full transition-[left]"
        :class="on ? 'left-[calc(100%-0.875rem)] bg-accent-ink' : 'left-0.5 bg-muted'"
      ></span>
    </button>
    <slot />
  </label>
</template>
