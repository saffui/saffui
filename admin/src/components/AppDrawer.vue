<script setup lang="ts">
// The right-side drawer every detail surface uses: overlay, Escape to close,
// the panel scrolls on its own. Content is the caller's; this owns only the
// frame.
import { onMounted, onUnmounted } from "vue";

const props = defineProps<{ title: string; subtitle?: string }>();
const emit = defineEmits<{ close: [] }>();

function onKey(event: KeyboardEvent) {
  if (event.key === "Escape") emit("close");
}
onMounted(() => document.addEventListener("keydown", onKey));
onUnmounted(() => document.removeEventListener("keydown", onKey));
</script>

<template>
  <div class="fixed inset-0 z-40">
    <div class="absolute inset-0 bg-black/30" @click="emit('close')"></div>
    <aside
      class="absolute inset-y-0 right-0 flex w-[560px] max-w-full flex-col border-l border-border bg-surface"
      role="dialog"
      aria-modal="true"
      :aria-label="props.title"
    >
      <header class="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div class="min-w-0">
          <h2 class="truncate text-sm font-semibold tracking-tight">{{ props.title }}</h2>
          <div v-if="props.subtitle" class="mt-0.5 truncate font-mono text-[11px] text-faint">
            {{ props.subtitle }}
          </div>
        </div>
        <button
          type="button"
          class="rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
          @click="emit('close')"
        >
          Esc
        </button>
      </header>
      <div class="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        <slot />
      </div>
    </aside>
  </div>
</template>
