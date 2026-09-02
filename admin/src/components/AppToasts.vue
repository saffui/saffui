<script setup lang="ts">
import AppIcon from "@/components/AppIcon.vue";
import { dismissToast, toasts } from "@/services/toasts";
</script>

<template>
  <div class="pointer-events-none fixed top-14 right-4 z-[60] flex w-80 flex-col gap-2">
    <TransitionGroup name="toast">
      <div
        v-for="held in toasts"
        :key="held.id"
        class="pointer-events-auto rounded-lg border bg-surface p-3 shadow-(--sf-shadow)"
        :class="held.tone === 'danger' ? 'border-danger/50' : 'border-ok/50'"
        role="alert"
      >
        <div class="flex items-start gap-2">
          <span
            class="mt-1 size-1.5 shrink-0 rounded-full"
            :class="held.tone === 'danger' ? 'bg-danger' : 'bg-ok'"
          ></span>
          <div class="min-w-0 flex-1">
            <p class="text-xs font-semibold">{{ held.title }}</p>
            <p v-if="held.body" class="mt-0.5 text-[11px] break-words text-muted">
              {{ held.body }}
            </p>
            <p v-if="held.hint" class="mt-1 text-[10.5px] text-faint">{{ held.hint }}</p>
          </div>
          <button
            type="button"
            class="grid size-5 shrink-0 place-items-center rounded text-faint hover:text-ink"
            aria-label="dismiss"
            @click="dismissToast(held.id)"
          >
            &times;
          </button>
        </div>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition:
    opacity 0.18s ease,
    transform 0.18s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
