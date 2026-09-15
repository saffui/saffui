<script setup lang="ts">
import { ref } from "vue";
import AppIcon from "./AppIcon.vue";

const props = defineProps<{ text: string }>();
const open = ref(false);
const anchor = ref<HTMLElement | null>(null);
const placed = ref({ left: 0, top: 0, below: false });

const WIDTH = 240;

// The bubble is placed from the trigger's rectangle and teleported to the body,
// so a card's edge never clips it.
function showHint() {
  const held = anchor.value?.getBoundingClientRect();
  if (!held) return;
  const below = held.top < 120;
  const left = Math.min(
    Math.max(8, held.left + held.width / 2 - WIDTH / 2),
    window.innerWidth - WIDTH - 8,
  );
  placed.value = { left, top: below ? held.bottom + 6 : held.top - 6, below };
  open.value = true;
}

function hideHint() {
  open.value = false;
}
</script>

<template>
  <span class="hint">
    <button
      ref="anchor"
      type="button"
      class="hint-trigger"
      :aria-label="props.text"
      @mouseenter="showHint"
      @mouseleave="hideHint"
      @focus="showHint"
      @blur="hideHint"
      @keydown.esc="hideHint"
      @click.prevent="open ? hideHint() : showHint()"
    >
      <AppIcon name="hint" :size="14" />
    </button>
    <Teleport to="body">
      <span
        v-if="open"
        class="hint-bubble"
        role="tooltip"
        :style="{
          left: `${placed.left}px`,
          top: `${placed.top}px`,
          transform: placed.below ? 'none' : 'translateY(-100%)',
        }"
      >
        {{ props.text }}
      </span>
    </Teleport>
  </span>
</template>

<style scoped>
.hint {
  display: inline-flex;
  vertical-align: middle;
}
.hint-trigger {
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  padding: 0;
  border: 0;
  border-radius: 999px;
  background: none;
  color: var(--muted);
  cursor: help;
}
.hint-trigger:hover,
.hint-trigger:focus-visible {
  color: var(--ink);
}
.hint-bubble {
  position: fixed;
  z-index: 70;
  width: 240px;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) * 0.6);
  background: var(--surface);
  color: var(--ink);
  font-size: 13px;
  font-weight: 400;
  line-height: 1.45;
  letter-spacing: normal;
  text-transform: none;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.18);
  pointer-events: none;
}
</style>
