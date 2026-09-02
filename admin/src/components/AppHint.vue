<script setup lang="ts">
// The little question mark beside a label. Hover or focus opens a short
// explanation; the name is a Fluent key, so every hint is translated where
// every other string is. The bubble teleports to the body and positions
// itself from the trigger's rectangle, because the pages scroll inside an
// overflow container that would otherwise clip a bubble near an edge.
import { ref } from "vue";
import { Info } from "lucide-vue-next";
import { say } from "@/i18n";

const props = defineProps<{ name?: string; text?: string }>();
const open = ref(false);
const anchor = ref<HTMLElement | null>(null);
const placed = ref({ left: 0, top: 0, below: false });
const text = () => props.text ?? (props.name ? say(props.name) : "");

const WIDTH = 224;

function show() {
  const held = anchor.value?.getBoundingClientRect();
  if (!held) return;
  // Above by default; below when the top of the viewport is too close.
  const below = held.top < 140;
  const left = Math.min(
    Math.max(8, held.left + held.width / 2 - WIDTH / 2),
    window.innerWidth - WIDTH - 8,
  );
  placed.value = { left, top: below ? held.bottom + 6 : held.top - 6, below };
  open.value = true;
}
function hide() {
  open.value = false;
}
</script>

<template>
  <span class="relative inline-flex align-middle">
    <button
      ref="anchor"
      type="button"
      class="grid size-4 place-items-center rounded-full text-faint hover:text-muted focus:text-muted focus:outline-none"
      :aria-label="text()"
      tabindex="-1"
      @mouseenter="show"
      @mouseleave="hide"
      @focus="show"
      @blur="hide"
      @click.prevent="open ? hide() : show()"
    >
      <Info :size="12" :stroke-width="1.6" />
    </button>
    <Teleport to="body">
      <span
        v-if="open"
        class="fixed z-[70] w-56 rounded-md border border-border bg-surface-3 px-2.5 py-1.5 text-[10.5px] leading-relaxed font-normal text-ink normal-case shadow-(--sf-shadow)"
        :style="{
          left: placed.left + 'px',
          top: placed.top + 'px',
          transform: placed.below ? 'none' : 'translateY(-100%)',
        }"
        role="tooltip"
      >
        {{ text() }}
      </span>
    </Teleport>
  </span>
</template>
