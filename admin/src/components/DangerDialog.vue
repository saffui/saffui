<script setup lang="ts">
// The deck's destructive dialog, built to its own measurements: 540 wide, a
// 66 head, a 56 foot, and a facts strip of 56. What is about to be lost is
// counted before it is lost, and the button stays out of reach until the
// name is typed back.
import { computed, ref, watch } from "vue";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";

const props = defineProps<{
  open: boolean;
  /// The heading, already worded for what is being taken away.
  title: string;
  /// The identifier under it, in mono: the thing itself, not a description.
  named: string;
  lede: string;
  /// What goes with it, counted. Rendered as the deck's facts strip.
  facts: { value: string; label: string }[];
  /// The quieter second paragraph, for what survives or what follows.
  aside?: string;
  /// What a caller meets afterwards, shown as the answer it will read.
  answer?: { code: string; body: string };
  /// The one consequence that deserves the danger tint of its own.
  warning?: string;
  /// Where this lands, said in the foot. Absent says nothing rather than
  /// claiming a trail that is not written.
  trail?: string;
  confirmLabel: string;
  failed?: string;
}>();

const emit = defineEmits<{ close: []; confirm: [] }>();

const typed = ref("");
const armed = computed(() => typed.value === props.named);

watch(
  () => props.open,
  (open) => {
    if (open) typed.value = "";
  },
);
</script>

<template>
  <div v-if="open" class="fixed inset-0 z-50 flex items-start justify-center">
    <div class="absolute inset-0 bg-black/45" @click="emit('close')"></div>
    <div
      class="relative mt-24 w-[540px] max-w-full rounded-lg border border-glass-line bg-glass shadow-(--sf-shadow) backdrop-blur-xl"
      role="dialog"
      aria-modal="true"
    >
      <div class="flex h-[66px] items-center gap-3 px-[18px]">
        <span
          class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-danger-tint text-danger"
        >
          <AppIcon name="remove" :size="15" />
        </span>
        <span class="min-w-0 flex-1">
          <span class="block truncate text-[15px] text-ink">{{ title }}</span>
          <span class="block truncate font-mono text-[11px] text-faint">{{ named }}</span>
        </span>
        <button
          type="button"
          class="shrink-0 text-muted hover:text-ink"
          :aria-label="say('action-cancel')"
          @click="emit('close')"
        >
          <AppIcon name="close" :size="16" />
        </button>
      </div>

      <div class="flex flex-col gap-3.5 px-[18px] pb-1">
        <p class="text-[13px] text-ink">{{ lede }}</p>

        <div class="flex rounded-md bg-neutral-tint">
          <div
            v-for="fact in facts"
            :key="fact.label"
            class="flex h-14 flex-1 flex-col justify-center gap-1 px-3"
          >
            <span class="font-mono text-[15px] leading-none text-ink">{{ fact.value }}</span>
            <span class="truncate text-[10px] text-faint">{{ fact.label }}</span>
          </div>
        </div>

        <p v-if="aside" class="text-[11.5px] text-muted">{{ aside }}</p>

        <div v-if="answer" class="flex flex-col gap-1.5">
          <span class="text-[10.5px] text-faint">{{ say("danger-answer-lede") }}</span>
          <div class="flex flex-col gap-1 rounded-md bg-surface-2 px-3 py-2.5">
            <span class="font-mono text-[11px] text-danger">{{ answer.code }}</span>
            <span class="font-mono text-[11px] whitespace-pre-wrap text-muted">{{
              answer.body
            }}</span>
          </div>
        </div>

        <div
          v-if="warning"
          class="flex items-center gap-2 rounded-md bg-danger-tint px-3 py-2.5"
        >
          <AppIcon name="danger" :size="13" class="shrink-0 text-danger" />
          <span class="text-[11px] text-muted">{{ warning }}</span>
        </div>

        <label class="flex flex-col gap-1.5">
          <span class="text-[10.5px] text-faint">{{
            say("danger-type-back", { named })
          }}</span>
          <input
            v-model="typed"
            class="sf-field font-mono"
            spellcheck="false"
            autocomplete="off"
            :placeholder="named"
          />
        </label>

        <p v-if="failed" class="text-[11px] text-danger" role="alert">{{ failed }}</p>
      </div>

      <div class="flex h-14 items-center gap-3 px-[18px]">
        <span v-if="trail" class="min-w-0 flex-1 truncate font-mono text-[10.5px] text-faint">{{
          trail
        }}</span>
        <span v-else class="flex-1"></span>
        <button type="button" class="sf-button sf-button-secondary" @click="emit('close')">
          {{ say("action-cancel") }}
        </button>
        <button
          type="button"
          class="sf-button sf-button-danger disabled:opacity-40"
          :disabled="!armed"
          @click="emit('confirm')"
        >
          <AppIcon name="remove" :size="13" />
          {{ confirmLabel }}
        </button>
      </div>
    </div>
  </div>
</template>
