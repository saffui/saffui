<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from "vue";
import { userSubjects, userSubjectValue } from "./userSubjects";
import type { UserBrief } from "@/models/user";

const props = defineProps<{
  realm: string;
  modelValue: string;
  idOnly?: boolean;
  placeholder?: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();
defineOptions({ inheritAttrs: false });
const listId = useId();
const users = ref<UserBrief[]>([]);
const open = ref(false);
const active = ref(-1);
const activeId = computed(() => active.value < 0 ? undefined : `${listId}-option-${active.value}`);
let timer: ReturnType<typeof setTimeout> | undefined;
let closeTimer: ReturnType<typeof setTimeout> | undefined;
let request = 0;

async function load() {
  const current = ++request;
  try {
    const found = await userSubjects(props.realm, props.modelValue);
    if (current === request) users.value = found;
  } catch {
    if (current === request) users.value = [];
  }
}

function schedule() {
  clearTimeout(timer);
  ++request;
  timer = setTimeout(load, 250);
}

function onInput(event: Event) {
  active.value = -1;
  open.value = true;
  emit("update:modelValue", (event.target as HTMLInputElement).value);
}

function choose(user: UserBrief) {
  emit("update:modelValue", userSubjectValue(user, props.idOnly === true));
  open.value = false;
  active.value = -1;
}

function move(step: number) {
  if (!users.value.length) return;
  open.value = true;
  active.value = (active.value + step + users.value.length) % users.value.length;
  nextTick(() => document.getElementById(activeId.value ?? "")?.scrollIntoView({ block: "nearest" }));
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === "ArrowDown") {
    event.preventDefault();
    move(1);
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    move(-1);
  } else if (event.key === "Enter" && open.value && active.value >= 0) {
    event.preventDefault();
    const user = users.value[active.value];
    if (user) choose(user);
  } else if (event.key === "Escape") {
    open.value = false;
    active.value = -1;
  }
}

function deferClose() {
  clearTimeout(closeTimer);
  closeTimer = setTimeout(() => {
    open.value = false;
    active.value = -1;
  }, 100);
}

onMounted(load);
watch(() => props.realm, () => {
  users.value = [];
  schedule();
});
watch(() => props.modelValue, schedule);
onBeforeUnmount(() => {
  clearTimeout(timer);
  clearTimeout(closeTimer);
  ++request;
});
</script>

<template>
  <div class="relative">
    <input
      v-bind="$attrs"
      :value="modelValue"
      :placeholder="placeholder"
      :aria-controls="listId"
      :aria-activedescendant="activeId"
      :aria-expanded="open"
      role="combobox"
      aria-autocomplete="list"
      autocomplete="off"
      spellcheck="false"
      @focus="open = true"
      @blur="deferClose"
      @keydown="onKeydown"
      @input="onInput"
    />
    <div
      v-if="open && users.length"
      :id="listId"
      role="listbox"
      class="sf-popover absolute top-full right-0 left-0 z-50 mt-1 max-h-64 overflow-y-auto p-1"
    >
      <div
        v-for="(user, index) in users"
        :id="`${listId}-option-${index}`"
        :key="user.user_id"
        role="option"
        :aria-selected="active === index"
        class="flex cursor-pointer items-center gap-3 rounded px-2.5 py-2"
        :class="active === index ? 'bg-accent-tint text-ink' : 'hover:bg-surface-2'"
        @mouseenter="active = index"
        @mousedown.prevent="choose(user)"
      >
        <span class="min-w-0 flex-1">
          <span class="block truncate text-[12.5px] font-medium text-ink">{{ user.user_name }}</span>
          <span v-if="user.email" class="mt-0.5 block truncate text-[11px] text-muted">{{ user.email }}</span>
        </span>
        <span class="max-w-[42%] truncate font-mono text-[10.5px] text-faint">{{ user.user_id }}</span>
      </div>
    </div>
  </div>
</template>
