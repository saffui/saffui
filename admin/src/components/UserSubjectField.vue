<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, useId, watch } from "vue";
import { userSubjects } from "./userSubjects";
import type { UserBrief } from "@/models/user";

const props = defineProps<{
  realm: string;
  modelValue: string;
  idOnly?: boolean;
  placeholder?: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();
const listId = useId();
const users = ref<UserBrief[]>([]);
let timer: ReturnType<typeof setTimeout> | undefined;
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

onMounted(load);
watch(() => props.realm, () => {
  users.value = [];
  schedule();
});
watch(() => props.modelValue, schedule);
onBeforeUnmount(() => {
  clearTimeout(timer);
  ++request;
});
</script>

<template>
  <input
    :value="modelValue"
    :list="listId"
    :placeholder="placeholder"
    autocomplete="off"
    spellcheck="false"
    @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  />
  <datalist :id="listId">
    <option
      v-for="user in users"
      :key="user.user_id"
      :value="idOnly ? user.user_id : user.user_name"
      :label="idOnly ? user.user_name : user.user_id"
    />
  </datalist>
</template>
