<script setup lang="ts">
import { onMounted, ref } from "vue";
import { say } from "@/i18n";

const props = defineProps<{ title: string; body: string; confirm: string; busy: boolean }>();
const emit = defineEmits<{ confirm: []; cancel: [] }>();
const dialog = ref<HTMLDialogElement | null>(null);

// Modal from the moment it shows: focus lands on the way out, and Escape takes it.
onMounted(() => dialog.value?.showModal());
</script>

<template>
  <dialog
    ref="dialog"
    class="confirm"
    aria-labelledby="confirm-title"
    aria-describedby="confirm-body"
    @cancel.prevent="emit('cancel')"
  >
    <h2 id="confirm-title">{{ props.title }}</h2>
    <p id="confirm-body">{{ props.body }}</p>
    <div class="confirm-actions">
      <button type="button" class="button" :disabled="props.busy" @click="emit('cancel')">
        {{ say("confirm-keep") }}
      </button>
      <button
        type="button"
        class="button button-danger"
        :disabled="props.busy"
        @click="emit('confirm')"
      >
        {{ props.confirm }}
      </button>
    </div>
  </dialog>
</template>
