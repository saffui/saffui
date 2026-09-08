<script setup lang="ts">
import { ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { useSession } from "@/stores/session";

const session = useSession();
const route = useRoute();
const realm = ref("main");
const failed = ref(route.query.failed !== undefined);

async function begin() {
  failed.value = false;
  await session.login(realm.value.trim() || "main");
}
</script>

<template>
  <div class="grid h-full place-items-center bg-bg">
    <div class="w-80 rounded-lg border border-border bg-surface p-6 shadow-(--sf-shadow)">
      <div class="mb-5 flex items-center gap-2.5">
        <div
          class="grid size-7 place-items-center rounded-md bg-accent font-semibold text-accent-ink"
        >
          S
        </div>
        <span class="text-sm font-semibold tracking-tight">{{ say("login-title") }}</span>
      </div>
      <p class="mb-4 text-xs text-muted">{{ say("login-lede") }}</p>
      <form @submit.prevent="begin">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("login-realm") }}
          <input
            v-model="realm"
            class="sf-field mt-1 font-mono"
            autocomplete="off"
            spellcheck="false"
          />
        </label>
        <button
          type="submit"
          class="sf-button sf-button-primary mt-4 w-full justify-center"
        >
          {{ say("login-continue") }}
        </button>
      </form>
      <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">
        {{ say("login-failed") }}
      </p>
    </div>
  </div>
</template>
