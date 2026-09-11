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
  <main class="grid min-h-full place-items-center bg-bg px-4 py-8" aria-labelledby="login-title">
    <section class="w-full max-w-sm rounded-lg border border-border bg-surface p-5 shadow-(--sf-shadow) sm:p-6">
      <div class="mb-5 flex items-center gap-2.5">
        <div
          class="grid size-7 place-items-center rounded-md bg-accent font-semibold text-accent-ink"
        >
          S
        </div>
        <h1 id="login-title" class="text-sm font-semibold tracking-tight">
          {{ say("login-title") }}
        </h1>
      </div>
      <p class="mb-5 max-w-[30ch] text-xs leading-5 text-muted">{{ say("login-lede") }}</p>
      <form @submit.prevent="begin">
        <label for="login-realm" class="block text-[11px] font-medium text-muted">
          {{ say("login-realm") }}
          <input
            id="login-realm"
            v-model="realm"
            class="sf-field mt-1.5 font-mono"
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
      <p v-if="failed" class="mt-4 border-l-2 border-danger pl-2.5 text-xs leading-5 text-danger" role="alert">
        {{ say("login-failed") }}
      </p>
    </section>
  </main>
</template>
