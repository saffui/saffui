<script setup lang="ts">
import { ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { useSession } from "@/stores/session";

const session = useSession();
const route = useRoute();
const realm = ref("main");
const host = window.location.host;
const failed = ref(route.query.failed !== undefined);

async function begin() {
  failed.value = false;
  await session.login(realm.value.trim() || "main");
}
</script>

<template>
  <main class="sf-login-shell grid min-h-full place-items-center px-4 py-8" aria-labelledby="login-title">
    <section class="sf-login-card">
      <div class="mb-5 flex items-center gap-3">
        <div
          class="grid size-[46px] place-items-center rounded-[9px] border border-accent-line bg-accent-tint font-semibold text-accent"
        >
          S
        </div>
        <h1 id="login-title" class="text-xl font-semibold tracking-tight">
          {{ say("login-title") }}
        </h1>
      </div>
      <p class="mb-5 max-w-[42ch] text-xs leading-5 text-muted">{{ say("login-lede") }}</p>
      <form @submit.prevent="begin">
        <label for="login-realm" class="block text-[11px] font-medium text-muted">
          {{ say("login-realm") }}
          <input id="login-realm" v-model="realm" class="sf-field mt-1.5 font-mono" autocomplete="off" spellcheck="false" />
        </label>
        <button
          type="submit"
          class="sf-button sf-button-primary mt-5 h-10 w-full justify-center"
        >
          {{ say("login-continue") }}
        </button>
      </form>
      <div class="mt-5 border-t border-border pt-3 font-mono text-[10.5px] text-faint">
        {{ host }}
      </div>
      <p v-if="failed" class="mt-4 border-l-2 border-danger pl-2.5 text-xs leading-5 text-danger" role="alert">
        {{ say("login-failed") }}
      </p>
    </section>
  </main>
</template>
