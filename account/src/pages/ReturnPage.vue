<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { say } from "@/i18n";
import { chooseRefusedRoute, finishSignIn } from "@/services/session";

const router = useRouter();

onMounted(async () => {
  try {
    await router.replace((await finishSignIn(new URLSearchParams(location.search))).path);
  } catch (refused) {
    await router.replace(chooseRefusedRoute(refused));
  }
});
</script>

<template>
  <main class="standalone" aria-busy="true">
    <p class="loading">{{ say("return-busy") }}</p>
  </main>
</template>
