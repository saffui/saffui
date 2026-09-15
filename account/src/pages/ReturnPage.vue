<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { SaffuiError } from "saffui-js";
import { say } from "@/i18n";
import { finishSignIn } from "@/services/session";

const router = useRouter();

onMounted(async () => {
  try {
    await router.replace(await finishSignIn(new URLSearchParams(location.search)));
  } catch (refused) {
    // A return address kept from an earlier sign-in has nothing left to redeem:
    // the console signs in afresh. Any other failure is explained.
    const stale = refused instanceof SaffuiError && refused.error === "no_login";
    await router.replace(stale ? "/profile" : "/trouble");
  }
});
</script>

<template>
  <main class="standalone" aria-busy="true">
    <p class="loading">{{ say("return-busy") }}</p>
  </main>
</template>
