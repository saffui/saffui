<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { useSession } from "@/stores/session";
import { takeRememberedPath } from "@/services/auth";

const session = useSession();
const router = useRouter();

onMounted(async () => {
  try {
    await session.returned(new URLSearchParams(location.search));
    const held = takeRememberedPath();
    const back = held.startsWith(`/${session.realm}/`) ? held : `/${session.realm}/overview`;
    await router.replace(back);
  } catch {
    await router.replace("/login?failed");
  }
});
</script>

<template>
  <div class="grid h-full place-items-center bg-bg text-xs text-muted">…</div>
</template>
