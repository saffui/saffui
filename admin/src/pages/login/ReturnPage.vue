<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { useSession } from "@/stores/session";

const session = useSession();
const router = useRouter();

onMounted(async () => {
  try {
    await session.returned(new URLSearchParams(location.search));
    await router.replace(`/${session.realm}/overview`);
  } catch {
    await router.replace("/login?failed");
  }
});
</script>

<template>
  <div class="grid h-full place-items-center bg-bg text-xs text-muted">…</div>
</template>
