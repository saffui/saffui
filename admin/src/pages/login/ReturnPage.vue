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
  <main class="grid min-h-full place-items-center bg-bg px-4 text-xs text-muted" aria-busy="true">
    <div class="flex items-center gap-2 rounded border border-border bg-surface px-3 py-2.5">
      <span class="size-1.5 animate-pulse rounded-full bg-accent" aria-hidden="true"></span>
      <span>…</span>
    </div>
  </main>
</template>
