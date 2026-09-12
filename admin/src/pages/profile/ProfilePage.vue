<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { getUser } from "@/services/users";
import { afterWrites } from "@/services/writes";
import { useSession } from "@/stores/session";
import type { UserFull } from "@/models/user";

const route = useRoute();
const session = useSession();
const realm = computed(() => session.realm || String(route.params.realm));
const user = ref<UserFull | null>(null);
const failed = ref(false);

async function load() {
  if (!session.userId) {
    failed.value = true;
    return;
  }
  try {
    user.value = await getUser(realm.value, session.userId);
    failed.value = false;
  } catch {
    user.value = null;
    failed.value = true;
  }
}
onMounted(load);
afterWrites(load);
</script>

<template>
  <div class="max-w-3xl">
    <h1 class="text-lg font-semibold tracking-tight">{{ say("profile-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ realm }}</p>
    <p v-if="failed" class="mt-5 text-xs text-danger" role="alert">{{ say("profile-unavailable") }}</p>
    <div v-else-if="user" class="sf-list mt-5 divide-y divide-border text-xs">
      <div class="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr]">
        <span class="text-muted">{{ say("profile-identity") }}</span>
        <strong class="font-medium">{{ user.user_name }}</strong>
      </div>
      <div class="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr]">
        <span class="text-muted">{{ say("profile-email") }}</span>
        <span>{{ user.email }}</span>
      </div>
      <div class="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr]">
        <span class="text-muted">{{ say("profile-realm-name") }}</span>
        <span>{{ realm }}</span>
      </div>
      <div class="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr]">
        <span class="text-muted">{{ say("profile-id") }}</span>
        <code class="break-all font-mono text-faint">{{ user.user_id }}</code>
      </div>
    </div>
  </div>
</template>
