<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { Eye, EyeOff } from "lucide-vue-next";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import { changeOwnPassword } from "@/services/account";
import { getUser } from "@/services/users";
import { afterWrites } from "@/services/writes";
import { useSession } from "@/stores/session";
import type { UserFull } from "@/models/user";
import { ownPasswordReady, passwordKeptHere } from "./ownPassword";

const route = useRoute();
const session = useSession();
const realm = computed(() => session.realm || String(route.params.realm));
const user = ref<UserFull | null>(null);
const failed = ref(false);

const current = ref("");
const replacement = ref("");
const again = ref("");
const showCurrent = ref(false);
const showReplacement = ref(false);
const showAgain = ref(false);
const saving = ref(false);
const refusal = ref("");
const ended = ref<number | null>(null);

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

async function changePassword() {
  ended.value = null;
  const ready = ownPasswordReady({
    current: current.value,
    replacement: replacement.value,
    again: again.value,
  });
  if (ready !== "ready") {
    refusal.value = say(ready === "mismatch" ? "user-password-mismatch" : "profile-password-missing");
    return;
  }
  refusal.value = "";
  saving.value = true;
  try {
    const told = await changeOwnPassword(realm.value, current.value, replacement.value);
    replacement.value = "";
    again.value = "";
    ended.value = told.ended_sessions;
  } catch {
    // The toast already said, with what to do about it.
  } finally {
    current.value = "";
    saving.value = false;
  }
}
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

    <section v-if="user" class="mt-8">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("profile-password") }} <AppHint name="profile-password-help" />
      </div>
      <p v-if="!passwordKeptHere(user)" class="mt-2 text-xs text-muted">
        {{ say("profile-password-directory") }}
      </p>
      <form v-else class="mt-2 flex flex-wrap items-end gap-2" @submit.prevent="changePassword">
        <input
          type="text"
          autocomplete="username"
          :value="user.user_name"
          class="sr-only"
          tabindex="-1"
          aria-hidden="true"
          readonly
        />
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("profile-password-current") }}
          <span class="relative mt-1 block">
            <input
              v-model="current"
              :type="showCurrent ? 'text' : 'password'"
              autocomplete="current-password"
              class="w-full rounded-md border border-border bg-surface-2 py-1.5 pr-7 pl-2.5 text-xs text-ink"
            />
            <button
              type="button"
              class="absolute inset-y-0 right-1.5 grid place-items-center text-faint hover:text-muted"
              :aria-label="say('user-password-reveal')"
              @click="showCurrent = !showCurrent"
            >
              <EyeOff v-if="showCurrent" :size="13" :stroke-width="1.6" />
              <Eye v-else :size="13" :stroke-width="1.6" />
            </button>
          </span>
        </label>
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("user-new-password") }}
          <span class="relative mt-1 block">
            <input
              v-model="replacement"
              :type="showReplacement ? 'text' : 'password'"
              autocomplete="new-password"
              class="w-full rounded-md border border-border bg-surface-2 py-1.5 pr-7 pl-2.5 text-xs text-ink"
            />
            <button
              type="button"
              class="absolute inset-y-0 right-1.5 grid place-items-center text-faint hover:text-muted"
              :aria-label="say('user-password-reveal')"
              @click="showReplacement = !showReplacement"
            >
              <EyeOff v-if="showReplacement" :size="13" :stroke-width="1.6" />
              <Eye v-else :size="13" :stroke-width="1.6" />
            </button>
          </span>
        </label>
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("user-new-password-again") }}
          <span class="relative mt-1 block">
            <input
              v-model="again"
              :type="showAgain ? 'text' : 'password'"
              autocomplete="new-password"
              class="w-full rounded-md border border-border bg-surface-2 py-1.5 pr-7 pl-2.5 text-xs text-ink"
            />
            <button
              type="button"
              class="absolute inset-y-0 right-1.5 grid place-items-center text-faint hover:text-muted"
              :aria-label="say('user-password-reveal')"
              @click="showAgain = !showAgain"
            >
              <EyeOff v-if="showAgain" :size="13" :stroke-width="1.6" />
              <Eye v-else :size="13" :stroke-width="1.6" />
            </button>
          </span>
        </label>
        <button type="submit" class="sf-button sf-button-primary" :disabled="saving">
          {{ say("profile-password-save") }}
        </button>
      </form>
      <p v-if="refusal" class="mt-2 text-xs text-danger" role="alert">{{ refusal }}</p>
      <p v-else-if="ended !== null" class="mt-2 text-xs text-muted" role="status">
        {{ say("profile-password-done", { count: String(ended) }) }}
      </p>
    </section>
  </div>
</template>
