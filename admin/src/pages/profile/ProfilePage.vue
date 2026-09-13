<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { Eye, EyeOff } from "lucide-vue-next";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import {
  changeOwnPassword,
  listOwnFactors,
  removeOwnApp,
  removeOwnKey,
  removeOwnRecoveryCodes,
  type OwnFactors,
} from "@/services/account";
import { ApiError } from "@/services/http";
import { getUser } from "@/services/users";
import { afterWrites } from "@/services/writes";
import { useSession } from "@/stores/session";
import type { UserFull } from "@/models/user";
import { OWN_FACTORS, freshEnough, type OwnFactor } from "./ownFactors";
import { ownPasswordReady, passwordKeptHere } from "./ownPassword";

const route = useRoute();
const session = useSession();
const realm = computed(() => session.realm || String(route.params.realm));
const user = ref<UserFull | null>(null);
const failed = ref(false);
const factors = ref<OwnFactors | null>(null);

const current = ref("");
const replacement = ref("");
const again = ref("");
const showCurrent = ref(false);
const showReplacement = ref(false);
const showAgain = ref(false);
const saving = ref(false);
const refusal = ref("");
const ended = ref<number | null>(null);
/// The preview has no server behind it, so no sign-in to send a person to.
const previewing = computed(() => session.accessToken === "preview");

async function addFactor(factor: OwnFactor) {
  await session.enrol(realm.value, factor, route.fullPath);
}

function when(held: string | null): string {
  return held ? new Date(held).toLocaleDateString() : "";
}

async function signInAgain() {
  if (window.confirm(say("profile-factor-sign-in-again"))) {
    await session.reauthenticate(realm.value, route.fullPath);
  }
}

/// Remove one of the person's factors, or first send them to sign in again
/// when the sign-in behind the page is too old for a removal.
async function removeFactor(named: string, remove: () => Promise<void>) {
  if (!freshEnough(factors.value?.fresh_until ?? null, Math.floor(Date.now() / 1000))) {
    await signInAgain();
    return;
  }
  if (!window.confirm(say("profile-factor-remove-confirm", { factor: named }))) return;
  try {
    await remove();
  } catch (refusal) {
    // The toast already said; a sign-in gone stale between the list and the
    // click is the one refusal the page can do something about.
    if (refusal instanceof ApiError && refusal.code === "account.reauthentication_required") {
      await signInAgain();
    }
  }
}

async function load() {
  if (!session.userId) {
    failed.value = true;
    return;
  }
  try {
    user.value = await getUser(realm.value, session.userId);
    failed.value = false;
    try {
      factors.value = await listOwnFactors(realm.value);
    } catch {
      // A role without account:read shows no list rather than a broken one.
      factors.value = null;
    }
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

    <section v-if="user" class="mt-8">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("profile-factors") }} <AppHint name="profile-factors-help" />
      </div>
      <div class="mt-2 flex flex-wrap gap-2">
        <button
          v-for="factor in OWN_FACTORS"
          :key="factor"
          type="button"
          class="sf-button"
          :disabled="previewing"
          @click="addFactor(factor)"
        >
          {{ say(`profile-factor-${factor}`) }}
        </button>
      </div>
      <p v-if="previewing" class="mt-2 text-xs text-muted">{{ say("profile-factors-preview") }}</p>
      <div v-if="factors" class="sf-list mt-3 divide-y divide-border text-xs">
        <p class="px-4 pt-3 pb-2 text-[11px] text-muted">{{ say("profile-factors-held") }}</p>
        <div v-for="app in factors.apps" :key="app.id" class="flex items-center gap-3 px-4 py-2.5">
          <span class="flex-1">
            <strong class="font-medium">{{ app.label || say(`profile-factor-kind-${app.kind}`) }}</strong>
            <span v-if="app.created_at" class="ml-2 text-muted">
              {{ say("profile-factor-added", { when: when(app.created_at) }) }}
            </span>
          </span>
          <AppHint v-if="app.kept_because" :text="app.kept_because" />
          <button
            type="button"
            class="sf-button"
            :disabled="previewing || app.kept_because !== null"
            @click="removeFactor(app.label || say(`profile-factor-kind-${app.kind}`), () => removeOwnApp(realm, app.id))"
          >
            {{ say("profile-factor-remove") }}
          </button>
        </div>
        <div v-for="key in factors.keys" :key="key.id" class="flex items-center gap-3 px-4 py-2.5">
          <span class="flex-1">
            <strong class="font-medium">{{ key.label || say("profile-factor-key") }}</strong>
            <span v-if="key.last_used_at" class="ml-2 text-muted">
              {{ say("profile-factor-used", { when: when(key.last_used_at) }) }}
            </span>
            <span v-else-if="key.enrolled_at" class="ml-2 text-muted">
              {{ say("profile-factor-added", { when: when(key.enrolled_at) }) }}
            </span>
          </span>
          <AppHint v-if="key.kept_because" :text="key.kept_because" />
          <button
            type="button"
            class="sf-button"
            :disabled="previewing || key.kept_because !== null"
            @click="removeFactor(key.label || say('profile-factor-key'), () => removeOwnKey(realm, key.id))"
          >
            {{ say("profile-factor-remove") }}
          </button>
        </div>
        <div v-if="factors.recovery_codes > 0" class="flex items-center gap-3 px-4 py-2.5">
          <span class="flex-1">
            <strong class="font-medium">
              {{ say("profile-factor-sheet", { count: String(factors.recovery_codes) }) }}
            </strong>
          </span>
          <button
            type="button"
            class="sf-button"
            :disabled="previewing"
            @click="removeFactor(say('profile-factor-sheet-named'), () => removeOwnRecoveryCodes(realm))"
          >
            {{ say("profile-factor-remove") }}
          </button>
        </div>
        <p v-if="!factors.apps.length && !factors.keys.length" class="px-4 py-3 text-muted">
          {{ say("profile-factors-none") }}
        </p>
      </div>
    </section>
  </div>
</template>
