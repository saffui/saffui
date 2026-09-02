<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import { createUser, listUsers } from "@/services/users";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import type { Page } from "@/models/paging";
import type { UserBrief } from "@/models/user";
import UserDrawer from "./UserDrawer.vue";

const PAGE_SIZE = 25;
const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const first = ref(0);
const page = ref<Page<UserBrief> | null>(null);
const failed = ref("");

const opened = computed(() => {
  const asked = route.query.user;
  return typeof asked === "string" && asked !== "" ? asked : null;
});

async function load() {
  failed.value = "";
  try {
    page.value = await listUsers(realm.value, first.value, PAGE_SIZE);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
watch(first, load);

function fullName(user: UserBrief): string {
  return [user.given_name, user.family_name].filter(Boolean).join(" ");
}

function open(user: UserBrief) {
  router.replace({ query: { ...route.query, user: user.user_id } });
}
function close() {
  const { user: _, ...rest } = route.query;
  router.replace({ query: rest });
}

/// The birth drawer: identity now, authority later on the memberships tab.
const making = ref(false);
const REQUIRED_ACTIONS = [
  "update-password",
  "verify-email",
  "configure-totp",
  "configure-webauthn",
] as const;
const born = ref({
  user_name: "",
  email: "",
  given_name: "",
  family_name: "",
  phone_number: "",
  password: "",
  actions: ["verify-email"] as string[],
});
function flipAction(action: string) {
  born.value.actions = born.value.actions.includes(action)
    ? born.value.actions.filter((held) => held !== action)
    : [...born.value.actions, action];
}
async function makeUser() {
  const spec = born.value;
  if (!spec.user_name.trim()) return;
  try {
    const made = await createUser(realm.value, {
      user_name: spec.user_name.trim(),
      email: spec.email.trim() || undefined,
      given_name: spec.given_name.trim() || undefined,
      family_name: spec.family_name.trim() || undefined,
      phone_number: spec.phone_number.trim() || undefined,
      password: spec.password || undefined,
      required_actions: spec.actions,
    });
    making.value = false;
    born.value = {
      user_name: "",
      email: "",
      given_name: "",
      family_name: "",
      phone_number: "",
      password: "",
      actions: ["verify-email"],
    };
    await load();
    router.replace({ query: { ...route.query, user: made.user_id ?? spec.user_name.trim() } });
  } catch {
    // The toast already said.
  }
}

const shownTotal = computed(() => {
  const total = page.value?.total;
  return total === null || total === undefined ? "" : new Intl.NumberFormat().format(total);
});
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("users-title") }}</h1>
      <button
        type="button"
        class="ml-3 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        @click="making = true"
      >
        {{ say("user-new") }}
      </button>
      <span v-if="shownTotal" class="font-mono text-[11px] text-faint">{{ shownTotal }}</span>
    </div>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <div v-if="page" class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("users-col-username") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-email") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-name") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("users-col-state") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="user in page.items"
            :key="user.user_id"
            class="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-2"
            :class="opened === user.user_id && 'bg-surface-2'"
            @click="open(user)"
          >
            <td class="px-3 py-2 font-mono text-[11.5px]">{{ user.user_name }}</td>
            <td class="px-3 py-2">
              <span class="inline-flex items-center gap-1.5">
                {{ user.email }}
                <AppIcon
                  v-if="user.email_verified"
                  name="verified"
                  :size="12"
                  class="text-ok"
                  :title="say('users-email-verified')"
                />
              </span>
            </td>
            <td class="px-3 py-2 text-muted">{{ fullName(user) }}</td>
            <td class="px-3 py-2">
              <span
                v-if="!user.enabled"
                class="rounded border border-danger/40 px-1.5 py-0.5 text-[10.5px] text-danger"
                >{{ say("users-disabled") }}</span
              >
              <span
                v-else-if="user.required_actions.length"
                class="rounded border border-warn/40 px-1.5 py-0.5 text-[10.5px] text-warn"
                >{{ say("users-actions-pending", { count: user.required_actions.length }) }}</span
              >
              <span v-else class="text-[10.5px] text-faint">{{ say("users-active") }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="page" class="mt-3 flex items-center gap-2 text-[11px] text-muted">
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
        :disabled="first === 0"
        @click="first = Math.max(0, first - PAGE_SIZE)"
      >
        {{ say("paging-previous") }}
      </button>
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 hover:bg-surface-2 disabled:opacity-40"
        :disabled="page.items.length < PAGE_SIZE"
        @click="first = first + PAGE_SIZE"
      >
        {{ say("paging-next") }}
      </button>
      <span class="font-mono">{{ first + 1 }}&ndash;{{ first + page.items.length }}</span>
    </div>

    <AppDrawer
      v-if="making"
      :title="say('user-new')"
      :subtitle="realm"
      @close="making = false"
    >
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="makeUser">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("users-col-username") }} <AppHint name="user-username-help" />
          <input
            v-model="born.user_name"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
          />
        </label>
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("users-col-email") }}
            <input
              v-model="born.email"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-phone") }}
            <input
              v-model="born.phone_number"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-given") }}
            <input
              v-model="born.given_name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-family") }}
            <input
              v-model="born.family_name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("user-first-password") }} <AppHint name="user-first-password-help" />
          <input
            v-model="born.password"
            type="password"
            autocomplete="new-password"
            :placeholder="say('user-first-password-skip')"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <div>
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("user-ask-first") }} <AppHint name="user-required-actions-help" />
          </div>
          <div class="mt-1.5 flex flex-col gap-1.5">
            <AppToggle
              v-for="action in REQUIRED_ACTIONS"
              :key="action"
              :model-value="born.actions.includes(action)"
              @update:model-value="flipAction(action)"
            >
              <span class="font-mono text-[11px]">{{ action }}</span>
            </AppToggle>
          </div>
        </div>
        <p class="text-[10.5px] text-faint">{{ say("user-new-note") }}</p>
        <div>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("realm-create") }}
          </button>
        </div>
      </form>
    </AppDrawer>

    <UserDrawer v-if="opened" :realm="realm" :user-id="opened" @close="close" />
  </div>
</template>
