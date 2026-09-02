<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import { listUsers } from "@/services/users";
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

const shownTotal = computed(() => {
  const total = page.value?.total;
  return total === null || total === undefined ? "" : new Intl.NumberFormat().format(total);
});
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("users-title") }}</h1>
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
                <span
                  v-if="user.email_verified"
                  class="size-1.5 rounded-full bg-ok"
                  :title="say('users-email-verified')"
                ></span>
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

    <UserDrawer v-if="opened" :realm="realm" :user-id="opened" @close="close" />
  </div>
</template>
