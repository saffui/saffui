<script setup lang="ts">
// The build's catalogue of required actions, and what this realm registered
// of it. Rows can be turned, not invented: an action nobody compiled cannot
// be asked of anybody.
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import { listActions, registerAction, reworkAction } from "@/services/flows";
import type { RequiredActionRow } from "@/models/flows";

const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const registered = ref<RequiredActionRow[]>([]);
const failed = ref("");

/// What the engine compiled: slug, the provider that shows its screen, and
/// a worded name for the row that has not been registered yet.
const CATALOGUE = [
  { action: "update-password", provider: "password", title: "Update password" },
  { action: "reset-password", provider: "password", title: "Reset password" },
  { action: "verify-email", provider: "mail", title: "Verify email" },
  { action: "configure-totp", provider: "totp", title: "Configure authenticator app" },
  { action: "configure-webauthn", provider: "webauthn", title: "Configure passkey" },
] as const;

async function load() {
  failed.value = "";
  try {
    registered.value = await listActions(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

const rows = computed(() =>
  CATALOGUE.map((held) => ({
    ...held,
    row: registered.value.find((row) => row.action === held.action) ?? null,
  })),
);

async function enrol(held: (typeof CATALOGUE)[number]) {
  try {
    await registerAction(realm.value, {
      provider_id: held.provider,
      action: held.action,
      name: held.action,
      display_name: held.title,
      description: "",
      enabled: true,
      default_action: false,
      on_time_action: null,
      priority: (Math.max(0, ...registered.value.map((row) => row.priority ?? 0)) + 10) | 0,
    });
    await load();
  } catch {
    // The toast already said.
  }
}

async function rework(row: RequiredActionRow, reshape: Partial<RequiredActionRow>) {
  try {
    await reworkAction(realm.value, row.action, { ...row, ...reshape });
    await load();
  } catch {
    // The toast already said; the switch stays where the server left it.
  }
}
</script>

<template>
  <div>
    <div class="flex items-center gap-3">
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 text-xs text-muted hover:bg-surface-2"
        @click="router.push(`/${realm}/authentication`)"
      >
        &larr; {{ say("flows-title") }}
      </button>
      <h1 class="text-lg font-semibold tracking-tight">{{ say("actions-title") }}</h1>
    </div>
    <p class="mt-1 max-w-2xl text-xs text-muted">{{ say("actions-lede") }}</p>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("actions-col-what") }}</th>
            <th class="px-3 py-2 font-medium">
              {{ say("actions-col-enabled") }} <AppHint name="actions-enabled-help" />
            </th>
            <th class="px-3 py-2 font-medium">
              {{ say("actions-col-birth") }} <AppHint name="actions-birth-help" />
            </th>
            <th class="px-3 py-2 font-medium">{{ say("flow-priority") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="held in rows" :key="held.action" class="border-b border-border/60 last:border-0">
            <td class="px-3 py-2">
              <div class="font-medium">{{ held.row?.display_name || held.title }}</div>
              <code class="font-mono text-[10.5px] text-faint">{{ held.action }}</code>
            </td>
            <template v-if="held.row">
              <td class="px-3 py-2">
                <AppToggle
                  :model-value="held.row.enabled ?? false"
                  @update:model-value="rework(held.row!, { enabled: !(held.row!.enabled ?? false) })"
                />
              </td>
              <td class="px-3 py-2">
                <AppToggle
                  :model-value="held.row.default_action ?? false"
                  @update:model-value="
                    rework(held.row!, { default_action: !(held.row!.default_action ?? false) })
                  "
                />
              </td>
              <td class="px-3 py-2 font-mono text-[11px]">{{ held.row.priority ?? 0 }}</td>
            </template>
            <template v-else>
              <td class="px-3 py-2" colspan="2">
                <button
                  type="button"
                  class="rounded border border-border px-2 py-1 text-[11px] text-accent hover:bg-surface-2"
                  @click="enrol(held)"
                >
                  {{ say("actions-register") }}
                </button>
                <AppHint name="actions-register-help" />
              </td>
              <td class="px-3 py-2 text-[10.5px] text-faint">{{ say("actions-unregistered") }}</td>
            </template>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
