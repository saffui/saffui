<script setup lang="ts">
import { computed, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import AppToggle from "@/components/AppToggle.vue";
import { say } from "@/i18n";
import type { DirectoryImportReport, DirectoryRow } from "@/models/federation";
import { deleteDirectory, importDirectory, putDirectory } from "@/services/federation";
import {
  directoryDraft,
  directoryIsWritable,
  directoryMutation,
  emptyDirectoryDraft,
} from "./directoryForms";

const props = defineProps<{ realm: string; row?: DirectoryRow }>();
const emit = defineEmits<{ close: []; saved: []; deleted: [] }>();

const draft = ref(props.row ? directoryDraft(props.row) : emptyDirectoryDraft());
const doomName = ref("");
const saving = ref(false);
const importing = ref(false);
const report = ref<DirectoryImportReport | null>(null);
const alias = computed(() => props.row?.alias ?? draft.value.alias.trim());
const writable = computed(() => directoryIsWritable(draft.value));

async function save() {
  if (!writable.value || !alias.value) return;
  saving.value = true;
  try {
    await putDirectory(props.realm, alias.value, directoryMutation(draft.value));
    emit("saved");
  } catch {
    // The toast carries the refusal.
  } finally {
    saving.value = false;
  }
}

async function importEveryone() {
  if (!props.row) return;
  importing.value = true;
  try {
    report.value = await importDirectory(props.realm, props.row.alias);
  } catch {
    // The toast carries the refusal.
  } finally {
    importing.value = false;
  }
}

async function drop() {
  if (!props.row || doomName.value !== props.row.alias) return;
  try {
    await deleteDirectory(props.realm, props.row.alias);
    emit("deleted");
  } catch {
    // The toast carries the refusal.
  }
}
</script>

<template>
  <AppDrawer
    :title="props.row?.alias || say('directory-new')"
    subtitle="LDAP"
    @close="emit('close')"
  >
    <form class="min-w-0 space-y-4 text-xs" @submit.prevent="save">
      <section class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_110px]">
        <label class="min-w-0 text-[11px] font-medium text-muted">
          {{ say("connector-alias") }}
          <input
            v-model="draft.alias"
            required
            :disabled="Boolean(props.row)"
            spellcheck="false"
            class="sf-field mt-1 font-mono disabled:opacity-60"
          />
        </label>
        <label class="min-w-0 text-[11px] font-medium text-muted">
          {{ say("federation-priority") }}
          <input v-model.number="draft.priority" type="number" class="sf-field mt-1 font-mono" />
        </label>
        <AppToggle v-model="draft.enabled">{{ say("connector-enabled") }}</AppToggle>
      </section>

      <section class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("directory-connection") }}
        </h3>
        <div class="mt-3 grid gap-3">
          <label class="min-w-0 text-[11px] font-medium text-muted">
            {{ say("directory-url") }}
            <input
              v-model="draft.url"
              required
              spellcheck="false"
              placeholder="ldaps://directory.example:636"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <div v-if="draft.url.trim().startsWith('ldap://')" class="rounded border border-warn/40 p-2">
            <AppToggle v-model="draft.dangerPlaintext">{{ say("directory-plaintext") }}</AppToggle>
          </div>
          <label class="min-w-0 text-[11px] font-medium text-muted">
            {{ say("directory-bind-dn") }}
            <input v-model="draft.bindDn" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="min-w-0 text-[11px] font-medium text-muted">
            {{ say("directory-bind-password") }}
            <input
              v-model="draft.bindPassword"
              type="password"
              autocomplete="new-password"
              :placeholder="props.row ? say('directory-secret-kept') : ''"
              class="sf-field mt-1 font-mono"
            />
            <span v-if="props.row" class="mt-1 block font-normal text-faint">
              {{ say("directory-secret-scope") }}
            </span>
          </label>
          <label class="min-w-0 text-[11px] font-medium text-muted">
            {{ say("directory-users-dn") }}
            <input v-model="draft.usersDn" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="min-w-0 text-[11px] font-medium text-muted">
            {{ say("directory-user-filter") }}
            <input v-model="draft.userFilter" required spellcheck="false" class="sf-field mt-1 font-mono" />
            <span class="mt-1 block font-normal text-faint">{{ say("directory-filter-hint") }}</span>
          </label>
        </div>
      </section>

      <section class="border-t border-border pt-4">
        <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("directory-attributes") }}
        </h3>
        <div class="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <label v-for="field in [
            ['usernameAttribute', 'directory-username-attribute'],
            ['emailAttribute', 'directory-email-attribute'],
            ['firstNameAttribute', 'directory-first-name-attribute'],
            ['lastNameAttribute', 'directory-last-name-attribute'],
          ] as const" :key="field[0]" class="min-w-0 text-[11px] font-medium text-muted">
            {{ say(field[1]) }}
            <input v-model="draft[field[0]]" required spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
        </div>
      </section>

      <p v-if="!writable" class="text-[11px] text-warn" role="alert">
        {{ say("directory-invalid") }}
      </p>
      <button type="submit" :disabled="saving || !writable" class="sf-button sf-button-primary">
        {{ say("settings-save") }}
      </button>
    </form>

    <section v-if="props.row" class="mt-5 border-t border-border pt-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("directory-import-title") }}
          </h3>
          <p class="mt-1 max-w-[44ch] text-[11px] leading-4 text-muted">
            {{ say("directory-import-lede") }}
          </p>
        </div>
        <button
          type="button"
          :disabled="importing || props.row.enabled === false"
          class="sf-button sf-button-secondary"
          @click="importEveryone"
        >
          {{ say(importing ? "directory-importing" : "directory-import") }}
        </button>
      </div>
      <dl v-if="report" class="mt-3 grid grid-cols-3 gap-2 text-center">
        <div v-for="fact in [
          [say('directory-import-walked'), report.walked],
          [say('directory-import-added'), report.imported],
          [say('directory-import-refreshed'), report.refreshed],
        ]" :key="String(fact[0])" class="rounded border border-border p-2">
          <dt class="text-[10px] text-faint">{{ fact[0] }}</dt>
          <dd class="mt-0.5 font-mono text-sm text-ink">{{ fact[1] }}</dd>
        </div>
      </dl>
    </section>

    <section v-if="props.row" class="mt-5 border-t border-danger/40 pt-4">
      <h3 class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
        {{ say("settings-danger") }}
      </h3>
      <p class="mt-1 text-[11px] leading-4 text-muted">{{ say("directory-delete-lede") }}</p>
      <div class="mt-2 flex min-w-0 gap-2">
        <input v-model="doomName" :placeholder="props.row.alias" class="min-w-0 flex-1 sf-field font-mono" />
        <button
          type="button"
          :disabled="doomName !== props.row.alias"
          class="sf-button sf-button-danger"
          @click="drop"
        >
          {{ say("directory-delete") }}
        </button>
      </div>
    </section>
  </AppDrawer>
</template>
