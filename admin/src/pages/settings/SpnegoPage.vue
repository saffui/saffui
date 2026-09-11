<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import { say } from "@/i18n";
import { ApiError } from "@/services/http";
import { deleteSpnego, getSpnego, putSpnego, type SpnegoRow } from "@/services/negotiation";
import { afterWrites } from "@/services/writes";
import { spnegoDraft, spnegoIsWritable, spnegoMutation, type SpnegoDraft } from "./spnegoForms";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const row = ref<SpnegoRow | null>(null);
const draft = ref<SpnegoDraft>(spnegoDraft(null));
const failed = ref("");
const loading = ref(true);
const saving = ref(false);

async function load() {
  loading.value = true;
  failed.value = "";
  try {
    row.value = await getSpnego(realm.value);
    draft.value = spnegoDraft(row.value);
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) {
      row.value = null;
      draft.value = spnegoDraft(null);
    } else failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    loading.value = false;
  }
}
onMounted(load);
afterWrites(load);

async function save() {
  if (!spnegoIsWritable(draft.value)) return;
  saving.value = true;
  failed.value = "";
  try {
    row.value = await putSpnego(realm.value, spnegoMutation(draft.value));
    draft.value = spnegoDraft(row.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    saving.value = false;
  }
}

async function remove() {
  if (!window.confirm(say("spnego-delete-confirm"))) return;
  failed.value = "";
  try {
    await deleteSpnego(realm.value);
    row.value = null;
    draft.value = spnegoDraft(null);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
</script>

<template>
  <div class="max-w-3xl">
    <h1 class="text-lg font-semibold tracking-tight">{{ say("spnego-title") }}</h1>
    <p class="mt-1 text-xs leading-5 text-muted">{{ say("spnego-lede") }}</p>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>
    <div v-if="!loading" class="mt-5 rounded-lg border border-border bg-surface p-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">{{ say("spnego-door") }}</h2>
          <p class="mt-1 text-xs text-muted">{{ row ? say("spnego-configured") : say("spnego-unconfigured") }}</p>
        </div>
        <span v-if="row" :class="row.enabled === false ? 'text-danger' : 'text-ok'" class="text-[11px]">
          {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
        </span>
      </div>
      <form class="mt-5 flex flex-col gap-4 text-xs" @submit.prevent="save">
        <AppToggle v-model="draft.enabled">{{ say("spnego-enabled") }}</AppToggle>
        <label class="text-[11px] font-medium text-muted">
          {{ say("spnego-principal") }} <AppHint name="spnego-principal-help" />
          <input v-model="draft.servicePrincipal" required spellcheck="false" placeholder="HTTP/id.example@EXAMPLE.ORG" class="sf-field mt-1 font-mono" />
          <span class="mt-1 block font-normal text-faint">{{ say("spnego-principal-hint") }}</span>
        </label>
        <p v-if="!spnegoIsWritable(draft)" class="text-[11px] text-warn" role="alert">{{ say("spnego-invalid") }}</p>
        <button type="submit" :disabled="saving || !spnegoIsWritable(draft)" class="self-start sf-button sf-button-primary">
          {{ say("settings-save") }}
        </button>
      </form>
    </div>
    <div v-if="row" class="mt-5 rounded-lg border border-danger/40 p-4">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">{{ say("settings-danger") }}</h2>
      <p class="mt-1 text-[11px] leading-4 text-muted">{{ say("spnego-delete-lede") }}</p>
      <button type="button" class="mt-3 sf-button sf-button-danger" @click="remove">{{ say("spnego-delete") }}</button>
    </div>
  </div>
</template>
