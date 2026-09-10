<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute, RouterLink } from "vue-router";
import { say } from "@/i18n";
import { afterWrites } from "@/services/writes";
import { createRealmMapper, deleteRealmMapper, listRealmMappers, updateRealmMapper, type ProtocolMapperWrite } from "@/services/scopes";
import type { ProtocolMapper } from "@/models/client";

const route = useRoute();
const realm = () => String(route.params.realm);
const rows = ref<ProtocolMapper[]>([]);
const failed = ref("");
const editor = ref<ProtocolMapper | null>(null);
const editorOpen = ref(false);
const draft = ref({ name: "", protocol: "openid-connect", mapper_type: "oidc-usermodel-property-mapper", configs: "{}" });
const types = [
  "oidc-usermodel-property-mapper",
  "oidc-usermodel-attribute-mapper",
  "oidc-full-name-mapper",
  "oidc-usermodel-realm-role-mapper",
  "oidc-usermodel-client-role-mapper",
  "oidc-audience-mapper",
];

async function load() {
  try {
    rows.value = await listRealmMappers(realm());
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

function open(row?: ProtocolMapper) {
  editorOpen.value = true;
  editor.value = row ?? null;
  draft.value = row
    ? { name: row.name, protocol: row.protocol, mapper_type: row.mapper_type, configs: "{}" }
    : { name: "", protocol: "openid-connect", mapper_type: types[0], configs: "{}" };
}

async function save() {
  let configs: Record<string, unknown> | null;
  try {
    configs = JSON.parse(draft.value.configs) as Record<string, unknown>;
  } catch {
    failed.value = say("mappers-config-invalid");
    return;
  }
  const body: ProtocolMapperWrite = { ...draft.value, configs };
  if (!body.name.trim()) return;
  try {
    if (editor.value) await updateRealmMapper(realm(), editor.value.mapper_id, body);
    else await createRealmMapper(realm(), body);
    editor.value = null;
    editorOpen.value = false;
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function remove(row: ProtocolMapper) {
  try {
    await deleteRealmMapper(realm(), row.mapper_id);
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("mappers-title") }}</h1>
        <p class="mt-1 text-xs text-muted">{{ say("mappers-lede") }}</p>
      </div>
      <RouterLink :to="`/${realm}/client-scopes`" class="text-xs text-muted hover:text-ink">{{ say("scopes-title") }}</RouterLink>
      <button type="button" class="sf-button sf-button-primary ml-auto" @click="open()">{{ say("mappers-new") }}</button>
    </div>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>
    <div class="sf-list mt-4 overflow-x-auto">
      <table class="sf-table">
        <thead><tr><th>{{ say("mappers-col-name") }}</th><th>{{ say("mappers-col-type") }}</th><th>{{ say("mappers-col-protocol") }}</th><th></th></tr></thead>
        <tbody>
          <tr v-for="row in rows" :key="row.mapper_id" class="border-b border-border/60 last:border-0">
            <td class="font-mono text-[11px]">{{ row.name }}</td>
            <td class="font-mono text-[10.5px] text-muted">{{ row.mapper_type }}</td>
            <td class="font-mono text-[10.5px] text-muted">{{ row.protocol }}</td>
            <td class="text-right whitespace-nowrap">
              <button type="button" class="text-xs text-accent hover:underline" @click="open(row)">{{ say("authz-route-edit") }}</button>
              <button type="button" class="ml-3 text-xs text-danger hover:underline" @click="remove(row)">{{ say("authz-route-delete") }}</button>
            </td>
          </tr>
          <tr v-if="!rows.length"><td colspan="4" class="text-muted">{{ say("mappers-none") }}</td></tr>
        </tbody>
      </table>
    </div>
    <div v-if="editorOpen" class="mt-4 rounded-lg border border-border bg-surface p-4">
      <div class="flex items-center justify-between"><h2 class="text-sm font-semibold">{{ editor ? say("mappers-edit") : say("mappers-new") }}</h2><button type="button" class="text-xs text-muted" @click="editorOpen = false">×</button></div>
      <form class="mt-3 grid gap-3 sm:grid-cols-2" @submit.prevent="save">
        <label class="text-[11px] font-medium text-muted">{{ say("mappers-col-name") }}<input v-model="draft.name" class="sf-field mt-1 font-mono" /></label>
        <label class="text-[11px] font-medium text-muted">{{ say("mappers-col-protocol") }}<select v-model="draft.protocol" class="sf-field mt-1 font-mono"><option value="openid-connect">openid-connect</option></select></label>
        <label class="text-[11px] font-medium text-muted sm:col-span-2">{{ say("mappers-col-type") }}<select v-model="draft.mapper_type" class="sf-field mt-1 font-mono"><option v-for="type in types" :key="type" :value="type">{{ type }}</option></select></label>
        <label class="text-[11px] font-medium text-muted sm:col-span-2">{{ say("mappers-config") }}<textarea v-model="draft.configs" rows="6" class="sf-field mt-1 font-mono text-[11px]" spellcheck="false" /></label>
        <button type="submit" class="sf-button sf-button-primary sm:col-span-2">{{ editor ? say("settings-save") : say("realm-create") }}</button>
      </form>
    </div>
  </div>
</template>
