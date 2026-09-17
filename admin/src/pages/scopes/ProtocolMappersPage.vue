<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, RouterLink } from "vue-router";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import { say } from "@/i18n";
import { afterWrites } from "@/services/writes";
import {
  createRealmMapper,
  deleteRealmMapper,
  listMapperKinds,
  listRealmMappers,
  updateRealmMapper,
  type ProtocolMapperWrite,
} from "@/services/scopes";
import {
  asJson,
  fieldsOf,
  fromJson,
  missing,
  readFlag,
  readText,
  switchesOf,
  writeFlag,
  writeText,
  type Kinds,
  type Switch,
} from "./mapperForm";
import type { AttributeValue, ProtocolMapper } from "@/models/client";

const route = useRoute();
const realm = () => String(route.params.realm);
const rows = ref<ProtocolMapper[]>([]);
const kinds = ref<Kinds>({ kinds: [], target_flags: [] });
const failed = ref("");
const editor = ref<ProtocolMapper | null>(null);
const editorOpen = ref(false);
// The text box is a second reading of the same bag, never a second copy.
const asText = ref(false);
const jsonText = ref("{}");
const jsonBad = ref(false);
const draft = ref({
  name: "",
  protocol: "openid-connect",
  mapper_type: "",
  configs: {} as Record<string, AttributeValue>,
});

const fields = computed(() => fieldsOf(kinds.value, draft.value.mapper_type));
const switches = computed(() => switchesOf(kinds.value, draft.value.mapper_type));
const refusals = computed(() => missing(kinds.value, draft.value.mapper_type, draft.value.configs));

async function load() {
  try {
    rows.value = await listRealmMappers(realm());
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function loadKinds() {
  try {
    kinds.value = await listMapperKinds(realm());
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

onMounted(async () => {
  await Promise.all([load(), loadKinds()]);
});
afterWrites(load);

function open(row?: ProtocolMapper) {
  editorOpen.value = true;
  asText.value = false;
  jsonBad.value = false;
  editor.value = row ?? null;
  draft.value = {
    name: row?.name ?? "",
    protocol: row?.protocol ?? "openid-connect",
    mapper_type: row?.mapper_type ?? (kinds.value.kinds[0]?.mapper_type ?? ""),
    configs: { ...row?.configs },
  };
}

/// Each key's explanation lives where every other string lives.
function hintOf(key: string): string {
  return `mapper-key-${key.replaceAll(".", "-")}-help`;
}

function textOf(key: string): string {
  return readText(draft.value.configs[key]);
}

/// An emptied box is a key nobody set, not a key set to nothing: the door
/// counts a present key as answered, so leaving it would hide what is absent.
function sayText(key: string, text: string) {
  if (text) draft.value.configs[key] = writeText(text);
  else delete draft.value.configs[key];
}

function flagOf(held: Switch): boolean {
  return readFlag(draft.value.configs[held.key], held.resting);
}

/// A switch left where the rule already rests is written nowhere, so the bag
/// keeps only what somebody actually decided.
function sayFlag(held: Switch, on: boolean) {
  if (on === held.resting) delete draft.value.configs[held.key];
  else draft.value.configs[held.key] = writeFlag(on);
}

function drop(key: string) {
  delete draft.value.configs[key];
}

function showJson() {
  jsonText.value = asJson(draft.value.configs);
  jsonBad.value = false;
  asText.value = true;
}

function readJson(text: string) {
  jsonText.value = text;
  const read = fromJson(text);
  jsonBad.value = read === null;
  if (read) draft.value.configs = read;
}

/// What the door would refuse, said in the reader's tongue. The door stays the
/// authority; this only spares the trip.
function wordRefusal(said: string): string {
  const cut = said.indexOf(":");
  const rest = said.slice(cut + 1);
  if (said.startsWith("missing:")) return say("mappers-need-key", { key: rest });
  if (said.startsWith("unknown:")) return say("mappers-unknown-key", { key: rest });
  return say("mappers-one-of-keys", { keys: rest.split(",").join(", ") });
}

/// A key this kind never reads has no field of its own, so without this the
/// only way out would be the JSON box.
function strayOf(said: string): string {
  return said.startsWith("unknown:") ? said.slice("unknown:".length) : "";
}

async function save() {
  if (asText.value && jsonBad.value) {
    failed.value = say("mappers-config-invalid");
    return;
  }
  const body: ProtocolMapperWrite = {
    name: draft.value.name,
    protocol: draft.value.protocol,
    mapper_type: draft.value.mapper_type,
    configs: draft.value.configs,
  };
  if (!body.name.trim()) return;
  try {
    if (editor.value) await updateRealmMapper(realm(), editor.value.mapper_id, body);
    else await createRealmMapper(realm(), body);
    editor.value = null;
    editorOpen.value = false;
    failed.value = "";
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
      <RouterLink :to="`/${realm()}/client-scopes`" class="text-xs text-muted hover:text-ink">{{ say("scopes-title") }}</RouterLink>
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
        <label class="text-[11px] font-medium text-muted">{{ say("mappers-col-name") }} <AppHint name="mappers-col-name-help" /><input v-model="draft.name" class="sf-field mt-1 font-mono" /></label>
        <label class="text-[11px] font-medium text-muted">{{ say("mappers-col-protocol") }} <AppHint name="mappers-col-protocol-help" /><select v-model="draft.protocol" class="sf-field mt-1 font-mono"><option value="openid-connect">openid-connect</option></select></label>
        <label class="text-[11px] font-medium text-muted sm:col-span-2">{{ say("mappers-col-type") }} <AppHint name="mappers-col-type-help" /><select v-model="draft.mapper_type" class="sf-field mt-1 font-mono"><option v-for="kind in kinds.kinds" :key="kind.mapper_type" :value="kind.mapper_type">{{ kind.mapper_type }}</option></select></label>

        <div class="sm:col-span-2 rounded-md border border-border/60 p-3">
          <div class="flex flex-wrap items-center gap-3">
            <span class="text-[11px] font-medium text-muted">{{ say("mappers-fields") }} <AppHint name="mappers-fields-help" /></span>
            <button type="button" class="ml-auto text-xs text-accent hover:underline" @click="asText ? (asText = false) : showJson()">{{ asText ? say("mappers-json-close") : say("mappers-json-open") }}</button>
          </div>
          <template v-if="asText">
            <p class="mt-2 text-[10.5px] text-muted">{{ say("mappers-json-lede") }}</p>
            <textarea :value="jsonText" rows="8" class="sf-field mt-2 w-full font-mono text-[11px]" spellcheck="false" @input="readJson(($event.target as HTMLTextAreaElement).value)" />
            <p v-if="jsonBad" class="mt-1 text-[10.5px] text-danger" role="alert">{{ say("mappers-config-invalid") }}</p>
          </template>
          <template v-else>
            <p v-if="!fields.length && !switches.length" class="mt-2 text-[10.5px] text-muted">{{ say("mappers-fields-none") }}</p>
            <div v-if="fields.length" class="mt-2 grid gap-3 sm:grid-cols-2">
              <label v-for="field in fields" :key="field.key" class="text-[11px] font-medium text-muted">
                <span class="font-mono">{{ field.key }}</span> <AppHint :name="hintOf(field.key)" />
                <span v-if="field.required || field.alternative" class="ml-1 text-[9.5px] text-faint uppercase">{{ say("mappers-required-mark") }}</span>
                <input :value="textOf(field.key)" class="sf-field mt-1 font-mono" @input="sayText(field.key, ($event.target as HTMLInputElement).value)" />
              </label>
            </div>
            <div v-if="switches.length" class="mt-3 flex flex-col gap-2">
              <AppToggle v-for="held in switches" :key="held.key" :model-value="flagOf(held)" @update:model-value="sayFlag(held, $event)">
                <span class="font-mono">{{ held.key }}</span> <AppHint :name="hintOf(held.key)" />
              </AppToggle>
            </div>
          </template>
        </div>

        <div v-if="!asText" class="sm:col-span-2 rounded-md border border-border/60 p-3">
          <span class="text-[11px] font-medium text-muted">{{ say("mappers-where") }} <AppHint name="mappers-where-help" /></span>
          <div class="mt-2 flex flex-wrap gap-4">
            <AppToggle v-for="flag in kinds.target_flags" :key="flag.key" :model-value="flagOf(flag)" @update:model-value="sayFlag(flag, $event)">
              <span class="font-mono">{{ flag.key }}</span> <AppHint :name="hintOf(flag.key)" />
            </AppToggle>
          </div>
        </div>

        <ul v-if="refusals.length" class="sm:col-span-2 flex flex-col gap-1">
          <li v-for="said in refusals" :key="said" class="flex items-center gap-2 text-[10.5px] text-danger">
            <span>{{ wordRefusal(said) }}</span>
            <button v-if="strayOf(said)" type="button" class="text-[10.5px] text-muted hover:text-ink hover:underline" @click="drop(strayOf(said))">{{ say("action-remove") }}</button>
          </li>
        </ul>

        <button type="submit" class="sf-button sf-button-primary sm:col-span-2">{{ editor ? say("settings-save") : say("realm-create") }}</button>
      </form>
    </div>
  </div>
</template>
