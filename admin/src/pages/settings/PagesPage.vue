<script setup lang="ts">
// What the realm says over the hosted pages' own words: per tongue, per key.
// The catalogue is the build's; a realm can reword a page, never invent one.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { getRealmSettings, listPageKeys, reshapeRealm, type PageKey } from "@/services/settings";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const keys = ref<PageKey[]>([]);
const failed = ref("");
const tongue = ref<"en" | "fr">("en");
/// tongue -> key -> the realm's wording. Empty string means nothing said.
const spoken = ref<Record<string, Record<string, string>>>({ en: {}, fr: {} });
const filter = ref("");

onMounted(async () => {
  try {
    const [catalogue, settings] = await Promise.all([
      listPageKeys(realm.value),
      getRealmSettings(realm.value),
    ]);
    keys.value = catalogue.keys;
    const held = (settings.page_overrides ?? {}) as Record<string, Record<string, string>>;
    spoken.value = { en: { ...held.en }, fr: { ...held.fr } };
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

const shown = computed(() => {
  const needle = filter.value.trim().toLowerCase();
  if (!needle) return keys.value;
  return keys.value.filter(
    (row) =>
      row.name.includes(needle) ||
      row.en.toLowerCase().includes(needle) ||
      row.fr.toLowerCase().includes(needle),
  );
});

function built(row: PageKey): string {
  return tongue.value === "en" ? row.en : row.fr;
}

const saidCount = computed(
  () =>
    Object.values(spoken.value.en).filter(Boolean).length +
    Object.values(spoken.value.fr).filter(Boolean).length,
);

async function save() {
  const packed: Record<string, Record<string, string>> = {};
  for (const held of ["en", "fr"] as const) {
    const words: Record<string, string> = {};
    for (const [name, value] of Object.entries(spoken.value[held])) {
      if (value.trim()) words[name] = value.trim();
    }
    if (Object.keys(words).length) packed[held] = words;
  }
  try {
    await reshapeRealm(
      realm.value,
      { page_overrides: Object.keys(packed).length ? packed : null },
      say("pages-subject"),
    );
  } catch {
    // The toast already said; an unknown key cannot happen from this editor.
  }
}
</script>

<template>
  <div>
    <div class="flex items-center gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("pages-title") }}</h1>
      <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">{{
        say("pages-said", { count: saidCount })
      }}</span>
      <div class="ml-auto flex items-center gap-2">
        <a
          :href="`/realms/${realm}/protocol/openid-connect/login`"
          target="_blank"
          rel="noopener"
          class="rounded-md border border-border px-2.5 py-1 text-xs text-muted hover:bg-surface-2"
        >
          {{ say("pages-open") }}
        </a>
        <button
          type="button"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          @click="save"
        >
          {{ say("settings-save") }}
        </button>
      </div>
    </div>
    <p class="mt-1 max-w-2xl text-xs text-muted">
      {{ say("pages-lede") }} <AppHint name="pages-lede-help" />
    </p>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 flex items-center gap-2">
      <div class="flex overflow-hidden rounded-md border border-border text-xs">
        <button
          v-for="held in ['en', 'fr'] as const"
          :key="held"
          type="button"
          class="px-3 py-1.5 font-mono"
          :class="
            tongue === held ? 'bg-surface-2 font-semibold text-ink' : 'text-muted hover:bg-surface'
          "
          @click="tongue = held"
        >
          {{ held }}
        </button>
      </div>
      <input
        v-model="filter"
        :placeholder="say('palette-filter')"
        class="w-64 rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
        spellcheck="false"
      />
    </div>

    <div class="mt-3 overflow-x-auto rounded-lg border border-border bg-surface">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="w-56 px-3 py-2 font-medium">{{ say("pages-col-key") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("pages-col-built") }}</th>
            <th class="px-3 py-2 font-medium">
              {{ say("pages-col-spoken") }} <AppHint name="pages-spoken-help" />
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in shown" :key="row.name" class="border-b border-border/60 last:border-0">
            <td class="px-3 py-2 align-top">
              <code class="font-mono text-[10.5px]">{{ row.name }}</code>
            </td>
            <td class="max-w-96 px-3 py-2 align-top text-[11px] text-muted">{{ built(row) }}</td>
            <td class="px-3 py-2">
              <input
                v-model="spoken[tongue][row.name]"
                :placeholder="say('pages-unspoken')"
                class="w-full rounded-md border border-border bg-surface-2 px-2 py-1 text-[11px] text-ink"
                :class="spoken[tongue][row.name]?.trim() && 'border-accent/50'"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
