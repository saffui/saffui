<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { forgetRealmTheme, getRealmTheme, writeRealmTheme } from "@/services/settings";

// The fifteen token names the hosted pages read: the whole contract, in the
// stylesheet's own order. The server refuses anything else whole.
const TOKENS = [
  "brand-primary",
  "brand-on-primary",
  "bg",
  "surface",
  "ink",
  "muted",
  "border",
  "danger",
  "radius",
  "font-sans",
  "card-border-width",
  "card-shadow",
  "logo-display",
  "logo-radius",
  "field-bg",
] as const;

const HALVES = ["light", "dark"] as const;
type Half = (typeof HALVES)[number];

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const half = ref<Half>("light");
const held = reactive<Record<Half, Record<string, string>>>({ light: {}, dark: {} });
const failed = ref("");
const saved = ref(false);
const worn = ref(false);

onMounted(async () => {
  try {
    const theme = await getRealmTheme(realm.value);
    if (theme) {
      worn.value = true;
      Object.assign(held.light, theme.light ?? {});
      Object.assign(held.dark, theme.dark ?? {});
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

function pruned(half_: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(half_).filter(([, value]) => value.trim() !== ""),
  );
}

async function save() {
  failed.value = "";
  saved.value = false;
  const asked: { light?: Record<string, string>; dark?: Record<string, string> } = {};
  const light = pruned(held.light);
  const dark = pruned(held.dark);
  if (Object.keys(light).length) asked.light = light;
  if (Object.keys(dark).length) asked.dark = dark;
  try {
    await writeRealmTheme(realm.value, asked);
    worn.value = true;
    saved.value = true;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function undress() {
  await forgetRealmTheme(realm.value);
  held.light = {};
  held.dark = {};
  worn.value = false;
  saved.value = false;
}

// A small living sample: the login card, wearing exactly what is typed.
const sample = computed(() => {
  const values = held[half.value];
  return {
    background: values["bg"] || (half.value === "dark" ? "#131316" : "#f4f4f5"),
    card: values["surface"] || (half.value === "dark" ? "#1c1c21" : "#ffffff"),
    ink: values["ink"] || (half.value === "dark" ? "#e8e8ec" : "#18181b"),
    border: values["border"] || (half.value === "dark" ? "#3a3a42" : "#d4d4d8"),
    accent: values["brand-primary"] || (half.value === "dark" ? "#e4e4e7" : "#18181b"),
    onAccent: values["brand-on-primary"] || (half.value === "dark" ? "#18181b" : "#ffffff"),
    radius: values["radius"] || "8px",
  };
});
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("theme-title") }}</h1>
      <div class="flex items-center gap-2">
        <button
          type="button"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          @click="save"
        >
          {{ say("settings-save") }}
        </button>
        <button
          v-if="worn"
          type="button"
          class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface-2"
          @click="undress"
        >
          {{ say("theme-undress") }}
        </button>
        <span v-if="saved" class="text-[11px] text-ok">{{ say("settings-saved") }}</span>
      </div>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("theme-lede") }}</p>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 flex flex-wrap gap-6">
      <div class="min-w-72 flex-1">
        <div class="flex gap-1">
          <button
            v-for="which in HALVES"
            :key="which"
            type="button"
            class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
            :class="half === which && 'bg-surface-2 font-medium text-ink'"
            @click="half = which"
          >
            {{ say(`theme-half-${which}`) }}
          </button>
        </div>
        <div class="mt-3 grid max-w-md gap-2">
          <label
            v-for="token in TOKENS"
            :key="token"
            class="grid grid-cols-[150px_1fr] items-center gap-2 text-xs"
          >
            <span class="font-mono text-[10.5px] text-muted">--{{ token }}</span>
            <input
              v-model="held[half][token]"
              class="rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-[11px] text-ink"
              spellcheck="false"
              :placeholder="say('theme-inherit')"
            />
          </label>
        </div>
      </div>

      <div class="w-72 shrink-0">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("theme-sample") }}
        </div>
        <div
          class="mt-2 grid h-64 place-items-center rounded-lg border border-border"
          :style="{ background: sample.background }"
        >
          <div
            class="w-52 p-4"
            :style="{
              background: sample.card,
              color: sample.ink,
              border: `1px solid ${sample.border}`,
              borderRadius: sample.radius,
            }"
          >
            <div class="text-sm font-semibold">{{ say("theme-sample-title") }}</div>
            <div
              class="mt-2 h-7 rounded"
              :style="{ background: sample.background, border: `1px solid ${sample.border}` }"
            ></div>
            <div
              class="mt-2 grid h-7 place-items-center text-xs font-semibold"
              :style="{
                background: sample.accent,
                color: sample.onAccent,
                borderRadius: `calc(${sample.radius} * 0.75)`,
              }"
            >
              {{ say("login-continue") }}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
