<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { forgetRealmTheme, getRealmTheme, writeRealmTheme } from "@/services/settings";
import AppearanceTabs from "./AppearanceTabs.vue";
import {
  COLOR_TOKENS,
  DETAIL_TOKENS,
  effective,
  emptyTheme,
  invalidThemeToken,
  THEME_DEFAULTS,
  themeDocument,
  type ThemeHalf,
  type ThemeToken,
} from "./themeForm";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const half = ref<ThemeHalf>("light");
const held = ref(emptyTheme());
const failed = ref("");
const worn = ref(false);
const saving = ref(false);

onMounted(async () => {
  try {
    const theme = await getRealmTheme(realm.value);
    held.value = emptyTheme(theme ?? undefined);
    worn.value = theme !== null;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

const overrideCount = computed(
  () =>
    Object.values(held.value.light).filter((value) => value?.trim()).length +
    Object.values(held.value.dark).filter((value) => value?.trim()).length,
);

function shown(token: ThemeToken): string {
  return effective(held.value, half.value, token);
}

function colorValue(token: ThemeToken): string {
  const value = shown(token);
  return /^#[0-9a-f]{6}$/i.test(value) ? value : THEME_DEFAULTS[half.value][token];
}

function pickColor(token: ThemeToken, event: Event) {
  held.value[half.value][token] = (event.target as HTMLInputElement).value.toUpperCase();
}

async function save() {
  failed.value = "";
  const invalid = invalidThemeToken(held.value);
  if (invalid) {
    half.value = invalid.half;
    failed.value = say("theme-invalid", {
      token: invalid.token,
      half: say(`theme-half-${invalid.half}`),
    });
    return;
  }

  saving.value = true;
  try {
    await writeRealmTheme(realm.value, themeDocument(held.value));
    worn.value = true;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    saving.value = false;
  }
}

async function undress() {
  failed.value = "";
  try {
    await forgetRealmTheme(realm.value);
    held.value = emptyTheme();
    worn.value = false;
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

const sample = computed(() => ({
  accent: shown("brand-primary"),
  background: shown("bg"),
  border: shown("border"),
  borderWidth: shown("card-border-width"),
  card: shown("surface"),
  danger: shown("danger"),
  field: shown("field-bg"),
  font: shown("font-sans"),
  ink: shown("ink"),
  logoDisplay: shown("logo-display"),
  logoRadius: shown("logo-radius"),
  muted: shown("muted"),
  onAccent: shown("brand-on-primary"),
  radius: shown("radius"),
  shadow: shown("card-shadow"),
}));
</script>

<template>
  <div>
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <div class="flex flex-wrap items-center gap-2">
          <h1 class="text-lg font-semibold tracking-tight">{{ say("theme-title") }}</h1>
          <span class="sf-badge">{{ say("theme-overrides", { count: overrideCount }) }}</span>
        </div>
        <p class="mt-1 max-w-2xl text-xs leading-5 text-muted">{{ say("theme-lede") }}</p>
      </div>
      <div class="flex items-center gap-2">
        <button
          v-if="worn"
          type="button"
          class="sf-button sf-button-danger"
          @click="undress"
        >
          {{ say("theme-undress") }}
        </button>
        <button
          type="button"
          class="sf-button sf-button-primary"
          :disabled="saving"
          @click="save"
        >
          {{ say("settings-save") }}
        </button>
      </div>
    </div>

    <AppearanceTabs class="mt-4" current="theme" />
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-5 grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
      <div class="min-w-0 space-y-5">
        <div class="inline-flex rounded-md border border-border bg-surface p-0.5" role="tablist">
          <button
            v-for="which in ['light', 'dark'] as const"
            :key="which"
            type="button"
            role="tab"
            :aria-selected="half === which"
            class="min-w-24 rounded px-3 py-1.5 text-xs"
            :class="half === which ? 'bg-surface-2 font-medium text-ink' : 'text-muted hover:text-ink'"
            @click="half = which"
          >
            {{ say(`theme-half-${which}`) }}
          </button>
        </div>

        <section class="rounded-lg border border-border bg-surface p-4">
          <h2 class="text-sm font-semibold text-ink">{{ say("theme-colors") }}</h2>
          <p class="mt-1 text-[11px] leading-4 text-muted">{{ say("theme-colors-help") }}</p>
          <div class="mt-4 grid gap-x-5 gap-y-3 md:grid-cols-2">
            <label
              v-for="field in COLOR_TOKENS"
              :key="field.token"
              class="grid min-w-0 grid-cols-[36px_minmax(0,1fr)] items-end gap-2"
            >
              <input
                type="color"
                :value="colorValue(field.token)"
                :aria-label="say(field.label)"
                class="h-8 w-9 cursor-pointer rounded border border-border bg-transparent p-0.5"
                @input="pickColor(field.token, $event)"
              />
              <span class="min-w-0 text-[11px] font-medium text-muted">
                {{ say(field.label) }}
                <input
                  v-model="held[half][field.token]"
                  spellcheck="false"
                  :placeholder="shown(field.token)"
                  class="mt-1 w-full sf-field font-mono text-[11px]"
                />
              </span>
            </label>
          </div>
        </section>

        <section class="rounded-lg border border-border bg-surface p-4">
          <h2 class="text-sm font-semibold text-ink">{{ say("theme-layout") }}</h2>
          <p class="mt-1 text-[11px] leading-4 text-muted">{{ say("theme-layout-help") }}</p>
          <div class="mt-4 grid gap-3 md:grid-cols-2">
            <label
              v-for="field in DETAIL_TOKENS"
              :key="field.token"
              class="text-[11px] font-medium text-muted"
            >
              {{ say(field.label) }}
              <input
                v-model="held[half][field.token]"
                spellcheck="false"
                :placeholder="shown(field.token)"
                class="mt-1 sf-field font-mono text-[11px]"
              />
            </label>
            <label class="text-[11px] font-medium text-muted md:col-span-2">
              {{ say("theme-font") }}
              <input
                v-model="held[half]['font-sans']"
                spellcheck="false"
                :placeholder="shown('font-sans')"
                class="mt-1 sf-field font-mono text-[11px]"
              />
            </label>
            <label class="text-[11px] font-medium text-muted">
              {{ say("theme-logo-visibility") }}
              <select v-model="held[half]['logo-display']" class="mt-1 sf-field">
                <option value="">{{ say("theme-inherit") }}</option>
                <option value="grid">{{ say("theme-logo-show") }}</option>
                <option value="none">{{ say("theme-logo-hide") }}</option>
              </select>
            </label>
          </div>
        </section>
      </div>

      <aside class="min-w-0 xl:sticky xl:top-5 xl:self-start">
        <div class="flex items-center justify-between gap-2">
          <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("theme-sample") }}
          </h2>
          <span class="font-mono text-[10px] text-faint">{{ say(`theme-half-${half}`) }}</span>
        </div>
        <div
          class="mt-2 grid min-h-[430px] place-items-center overflow-hidden rounded-lg border border-border p-6"
          :style="{ background: sample.background, fontFamily: sample.font }"
        >
          <div
            class="w-full max-w-72 p-5"
            :style="{
              background: sample.card,
              border: `${sample.borderWidth} solid ${sample.border}`,
              borderRadius: sample.radius,
              boxShadow: sample.shadow,
              color: sample.ink,
            }"
          >
            <div
              class="mb-5 size-9 place-items-center border text-sm font-semibold"
              :style="{
                background: sample.accent,
                borderColor: sample.border,
                borderRadius: sample.logoRadius,
                color: sample.onAccent,
                display: sample.logoDisplay,
              }"
            >
              S
            </div>
            <div class="text-base font-semibold">{{ say("theme-sample-title") }}</div>
            <p class="mt-1 text-[11px] leading-4" :style="{ color: sample.muted }">
              {{ say("theme-sample-lede") }}
            </p>
            <label class="mt-4 block text-[11px] font-medium" :style="{ color: sample.muted }">
              {{ say("theme-sample-username") }}
              <span
                class="mt-1 block h-8 w-full"
                :style="{
                  background: sample.field,
                  border: `1px solid ${sample.border}`,
                  borderRadius: sample.radius,
                }"
              ></span>
            </label>
            <div
              class="mt-3 grid h-8 place-items-center text-xs font-semibold"
              :style="{
                background: sample.accent,
                borderRadius: sample.radius,
                color: sample.onAccent,
              }"
            >
              {{ say("login-continue") }}
            </div>
            <p class="mt-3 text-center text-[10px]" :style="{ color: sample.danger }">
              {{ say("theme-sample-error") }}
            </p>
          </div>
        </div>
        <p class="mt-2 text-[10.5px] leading-4 text-faint">{{ say("theme-preview-safe") }}</p>
      </aside>
    </div>
  </div>
</template>
