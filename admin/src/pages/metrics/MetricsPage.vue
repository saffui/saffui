<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { readBusinessMetrics, type BusinessMetrics } from "@/services/overview";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const windowSeconds = ref(86_400);
const metrics = ref<BusinessMetrics | null>(null);
const failed = ref("");

const WINDOWS = [
  [3_600, "1 h"],
  [86_400, "24 h"],
  [604_800, "7 d"],
  [2_592_000, "30 d"],
] as const;

async function load() {
  failed.value = "";
  try {
    metrics.value = await readBusinessMetrics(realm.value, windowSeconds.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

onMounted(load);
watch(windowSeconds, load);

function shown(value: number | null): string {
  return value === null ? say("value-no-data") : new Intl.NumberFormat().format(value);
}

function latency(value: number | null): string {
  return value === null ? say("value-no-data") : `${Math.round(value)} µs`;
}
</script>

<template>
  <div class="mx-auto w-full max-w-[1440px]">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("metrics-title") }}</h1>
        <p class="mt-1 text-xs text-muted">{{ say("metrics-lede") }}</p>
      </div>
      <label class="flex items-center gap-2 text-[11px] text-muted">
        {{ say("metrics-window") }}
        <select v-model="windowSeconds" class="sf-field w-auto font-mono">
          <option v-for="[seconds, label] in WINDOWS" :key="seconds" :value="seconds">{{ label }}</option>
        </select>
      </label>
    </div>

    <p v-if="failed" class="mt-4 border-l-2 border-danger pl-2.5 text-xs text-danger" role="alert">
      {{ failed }}
    </p>

    <template v-if="metrics">
      <div class="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <section class="rounded-lg border border-border bg-surface p-4">
          <div class="text-[11px] text-muted">{{ say("overview-decisions") }}</div>
          <div class="mt-2 font-mono text-2xl tabular-nums">{{ shown(metrics.decisions.total) }}</div>
          <div class="sf-meta-list mt-2 text-[10.5px] text-faint">
            <span>{{ shown(metrics.decisions.permits) }} {{ say("overview-permits") }}</span>
            <span>{{ shown(metrics.decisions.denials) }} {{ say("overview-denials") }}</span>
          </div>
        </section>
        <section class="rounded-lg border border-border bg-surface p-4">
          <div class="text-[11px] text-muted">{{ say("overview-disagreements") }}</div>
          <div class="mt-2 font-mono text-2xl tabular-nums">{{ shown(metrics.decisions.disagreements) }}</div>
          <div class="mt-2 text-[10.5px] text-faint">
            {{ shown(metrics.decisions.indeterminate) }} {{ say("overview-indeterminate") }}
          </div>
        </section>
        <section class="rounded-lg border border-border bg-surface p-4">
          <div class="text-[11px] text-muted">{{ say("overview-logins") }}</div>
          <div class="mt-2 font-mono text-2xl tabular-nums">{{ shown(metrics.logins.total) }}</div>
          <div class="sf-meta-list mt-2 text-[10.5px] text-faint">
            <span>{{ shown(metrics.logins.signed_in) }} {{ say("overview-signed-in") }}</span>
            <span>{{ shown(metrics.logins.sign_in_failed) }} {{ say("overview-sign-in-failed") }}</span>
          </div>
        </section>
        <section class="rounded-lg border border-border bg-surface p-4">
          <div class="text-[11px] text-muted">
            {{ say("overview-decision-latency") }} <AppHint name="metrics-p95-help" />
          </div>
          <div class="mt-2 font-mono text-2xl tabular-nums">{{ latency(metrics.decisions.p95_duration_us) }}</div>
          <div class="sf-meta-list mt-2 text-[10.5px] text-faint">
            <span>{{ say("overview-p95") }}</span>
            <span v-if="metrics.decisions.total > metrics.decisions.p95_sample">
              {{ say("metrics-p95-sample", { count: metrics.decisions.p95_sample }) }}
            </span>
          </div>
        </section>
      </div>

      <div class="mt-4 rounded-lg border border-border bg-surface px-4 py-3 text-[11px] text-faint">
        {{ say("metrics-window-value", { seconds: metrics.window_seconds }) }}
      </div>
    </template>
  </div>
</template>
