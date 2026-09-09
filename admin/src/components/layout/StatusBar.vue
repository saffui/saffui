<script setup lang="ts">
// The deck's bar along the foot of every screen: where this is, and how it
// is doing. Nothing here costs a query of its own. The host and the clock
// are the browser's, the realm is the route's, and the two readings come
// from the one standing fetch the overview already makes.
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { useStanding } from "@/stores/standing";
import { afterWrites } from "@/services/writes";

/// Where this console is served from, which is where the deployment answers.
const host = window.location.host;
const route = useRoute();
const standing = useStanding();
const realm = computed(() => String(route.params.realm ?? ""));

const now = ref(stamp());
let ticking = 0;

function stamp(): string {
  return new Date().toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

onMounted(() => {
  ticking = window.setInterval(() => (now.value = stamp()), 30_000);
  if (realm.value) void standing.read(realm.value);
});
onUnmounted(() => window.clearInterval(ticking));

watch(realm, (named) => named && standing.read(named));
afterWrites(() => realm.value && standing.read(realm.value, true));
</script>

<template>
  <footer
    class="flex h-[26px] shrink-0 items-center gap-2 border-t border-border bg-surface px-[18px] text-[11.5px] text-faint"
  >
    <span class="size-[6px] shrink-0 rounded-full bg-ok"></span>
    <span class="truncate font-mono">{{ host }}</span>
    <span aria-hidden="true">·</span>
    <span class="truncate font-mono">{{ say("status-realm", { realm }) }}</span>

    <span class="flex-1"></span>

    <span v-if="standing.held" class="shrink-0">
      {{ say("status-queue", { held: standing.held.queue }) }}
    </span>
    <span v-if="standing.held?.slow_tail_millis !== undefined" class="shrink-0">
      {{ say("status-slow-tail", { millis: standing.held.slow_tail_millis }) }}
    </span>
    <span class="shrink-0 font-mono tabular-nums">{{ now }}</span>
  </footer>
</template>

