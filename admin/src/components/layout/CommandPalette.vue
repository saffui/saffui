<script setup lang="ts">
// The jump-anywhere box: pages by name, realms by prefix. Opens on the
// keyboard shortcut or the top bar button, filters as you type, Enter takes
// the first match, Escape leaves quietly.
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import { listRealms } from "@/services/realms";
import type { RealmBrief } from "@/models/realm";

const opened = defineModel<boolean>({ required: true });
const route = useRoute();
const router = useRouter();
const typed = ref("");
const field = ref<HTMLInputElement | null>(null);
const realms = ref<RealmBrief[]>([]);

const PAGES: { leaf: string; name: () => string }[] = [
  { leaf: "overview", name: () => say("nav-overview") },
  { leaf: "users", name: () => say("nav-users") },
  { leaf: "roles", name: () => say("nav-roles") },
  { leaf: "groups", name: () => say("nav-groups") },
  { leaf: "organizations", name: () => say("nav-organizations") },
  { leaf: "clients", name: () => say("nav-clients") },
  { leaf: "client-scopes", name: () => say("nav-scopes") },
  { leaf: "authentication", name: () => say("nav-authentication") },
  { leaf: "authorization", name: () => say("nav-authorization") },
  { leaf: "federation", name: () => say("nav-federation") },
  { leaf: "governance", name: () => say("nav-governance") },
  { leaf: "events", name: () => say("nav-events") },
  { leaf: "journal", name: () => say("nav-journal") },
  { leaf: "settings", name: () => say("nav-settings") },
  { leaf: "keys", name: () => say("nav-keys") },
  { leaf: "theme", name: () => say("nav-theme") },
  { leaf: "pages", name: () => say("nav-pages") },
  { leaf: "token-preview", name: () => say("nav-preview") },
];

interface Hit {
  kind: "page" | "realm";
  label: string;
  hint: string;
  go: () => void;
}

const hits = computed<Hit[]>(() => {
  const realm = String(route.params.realm ?? "main");
  const needle = typed.value.trim().toLowerCase();
  const pages: Hit[] = PAGES.map((page) => ({
    kind: "page" as const,
    label: page.name(),
    hint: `/${realm}/${page.leaf}`,
    go: () => router.push(`/${realm}/${page.leaf}`),
  }));
  const elsewhere: Hit[] = realms.value
    .filter((held) => held.name !== realm)
    .map((held) => ({
      kind: "realm" as const,
      label: held.display_name || held.name,
      hint: say("palette-switch", { realm: held.name }),
      go: () => router.push(`/${held.name}/overview`),
    }));
  const all = [...pages, ...elsewhere];
  if (!needle) return all.slice(0, 9);
  return all
    .filter(
      (hit) =>
        hit.label.toLowerCase().includes(needle) || hit.hint.toLowerCase().includes(needle),
    )
    .slice(0, 9);
});

watch(opened, async (now) => {
  if (now) {
    typed.value = "";
    await nextTick();
    field.value?.focus();
    try {
      realms.value = await listRealms();
    } catch {
      realms.value = [];
    }
  }
});

function pick(hit: Hit) {
  opened.value = false;
  hit.go();
}
function onSubmit() {
  const first = hits.value[0];
  if (first) pick(first);
}

function onKey(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    opened.value = !opened.value;
  }
  if (event.key === "Escape") opened.value = false;
}
onMounted(() => document.addEventListener("keydown", onKey));
onUnmounted(() => document.removeEventListener("keydown", onKey));
</script>

<template>
  <div v-if="opened" class="fixed inset-0 z-50">
    <div class="absolute inset-0 bg-black/30" @click="opened = false"></div>
    <div
      class="absolute top-24 left-1/2 w-[480px] max-w-full -translate-x-1/2 overflow-hidden rounded-lg border border-border bg-surface shadow-(--sf-shadow)"
      role="dialog"
      aria-modal="true"
    >
      <form class="flex items-center gap-2 border-b border-border px-3" @submit.prevent="onSubmit">
        <AppIcon name="search" :size="14" class="text-faint" />
        <input
          ref="field"
          v-model="typed"
          class="w-full bg-transparent py-2.5 text-sm text-ink outline-none"
          :placeholder="say('topbar-search')"
          spellcheck="false"
        />
        <kbd class="rounded border border-border bg-surface-2 px-1 font-mono text-[10px] text-faint"
          >esc</kbd
        >
      </form>
      <div class="max-h-80 overflow-y-auto p-1.5">
        <button
          v-for="(hit, at) in hits"
          :key="hit.hint"
          type="button"
          class="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-xs hover:bg-surface-2"
          :class="at === 0 && 'bg-surface-2'"
          @click="pick(hit)"
        >
          <AppIcon :name="hit.kind === 'realm' ? 'directory' : 'chevron'" :size="13" class="text-faint" />
          <span class="text-ink">{{ hit.label }}</span>
          <span class="ml-auto font-mono text-[10.5px] text-faint">{{ hit.hint }}</span>
        </button>
        <p v-if="!hits.length" class="px-2.5 py-3 text-xs text-muted">
          {{ say("palette-nothing") }}
        </p>
      </div>
    </div>
  </div>
</template>
