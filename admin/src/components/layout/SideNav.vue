<script setup lang="ts">
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import RealmSelector from "./RealmSelector.vue";
import { SIDE_NAV_GROUPS } from "./sideNav";
import { say } from "@/i18n";

defineProps<{ open: boolean }>();
const emit = defineEmits<{ close: [] }>();

const route = useRoute();
const realm = () => String(route.params.realm ?? "main");

function target(leaf: string): string {
  return `/${realm()}/${leaf}`;
}
function active(leaf: string): boolean {
  const current = target(leaf);
  return route.path === current || route.path.startsWith(`${current}/`);
}
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-40 bg-black/30 md:hidden"
    aria-hidden="true"
    @click="emit('close')"
  ></div>
  <nav
    class="fixed inset-y-0 left-0 z-50 flex w-rail shrink-0 -translate-x-full flex-col border-r border-border bg-surface transition-transform duration-200 md:relative md:z-auto md:translate-x-0"
    :class="open && 'translate-x-0'"
  >
    <div class="flex h-[52px] shrink-0 items-center gap-2.5 px-3">
      <div
        class="grid size-6 shrink-0 place-items-center rounded bg-accent-tint text-[13px] font-semibold text-accent"
      >
        S
      </div>
      <span class="text-[13.5px] text-ink">{{ say("console-name") }}</span>
    </div>

    <RealmSelector />

    <div class="min-h-0 flex-1 overflow-y-auto py-2">
      <div v-for="group in SIDE_NAV_GROUPS" :key="group.label" class="mb-2">
        <div
          v-if="group.label"
          class="px-3 pt-2.5 pb-1 text-[10px] font-semibold tracking-[0.09em] text-faint uppercase"
        >
          {{ say(group.label) }}
        </div>
        <router-link
          v-for="item in group.items"
          :key="item.leaf"
          :to="target(item.leaf)"
          class="group flex h-[31px] items-center gap-2.5 pr-3 hover:bg-neutral-tint"
          :class="active(item.leaf) && 'bg-accent-tint'"
          @click="emit('close')"
        >
          <span
            class="h-[29px] w-0.5 shrink-0"
            :class="active(item.leaf) ? 'bg-accent' : 'bg-transparent'"
          ></span>
          <AppIcon
            :name="item.icon"
            :size="14"
            :class="active(item.leaf) ? 'text-accent' : 'text-faint'"
          />
          <span
            class="truncate text-[13.5px]"
            :class="active(item.leaf) ? 'font-medium text-ink' : 'text-muted'"
            >{{ say(item.label) }}</span
          >
        </router-link>
      </div>
    </div>

    <div class="flex h-[34px] shrink-0 items-center gap-1.5 px-3">
      <AppIcon name="server" :size="13" class="shrink-0 text-ok" />
      <span class="truncate text-[11.5px] text-faint">{{ say("console-footprint") }}</span>
    </div>
  </nav>
</template>
