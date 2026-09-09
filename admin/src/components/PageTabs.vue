<script setup lang="ts">
// The deck's tab row: 32 tall, a rule under the whole of it, and the one in
// force underlined in accent. Each tab is a link, not a panel, so a tab is
// linkable and the browser's back button means what it says.
import { computed } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";

/// The registries a person moves between while doing one job. Each keeps its
/// own entry in the sidebar as well, so both paths lead to the same screen.
const DIRECTORY = ["users", "groups", "roles", "organizations", "sessions"];

const props = defineProps<{
  leaves?: string[];
  /// Where a tab goes. The default is a sibling screen under the realm; a
  /// page whose tabs are boards of itself names its own.
  to?: (leaf: string) => string;
  /// Which leaf is in force, when it is not the path's own segment.
  at?: string;
  /// Leaves holding something unsaved, shown as a dot beside the label.
  marked?: string[];
  /// What the labels are read from, minus the leaf.
  saying?: string;
}>();
const shown = computed(() => props.leaves ?? DIRECTORY);

const route = useRoute();
const realm = computed(() => String(route.params.realm ?? ""));
const here = computed(() => props.at ?? String(route.path.split("/")[2] ?? ""));
const goes = computed(() => props.to ?? ((leaf: string) => `/${realm.value}/${leaf}`));
</script>

<template>
  <nav class="flex h-8 items-center gap-0.5 border-b border-border">
    <RouterLink
      v-for="leaf in shown"
      :key="leaf"
      :to="goes(leaf)"
      class="flex h-8 items-center gap-1.5 border-b-2 px-3 text-[13.5px]"
      :class="
        leaf === here
          ? 'border-accent text-ink'
          : 'border-transparent text-muted hover:text-ink'
      "
    >
      {{ say(`${props.saying ?? "nav"}-${leaf}`) }}
      <span
        v-if="marked?.includes(leaf)"
        class="size-[5px] rounded-full bg-accent"
        :title="say('tabs-unsaved')"
      ></span>
    </RouterLink>
  </nav>
</template>
