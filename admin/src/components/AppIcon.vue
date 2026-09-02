<script setup lang="ts">
// One door to the icon set. Pages name icons by role, never by the library's
// vocabulary, so swapping the set later touches this file alone. Lucide,
// tree-shaken: only the glyphs named here ship.
import {
  ChartNoAxesColumn,
  Users,
  FolderTree,
  IdCard,
  MonitorSmartphone,
  Tags,
  Fingerprint,
  ShieldCheck,
  Share2,
  Scale,
  Activity,
  Settings2,
  KeyRound,
  Search,
  ChevronRight,
  Sun,
  Moon,
  type LucideProps,
} from "lucide-vue-next";
import type { FunctionalComponent } from "vue";

const GLYPHS: Record<string, FunctionalComponent<LucideProps>> = {
  overview: ChartNoAxesColumn,
  users: Users,
  directory: FolderTree,
  roles: IdCard,
  clients: MonitorSmartphone,
  scopes: Tags,
  authentication: Fingerprint,
  authorization: ShieldCheck,
  federation: Share2,
  governance: Scale,
  events: Activity,
  settings: Settings2,
  key: KeyRound,
  search: Search,
  chevron: ChevronRight,
  sun: Sun,
  moon: Moon,
};

const props = defineProps<{ name: keyof typeof GLYPHS; size?: number }>();
</script>

<template>
  <component
    :is="GLYPHS[props.name]"
    :size="props.size ?? 16"
    :stroke-width="1.6"
    aria-hidden="true"
  />
</template>
