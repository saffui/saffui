<script setup lang="ts">
// One door to the icon set. Pages name icons by role, never by the library's
// vocabulary, so swapping the set later touches this file alone. Lucide,
// tree-shaken: only the glyphs named here ship.
import {
  LayoutDashboard,
  Users,
  UsersRound,
  Building2,
  IdCard,
  AppWindow,
  Tags,
  LogIn,
  Lock,
  FlaskConical,
  Share2,
  Palette,
  FileText,
  Scale,
  ChartNoAxesColumn,
  Activity,
  ScrollText,
  Settings,
  Key,
  MonitorSmartphone,
  Server,
  Globe,
  Search,
  ChevronRight,
  ChevronsUpDown,
  Sun,
  Moon,
  Plus,
  Eye,
  EyeOff,
  BadgeCheck,
  TriangleAlert,
  X,
  Trash2,
  Menu,
  type LucideProps,
} from "lucide-vue-next";
import type { FunctionalComponent } from "vue";

// The names the deck gives each place, not the library's. Where a board
// names its glyph, that is the one here.
const GLYPHS = {
  overview: LayoutDashboard,
  users: Users,
  groups: UsersRound,
  organizations: Building2,
  roles: IdCard,
  clients: AppWindow,
  scopes: Tags,
  authentication: LogIn,
  authorization: Lock,
  evaluator: FlaskConical,
  federation: Share2,
  appearance: Palette,
  pages: FileText,
  governance: Scale,
  metrics: ChartNoAxesColumn,
  events: Activity,
  journal: ScrollText,
  settings: Settings,
  key: Key,
  sessions: MonitorSmartphone,
  server: Server,
  issuer: Globe,
  search: Search,
  chevron: ChevronRight,
  "chevron-pick": ChevronsUpDown,
  sun: Sun,
  moon: Moon,
  plus: Plus,
  eye: Eye,
  "eye-off": EyeOff,
  verified: BadgeCheck,
  danger: TriangleAlert,
  close: X,
  remove: Trash2,
  menu: Menu,
} satisfies Record<string, FunctionalComponent<LucideProps>>;

// Literal keys, so a name with no glyph here fails the type check instead of
// rendering an empty box.
export type GlyphName = keyof typeof GLYPHS;

const props = defineProps<{ name: GlyphName; size?: number }>();
</script>

<template>
  <component
    :is="GLYPHS[props.name]"
    :size="props.size ?? 16"
    :stroke-width="1.6"
    aria-hidden="true"
  />
</template>
