<script setup lang="ts">
// The policy graph and the decision simulator, on the same canvas engine as
// the flow editor. Policies are laid out by depth: leaves left, composites
// to the right of everything they are built from, permissions (policies
// binding resources) drawn against their resources. The simulator asks the
// server's own engine and lights the nodes the trace names.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import { evaluate, listAuthzScopes, listPolicies, listResources } from "@/services/authz";
import { ApiError } from "@/services/http";
import type {
  EvaluateAnswer,
  EvaluateQuestion,
  PolicyRow,
  ResourceRow,
  ScopeRow,
} from "@/models/authz";

const NODE_W = 190;
const NODE_H = 56;
const GAP_X = 80;
const GAP_Y = 22;

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const clientId = ref("web-dashboard");
const policies = ref<PolicyRow[]>([]);
const resources = ref<ResourceRow[]>([]);
const scopes = ref<ScopeRow[]>([]);
const failed = ref("");
const unprotected = ref(false);
const selected = ref<PolicyRow | null>(null);

const view = ref({ x: -40, y: -200, zoom: 0.95 });
const dragging = ref<{ px: number; py: number; ox: number; oy: number } | null>(null);

const subject = ref("ada");
const askedPolicy = ref("");
const verdict = ref<EvaluateAnswer | null>(null);
const litPolicies = ref<Set<string>>(new Set());

async function load() {
  failed.value = "";
  unprotected.value = false;
  verdict.value = null;
  litPolicies.value = new Set();
  selected.value = null;
  try {
    [policies.value, resources.value, scopes.value] = await Promise.all([
      listPolicies(realm.value, clientId.value),
      listResources(realm.value, clientId.value),
      listAuthzScopes(realm.value, clientId.value),
    ]);
    askedPolicy.value = policies.value[0]?.policy_id ?? "";
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) {
      unprotected.value = true;
      policies.value = [];
      resources.value = [];
      scopes.value = [];
      return;
    }
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

interface PlacedPolicy {
  row: PolicyRow;
  x: number;
  y: number;
}

/// Depth-layered layout: a policy sits one column right of the deepest
/// policy it is built from; roots without children sit in column zero.
const placed = computed<PlacedPolicy[]>(() => {
  const byId = new Map(policies.value.map((row) => [row.policy_id, row]));
  const depth = new Map<string, number>();
  const measuring = new Set<string>();
  const depthOf = (id: string): number => {
    const held = depth.get(id);
    if (held !== undefined) return held;
    if (measuring.has(id)) return 0;
    measuring.add(id);
    const row = byId.get(id);
    const children = row?.policies.filter((child) => byId.has(child)) ?? [];
    const measured = children.length
      ? 1 + Math.max(...children.map((child) => depthOf(child)))
      : 0;
    measuring.delete(id);
    depth.set(id, measured);
    return measured;
  };
  const columns = new Map<number, PolicyRow[]>();
  for (const row of policies.value) {
    const at = depthOf(row.policy_id);
    const column = columns.get(at) ?? [];
    column.push(row);
    columns.set(at, column);
  }
  const out: PlacedPolicy[] = [];
  for (const [column, rows] of columns) {
    const tall = rows.length * NODE_H + (rows.length - 1) * GAP_Y;
    rows.forEach((row, at) => {
      out.push({
        row,
        x: column * (NODE_W + GAP_X),
        y: -tall / 2 + at * (NODE_H + GAP_Y),
      });
    });
  }
  return out;
});

const spotOf = computed(() => {
  const spots = new Map<string, PlacedPolicy>();
  for (const one of placed.value) spots.set(one.row.policy_id, one);
  return spots;
});

/// Resource pillars, right of the deepest policy column.
const resourceX = computed(() => {
  const deepest = Math.max(0, ...placed.value.map((one) => one.x));
  return deepest + NODE_W + GAP_X + 30;
});
const placedResources = computed(() => {
  const tall = resources.value.length * NODE_H + (resources.value.length - 1) * GAP_Y;
  return resources.value.map((row, at) => ({
    row,
    x: resourceX.value,
    y: -tall / 2 + at * (NODE_H + GAP_Y) - 140,
  }));
});

function elbow(x1: number, y1: number, x2: number, y2: number): string {
  const mid = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;
}

const edges = computed<{ d: string; lit: boolean }[]>(() => {
  const drawn: { d: string; lit: boolean }[] = [];
  for (const one of placed.value) {
    for (const child of one.row.policies) {
      const from = spotOf.value.get(child);
      if (!from) continue;
      drawn.push({
        d: elbow(from.x + NODE_W, from.y + NODE_H / 2, one.x, one.y + NODE_H / 2),
        lit: litPolicies.value.has(child) && litPolicies.value.has(one.row.policy_id),
      });
    }
    for (const bound of one.row.resources) {
      const to = placedResources.value.find((held) => held.row.resource_id === bound);
      if (!to) continue;
      drawn.push({
        d: elbow(one.x + NODE_W, one.y + NODE_H / 2, to.x, to.y + NODE_H / 2),
        lit: false,
      });
    }
  }
  return drawn;
});

function stripe(row: PolicyRow): string {
  if (row.resources.length || row.scopes.length) return "var(--sf-accent)";
  if (row.policy_type === "aggregated" || row.policies.length) return "var(--sf-info)";
  return "var(--sf-muted)";
}

/// The trace names policies by id wherever it met them; collect every id it
/// carries, at any depth, and light those nodes.
function litFrom(detail: unknown): Set<string> {
  const lit = new Set<string>();
  const walk = (held: unknown) => {
    if (Array.isArray(held)) {
      for (const one of held) walk(one);
      return;
    }
    if (held && typeof held === "object") {
      for (const [key, value] of Object.entries(held)) {
        if (key === "policy_id" && typeof value === "string") lit.add(value);
        else walk(value);
      }
    }
  };
  walk(detail);
  return lit;
}

async function simulate() {
  failed.value = "";
  verdict.value = null;
  if (!askedPolicy.value || !subject.value.trim()) return;
  const question: EvaluateQuestion = {
    kind: "policy",
    server_id: clientId.value,
    policy_id: askedPolicy.value,
  };
  try {
    verdict.value = await evaluate(realm.value, subject.value.trim(), question);
    litPolicies.value = litFrom(verdict.value.detail);
    litPolicies.value.add(askedPolicy.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function onWheel(event: WheelEvent) {
  const factor = event.deltaY < 0 ? 1.1 : 0.9;
  view.value.zoom = Math.min(2.5, Math.max(0.35, view.value.zoom * factor));
}
function onPointerDown(event: PointerEvent) {
  dragging.value = { px: event.clientX, py: event.clientY, ox: view.value.x, oy: view.value.y };
}
function onPointerMove(event: PointerEvent) {
  if (!dragging.value) return;
  view.value.x = dragging.value.ox - (event.clientX - dragging.value.px) / view.value.zoom;
  view.value.y = dragging.value.oy - (event.clientY - dragging.value.py) / view.value.zoom;
}
function onPointerUp() {
  dragging.value = null;
}

const canvasBox = computed(() => {
  const width = 1100 / view.value.zoom;
  const height = 560 / view.value.zoom;
  return `${view.value.x} ${view.value.y} ${width} ${height}`;
});

function nodeStroke(row: PolicyRow): string {
  if (verdict.value && litPolicies.value.has(row.policy_id)) {
    return verdict.value.computed === "permit" ? "var(--sf-ok)" : "var(--sf-danger)";
  }
  if (selected.value?.policy_id === row.policy_id) return "var(--sf-accent)";
  return "var(--sf-border)";
}
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="flex items-center gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("authz-title") }}</h1>
      <form class="ml-auto flex items-center gap-2" @submit.prevent="load">
        <label class="text-[11px] text-muted">{{ say("authz-server") }}</label>
        <input
          v-model="clientId"
          class="w-44 rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-ink"
          spellcheck="false"
        />
        <button
          type="submit"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
        >
          {{ say("authz-load") }}
        </button>
      </form>
    </div>

    <p v-if="failed" class="mt-2 text-xs text-danger" role="alert">{{ failed }}</p>
    <p v-if="unprotected" class="mt-2 text-xs text-muted">{{ say("authz-unprotected") }}</p>

    <div class="mt-3 flex min-h-0 flex-1 gap-3">
      <div class="min-w-0 flex-1 overflow-hidden rounded-lg border border-border bg-surface">
        <svg
          class="h-full w-full cursor-grab active:cursor-grabbing"
          :viewBox="canvasBox"
          @wheel.prevent="onWheel"
          @pointerdown="onPointerDown"
          @pointermove="onPointerMove"
          @pointerup="onPointerUp"
          @pointerleave="onPointerUp"
        >
          <defs>
            <pattern id="authz-dots" width="22" height="22" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="1" fill="var(--sf-border)" opacity="0.55" />
            </pattern>
          </defs>
          <rect
            :x="view.x - 2000"
            :y="view.y - 2000"
            width="6000"
            height="6000"
            fill="url(#authz-dots)"
          />

          <path
            v-for="(edge, at) in edges"
            :key="at"
            :d="edge.d"
            fill="none"
            :stroke="edge.lit ? 'var(--sf-accent)' : 'var(--sf-faint)'"
            :stroke-width="edge.lit ? 2 : 1.4"
          />

          <g
            v-for="one in placed"
            :key="one.row.policy_id"
            class="cursor-pointer"
            @pointerdown.stop
            @click.stop="selected = one.row"
          >
            <rect
              :x="one.x"
              :y="one.y"
              :width="NODE_W"
              :height="NODE_H"
              rx="8"
              fill="var(--sf-surface-2)"
              :stroke="nodeStroke(one.row)"
              :stroke-width="litPolicies.has(one.row.policy_id) ? 1.8 : 1"
            />
            <rect
              :x="one.x"
              :y="one.y"
              width="3"
              :height="NODE_H"
              rx="1.5"
              :fill="stripe(one.row)"
            />
            <text
              :x="one.x + 14"
              :y="one.y + 23"
              fill="var(--sf-ink)"
              font-size="12.5"
              font-weight="600"
            >
              {{ one.row.name }}
            </text>
            <text
              :x="one.x + 14"
              :y="one.y + 41"
              fill="var(--sf-muted)"
              font-size="10.5"
              font-family="JetBrains Mono, monospace"
            >
              {{ one.row.policy_type }}
            </text>
          </g>

          <g v-for="held in placedResources" :key="held.row.resource_id">
            <rect
              :x="held.x"
              :y="held.y"
              :width="NODE_W - 30"
              :height="NODE_H - 14"
              rx="21"
              fill="var(--sf-surface-2)"
              stroke="var(--sf-border)"
            />
            <text
              :x="held.x + 16"
              :y="held.y + 26"
              fill="var(--sf-ink)"
              font-size="12"
            >
              {{ held.row.name }}
            </text>
          </g>
        </svg>
      </div>

      <aside class="flex w-72 shrink-0 flex-col gap-3">
        <div class="rounded-lg border border-border bg-surface p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("authz-simulator") }}
          </div>
          <form class="mt-2 flex flex-col gap-2 text-xs" @submit.prevent="simulate">
            <label class="text-[11px] font-medium text-muted">
              {{ say("authz-subject") }}
              <input
                v-model="subject"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
                spellcheck="false"
              />
            </label>
            <label class="text-[11px] font-medium text-muted">
              {{ say("authz-policy") }}
              <select
                v-model="askedPolicy"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
              >
                <option
                  v-for="row in policies"
                  :key="row.policy_id"
                  :value="row.policy_id"
                >
                  {{ row.name }}
                </option>
              </select>
            </label>
            <button
              type="submit"
              class="mt-1 rounded-md bg-accent py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
            >
              {{ say("authz-ask") }}
            </button>
          </form>

          <div v-if="verdict" class="mt-3">
            <div
              class="rounded-md border px-3 py-2 text-center text-sm font-bold tracking-wide"
              :class="
                verdict.computed === 'permit'
                  ? 'border-ok/50 text-ok'
                  : 'border-danger/50 text-danger'
              "
            >
              {{
                verdict.computed === "permit"
                  ? say("authz-granted")
                  : verdict.computed === "deny"
                    ? say("authz-denied")
                    : say("authz-indeterminate")
              }}
            </div>
            <div
              v-if="(verdict.detail.reasons ?? []).length"
              class="mt-2 max-h-40 overflow-y-auto rounded border border-border bg-surface-2 p-2"
            >
              <pre class="font-mono text-[10px] leading-relaxed whitespace-pre-wrap">{{
                JSON.stringify(verdict.detail.reasons, null, 1)
              }}</pre>
            </div>
            <p v-else class="mt-2 text-[10.5px] text-faint">
              {{ say("authz-no-reasons") }}
            </p>
          </div>
        </div>

        <div v-if="selected" class="rounded-lg border border-border bg-surface p-3">
          <div class="text-sm font-semibold tracking-tight">{{ selected.name }}</div>
          <div class="mt-0.5 font-mono text-[10.5px] text-faint">{{ selected.policy_id }}</div>
          <dl class="mt-2 grid grid-cols-[86px_1fr] gap-y-1.5 text-xs">
            <dt class="text-muted">{{ say("mappers-col-type") }}</dt>
            <dd class="font-mono text-[11px]">{{ selected.policy_type }}</dd>
            <dt v-if="selected.policies.length" class="text-muted">
              {{ say("authz-built-from") }}
            </dt>
            <dd v-if="selected.policies.length" class="font-mono text-[10.5px]">
              {{ selected.policies.length }}
            </dd>
            <dt v-if="selected.resources.length" class="text-muted">
              {{ say("authz-binds") }}
            </dt>
            <dd v-if="selected.resources.length" class="font-mono text-[10.5px]">
              {{ selected.resources.length }} &middot; {{ selected.scopes.length }}
            </dd>
          </dl>
          <p v-if="selected.description" class="mt-2 text-[11px] text-muted">
            {{ selected.description }}
          </p>
        </div>
      </aside>
    </div>
  </div>
</template>
