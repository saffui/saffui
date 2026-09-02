<script setup lang="ts">
// The flow as a circuit: entry on the left, established on the right, the
// steps between laid out by the engine's own rules. Consecutive alternative
// steps stack as parallel branches; required steps stand alone in series;
// disabled steps hang dimmed off the path. Hand-rolled SVG: pan, zoom,
// selection, and a live requirement editor in the inspector.
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import { addExecution, removeExecution } from "@/services/flows";
import { getFlow, setRequirement } from "@/services/flows";
import type { ExecutionRow, FlowDetail, Requirement } from "@/models/flows";

const NODE_W = 190;
const NODE_H = 56;
const GAP_X = 72;
const GAP_Y = 20;

const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const flowId = computed(() => String(route.params.flow));
const held = ref<FlowDetail | null>(null);
const failed = ref("");
const selected = ref<ExecutionRow | null>(null);

const view = ref({ x: -60, y: -40, zoom: 1 });
const dragging = ref<{ px: number; py: number; ox: number; oy: number } | null>(null);

async function load() {
  try {
    held.value = await getFlow(realm.value, flowId.value);
    if (selected.value) {
      selected.value =
        held.value.executions.find(
          (row) => row.execution_id === selected.value?.execution_id,
        ) ?? null;
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

interface Placed {
  row: ExecutionRow;
  x: number;
  y: number;
}
interface Stage {
  nodes: Placed[];
}

/// The engine's reading, drawn: sort by priority, fold runs of alternatives
/// into one parallel stage, and let each stage centre itself on the spine.
const stages = computed<Stage[]>(() => {
  if (!held.value) return [];
  const ordered = [...held.value.executions].sort((a, b) => a.priority - b.priority);
  const folded: ExecutionRow[][] = [];
  for (const row of ordered) {
    const last = folded[folded.length - 1];
    if (
      row.requirement === "alternative" &&
      last &&
      last[0].requirement === "alternative"
    ) {
      last.push(row);
    } else {
      folded.push([row]);
    }
  }
  let x = NODE_W + GAP_X;
  return folded.map((rows) => {
    const tall = rows.length * NODE_H + (rows.length - 1) * GAP_Y;
    const top = -tall / 2;
    const stage: Stage = {
      nodes: rows.map((row, at) => ({
        row,
        x,
        y: top + at * (NODE_H + GAP_Y),
      })),
    };
    x += NODE_W + GAP_X;
    return stage;
  });
});

const exitX = computed(() => (stages.value.length + 1) * (NODE_W + GAP_X));

/// One rounded elbow between two ports.
function elbow(x1: number, y1: number, x2: number, y2: number): string {
  const mid = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;
}

const edges = computed<string[]>(() => {
  const drawn: string[] = [];
  let fromX = NODE_W;
  let fromYs = [0];
  for (const stage of stages.value) {
    // A stage the engine would skip is skipped by the wire too: disabled
    // steps are drawn dimmed beside the path, never on it.
    const living = stage.nodes.filter((node) => node.row.requirement !== "disabled");
    if (!living.length) continue;
    for (const node of living) {
      for (const y of fromYs) {
        drawn.push(elbow(fromX, y, node.x, node.y + NODE_H / 2));
      }
    }
    fromX = living[0].x + NODE_W;
    fromYs = living.map((node) => node.y + NODE_H / 2);
  }
  for (const y of fromYs) {
    drawn.push(elbow(fromX, y, exitX.value, 0));
  }
  return drawn;
});

function stripe(requirement: Requirement): string {
  if (requirement === "required") return "var(--sf-accent)";
  if (requirement === "alternative") return "var(--sf-info)";
  return "var(--sf-faint)";
}

function stepName(row: ExecutionRow): string {
  return row.step.kind === "authenticator" ? row.step.authenticator : say("flow-sub-flow");
}

function onWheel(event: WheelEvent) {
  const factor = event.deltaY < 0 ? 1.1 : 0.9;
  view.value.zoom = Math.min(2.5, Math.max(0.35, view.value.zoom * factor));
}
function onPointerDown(event: PointerEvent) {
  dragging.value = {
    px: event.clientX,
    py: event.clientY,
    ox: view.value.x,
    oy: view.value.y,
  };
}
function onPointerMove(event: PointerEvent) {
  if (!dragging.value) return;
  view.value.x = dragging.value.ox - (event.clientX - dragging.value.px) / view.value.zoom;
  view.value.y = dragging.value.oy - (event.clientY - dragging.value.py) / view.value.zoom;
}
function onPointerUp() {
  dragging.value = null;
}
/// What this build can run; mirrors the engine's catalogue.
const AUTHENTICATORS = ["password", "totp", "webauthn", "magic-link", "kerberos"] as const;
const adding = ref(false);
const stepDraft = ref({ alias: "", authenticator: "password", requirement: "required" });
async function addStep() {
  if (!held.value) return;
  const top = Math.max(0, ...held.value.executions.map((row) => row.priority));
  try {
    await addExecution(realm.value, flowId.value, {
      alias: stepDraft.value.alias.trim() || stepDraft.value.authenticator,
      flow_id: flowId.value,
      priority: top + 10,
      step: { kind: "authenticator", authenticator: stepDraft.value.authenticator },
      requirement: stepDraft.value.requirement,
    });
    adding.value = false;
    stepDraft.value = { alias: "", authenticator: "password", requirement: "required" };
    held.value = await getFlow(realm.value, flowId.value);
  } catch {
    // The toast already said.
  }
}
async function dropStep(executionId: string) {
  try {
    await removeExecution(realm.value, executionId);
    held.value = await getFlow(realm.value, flowId.value);
  } catch {
    // The toast already said.
  }
}

function fit() {
  view.value = { x: -60, y: -40 - 120, zoom: 0.9 };
}

const canvasBox = computed(() => {
  const width = 1100 / view.value.zoom;
  const height = 640 / view.value.zoom;
  return `${view.value.x} ${view.value.y - height / 2 + 120} ${width} ${height}`;
});

async function changeRequirement(requirement: Requirement) {
  if (!selected.value) return;
  await setRequirement(realm.value, selected.value.execution_id, requirement);
  await load();
}

const REQUIREMENTS: Requirement[] = ["required", "alternative", "disabled"];
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="flex items-center gap-3">
      <button
        type="button"
        class="rounded-md border border-border px-2 py-1 text-xs text-muted hover:bg-surface-2"
        @click="router.push(`/${realm}/authentication`)"
      >
        &larr; {{ say("flows-title") }}
      </button>
      <button
        type="button"
        class="rounded-md bg-accent px-2.5 py-1 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        @click="adding = true"
      >
        {{ say("flow-add-step") }}
      </button>
      <h1 class="font-mono text-sm font-semibold tracking-tight">
        {{ held?.flow.alias ?? flowId }}
      </h1>
      <span
        v-if="held?.flow.built_in"
        class="rounded border border-accent/40 px-1.5 py-0.5 text-[10px] text-accent-strong"
        >{{ say("flows-built-in") }}</span
      >
      <div class="ml-auto flex items-center gap-1">
        <button
          type="button"
          class="grid size-6 place-items-center rounded border border-border text-xs hover:bg-surface-2"
          @click="view.zoom = Math.min(2.5, view.zoom * 1.15)"
        >
          +
        </button>
        <button
          type="button"
          class="grid size-6 place-items-center rounded border border-border text-xs hover:bg-surface-2"
          @click="view.zoom = Math.max(0.35, view.zoom * 0.87)"
        >
          &minus;
        </button>
        <button
          type="button"
          class="rounded border border-border px-2 py-1 text-[11px] hover:bg-surface-2"
          @click="fit"
        >
          {{ say("flow-fit") }}
        </button>
      </div>
    </div>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-3 flex min-h-0 flex-1 gap-3">
      <div
        class="min-w-0 flex-1 overflow-hidden rounded-lg border border-border bg-surface"
      >
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
            <pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="1" fill="var(--sf-border)" opacity="0.55" />
            </pattern>
          </defs>
          <rect
            :x="view.x - 2000"
            :y="view.y - 2000"
            width="6000"
            height="6000"
            fill="url(#dots)"
          />

          <path
            v-for="(edge, at) in edges"
            :key="at"
            :d="edge"
            fill="none"
            stroke="var(--sf-faint)"
            stroke-width="1.4"
          />

          <g>
            <rect
              x="0"
              y="-17"
              :width="NODE_W - 60"
              height="34"
              rx="17"
              fill="var(--sf-surface-2)"
              stroke="var(--sf-border)"
            />
            <text
              :x="(NODE_W - 60) / 2"
              y="4"
              text-anchor="middle"
              fill="var(--sf-muted)"
              font-size="12"
            >
              {{ say("flow-entry") }}
            </text>
          </g>

          <g v-for="stage in stages" :key="stage.nodes[0].row.execution_id">
            <g
              v-for="node in stage.nodes"
              :key="node.row.execution_id"
              class="cursor-pointer"
              :opacity="node.row.requirement === 'disabled' ? 0.45 : 1"
              @pointerdown.stop
              @click.stop="selected = node.row"
            >
              <rect
                :x="node.x"
                :y="node.y"
                :width="NODE_W"
                :height="NODE_H"
                rx="8"
                fill="var(--sf-surface-2)"
                :stroke="
                  selected?.execution_id === node.row.execution_id
                    ? 'var(--sf-accent)'
                    : 'var(--sf-border)'
                "
                :stroke-width="selected?.execution_id === node.row.execution_id ? 1.6 : 1"
                :stroke-dasharray="node.row.step.kind === 'sub_flow' ? '4 3' : undefined"
              />
              <rect
                :x="node.x"
                :y="node.y"
                width="3"
                :height="NODE_H"
                rx="1.5"
                :fill="stripe(node.row.requirement)"
              />
              <text
                :x="node.x + 14"
                :y="node.y + 23"
                fill="var(--sf-ink)"
                font-size="12.5"
                font-weight="600"
              >
                {{ node.row.alias }}
              </text>
              <text
                :x="node.x + 14"
                :y="node.y + 41"
                fill="var(--sf-muted)"
                font-size="10.5"
                font-family="JetBrains Mono, monospace"
              >
                {{ stepName(node.row) }} &middot; {{ say(`flow-req-${node.row.requirement}`) }}
              </text>
            </g>
          </g>

          <g>
            <rect
              :x="exitX"
              y="-17"
              :width="NODE_W - 44"
              height="34"
              rx="17"
              fill="var(--sf-surface-2)"
              stroke="var(--sf-ok)"
            />
            <text
              :x="exitX + (NODE_W - 44) / 2"
              y="4"
              text-anchor="middle"
              fill="var(--sf-ok)"
              font-size="12"
            >
              {{ say("flow-established") }}
            </text>
          </g>
        </svg>
      </div>

      <aside class="w-64 shrink-0 rounded-lg border border-border bg-surface p-3">
        <template v-if="selected">
          <div class="text-sm font-semibold tracking-tight">{{ selected.alias }}</div>
          <div class="mt-0.5 font-mono text-[10.5px] text-faint">
            {{ selected.execution_id }}
          </div>
          <dl class="mt-3 grid grid-cols-[80px_1fr] gap-y-2 text-xs">
            <dt class="text-muted">{{ say("flow-step") }}</dt>
            <dd class="font-mono text-[11px]">{{ stepName(selected) }}</dd>
            <dt class="text-muted">{{ say("flow-priority") }}</dt>
            <dd class="font-mono text-[11px]">{{ selected.priority }}</dd>
          </dl>
          <div class="mt-4">
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("flow-requirement") }}
            </div>
            <div class="mt-1.5 flex flex-col gap-1">
              <button
                v-for="requirement in REQUIREMENTS"
                :key="requirement"
                type="button"
                class="rounded-md border px-2 py-1.5 text-left text-xs"
                :class="
                  selected.requirement === requirement
                    ? 'border-accent bg-surface-2 font-medium text-ink'
                    : 'border-border text-muted hover:bg-surface-2'
                "
                @click="changeRequirement(requirement)"
              >
                {{ say(`flow-req-${requirement}`) }}
              </button>
            </div>
            <p class="mt-2 text-[10.5px] text-faint">{{ say("flow-req-help") }}</p>
            <button
              type="button"
              class="mt-3 w-full rounded-md border border-danger/40 px-2 py-1.5 text-xs text-danger hover:bg-surface-2"
              @click="dropStep(selected.execution_id)"
            >
              {{ say("flow-remove-step") }}
            </button>
          </div>
        </template>
        <p v-else class="text-xs text-muted">{{ say("flow-pick") }}</p>
      </aside>
    </div>
  
  <AppDrawer v-if="adding" :title="say('flow-add-step')" :subtitle="held?.flow.alias ?? flowId" @close="adding = false">
    <form class="flex flex-col gap-3 text-xs" @submit.prevent="addStep">
      <label class="block text-[11px] font-medium text-muted">
        {{ say("flow-step-what") }} <AppHint name="flow-step-what-help" />
        <select v-model="stepDraft.authenticator" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink">
          <option v-for="held2 in AUTHENTICATORS" :key="held2" :value="held2">{{ held2 }}</option>
        </select>
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("flows-col-alias") }}
        <input v-model="stepDraft.alias" :placeholder="stepDraft.authenticator" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink" spellcheck="false" />
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("flow-requirement") }} <AppHint name="flow-requirement-help" />
        <select v-model="stepDraft.requirement" class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink">
          <option value="required">required</option>
          <option value="alternative">alternative</option>
          <option value="disabled">disabled</option>
        </select>
      </label>
      <p class="text-[10.5px] text-faint">{{ say("flow-add-note") }}</p>
      <div>
        <button type="submit" class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong">
          {{ say("flow-add-step") }}
        </button>
      </div>
    </form>
  </AppDrawer>
</div>
</template>
