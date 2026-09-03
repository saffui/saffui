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
import { reorderFlow } from "@/services/flows";

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
const canvas = ref<SVGSVGElement | null>(null);

/// A pointer event in the drawing's own coordinates, whatever the zoom.
function world(event: PointerEvent): { x: number; y: number } {
  const box = canvas.value?.getBoundingClientRect();
  if (!box) return { x: 0, y: 0 };
  const width = 1100 / view.value.zoom;
  const height = 640 / view.value.zoom;
  return {
    x: view.value.x + ((event.clientX - box.left) / box.width) * width,
    y: view.value.y - height / 2 + 120 + ((event.clientY - box.top) / box.height) * height,
  };
}

/// A node being carried: where it was grabbed, where it is, and whether it
/// actually moved, since a still grab is just a click.
const carrying = ref<{
  row: ExecutionRow;
  dx: number;
  dy: number;
  wx: number;
  wy: number;
  moved: boolean;
} | null>(null);
const hovered = ref<string | null>(null);

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

/// Every placed node, in the engine's running order.
const flat = computed<Placed[]>(() => stages.value.flatMap((stage) => stage.nodes));

/// Where a point between the columns would land in the running order.
function slotAt(wx: number, wy: number): number {
  const half = (NODE_W + GAP_X) / 2;
  const rows = flat.value;
  for (let at = 0; at < rows.length; at += 1) {
    const centre = rows[at].x + NODE_W / 2;
    if (wx < centre - half) return at;
    if (Math.abs(wx - centre) <= half && wy < rows[at].y + NODE_H / 2) return at;
  }
  return rows.length;
}

/// The marker for the slot the carried node would take.
const dropSlot = computed<{ x: number; y: number } | null>(() => {
  if (!carrying.value?.moved) return null;
  const at = slotAt(carrying.value.wx, carrying.value.wy);
  const rows = flat.value;
  if (at >= rows.length) return { x: exitX.value - GAP_X / 2, y: 0 };
  return { x: rows[at].x - GAP_X / 2, y: rows[at].y + NODE_H / 2 };
});

function grab(event: PointerEvent, row: ExecutionRow) {
  const at = world(event);
  const placed = flat.value.find((node) => node.row.execution_id === row.execution_id);
  carrying.value = {
    row,
    dx: at.x - (placed?.x ?? at.x),
    dy: at.y - (placed?.y ?? at.y),
    wx: at.x,
    wy: at.y,
    moved: false,
  };
}

async function release() {
  const carried = carrying.value;
  carrying.value = null;
  if (!carried || !held.value) return;
  if (!carried.moved) {
    selected.value = carried.row;
    return;
  }
  // Rebuild the whole running order around the drop, then say it once.
  const order = flat.value
    .map((node) => node.row)
    .filter((row) => row.execution_id !== carried.row.execution_id);
  let at = slotAt(carried.wx, carried.wy);
  const before = flat.value.findIndex(
    (node) => node.row.execution_id === carried.row.execution_id,
  );
  if (before !== -1 && before < at) at -= 1;
  order.splice(Math.min(at, order.length), 0, carried.row);
  try {
    await reorderFlow(
      realm.value,
      flowId.value,
      order.map((row, index) => ({ execution_id: row.execution_id, priority: (index + 1) * 10 })),
    );
    await load();
  } catch {
    // The toast already said; the drawing snaps back to the engine's truth.
  }
}

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
  if (carrying.value) {
    const at = world(event);
    carrying.value.wx = at.x;
    carrying.value.wy = at.y;
    if (
      Math.abs(at.x - (carrying.value.dx + flatX(carrying.value.row))) > 4 ||
      carrying.value.moved
    ) {
      carrying.value.moved = true;
    }
    return;
  }
  if (!dragging.value) return;
  view.value.x = dragging.value.ox - (event.clientX - dragging.value.px) / view.value.zoom;
  view.value.y = dragging.value.oy - (event.clientY - dragging.value.py) / view.value.zoom;
}
function flatX(row: ExecutionRow): number {
  return flat.value.find((node) => node.row.execution_id === row.execution_id)?.x ?? 0;
}
function onPointerUp() {
  dragging.value = null;
  if (carrying.value) void release();
}
/// What this build can run; mirrors the engine's catalogue.
const AUTHENTICATORS = ["password", "totp", "webauthn", "magic-link", "kerberos"] as const;
const adding = ref(false);
/// Where the next step lands in the running order; the end when unsaid.
const insertAt = ref<number | null>(null);
const stepDraft = ref({ alias: "", authenticator: "password", requirement: "required" });

/// A priority strictly between the neighbours of the asked slot. When the
/// numbering leaves no room, the whole order is rewritten first: the numbers
/// are the engine's bookkeeping, not anybody's meaning.
async function insertionPriority(at: number): Promise<number> {
  const rows = flat.value.map((node) => node.row);
  const left = at > 0 ? rows[at - 1].priority : 0;
  const right = at < rows.length ? rows[at].priority : left + 20;
  if (right - left >= 2) return Math.floor((left + right) / 2);
  await reorderFlow(
    realm.value,
    flowId.value,
    rows.map((row, index) => ({ execution_id: row.execution_id, priority: (index + 1) * 10 })),
  );
  await load();
  return at * 10 + 5;
}

async function addStep() {
  if (!held.value) return;
  try {
    const rows = held.value.executions;
    const priority =
      insertAt.value === null
        ? Math.max(0, ...rows.map((row) => row.priority)) + 10
        : await insertionPriority(insertAt.value);
    await addExecution(realm.value, flowId.value, {
      alias: stepDraft.value.alias.trim() || stepDraft.value.authenticator,
      flow_id: flowId.value,
      priority,
      step: { kind: "authenticator", authenticator: stepDraft.value.authenticator },
      requirement: stepDraft.value.requirement,
    });
    adding.value = false;
    insertAt.value = null;
    stepDraft.value = { alias: "", authenticator: "password", requirement: "required" };
    held.value = await getFlow(realm.value, flowId.value);
  } catch {
    // The toast already said.
  }
}

/// The + between the columns: how many steps stand before slot k.
function plusSlots(): { at: number; x: number }[] {
  const marks: { at: number; x: number }[] = [];
  let counted = 0;
  stages.value.forEach((stage, k) => {
    marks.push({ at: counted, x: NODE_W + GAP_X + k * (NODE_W + GAP_X) - GAP_X / 2 });
    counted += stage.nodes.length;
  });
  marks.push({ at: counted, x: exitX.value - GAP_X / 2 });
  return marks;
}
function openInsert(at: number) {
  insertAt.value = at;
  adding.value = true;
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
          ref="canvas"
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
              class="cursor-move"
              :opacity="
                carrying?.moved && carrying.row.execution_id === node.row.execution_id
                  ? 0.3
                  : node.row.requirement === 'disabled'
                    ? 0.45
                    : 1
              "
              @pointerdown.stop="grab($event, node.row)"
              @pointerenter="hovered = node.row.execution_id"
              @pointerleave="hovered = null"
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
                    : hovered === node.row.execution_id
                      ? 'var(--sf-faint)'
                      : 'var(--sf-border)'
                "
                :stroke-width="selected?.execution_id === node.row.execution_id ? 1.6 : 1"
                :stroke-dasharray="node.row.step.kind === 'sub_flow' ? '4 3' : undefined"
              />
              <g
                :opacity="hovered === node.row.execution_id ? 0.9 : 0.35"
                :fill="'var(--sf-faint)'"
              >
                <circle
                  v-for="dot in 6"
                  :key="dot"
                  :cx="node.x + NODE_W - 12 + ((dot - 1) % 2) * 5"
                  :cy="node.y + 20 + Math.floor((dot - 1) / 2) * 6"
                  r="1.2"
                />
              </g>
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

          <!-- The doors between the columns: a step can be born exactly here. -->
          <g v-for="mark in plusSlots()" :key="'plus-' + mark.at" class="cursor-pointer">
            <circle
              :cx="mark.x"
              cy="0"
              r="9"
              fill="var(--sf-surface)"
              stroke="var(--sf-border)"
              class="hover:stroke-(--sf-accent)"
              @pointerdown.stop
              @click.stop="openInsert(mark.at)"
            />
            <text
              :x="mark.x"
              y="3.5"
              text-anchor="middle"
              fill="var(--sf-muted)"
              font-size="12"
              pointer-events="none"
            >
              +
            </text>
          </g>

          <!-- The slot a carried step would take. -->
          <g v-if="dropSlot">
            <circle :cx="dropSlot.x" :cy="dropSlot.y" r="5" fill="var(--sf-accent)" />
            <line
              :x1="dropSlot.x"
              :y1="dropSlot.y - 26"
              :x2="dropSlot.x"
              :y2="dropSlot.y + 26"
              stroke="var(--sf-accent)"
              stroke-width="1.4"
            />
          </g>

          <!-- The carried step itself, riding the pointer. -->
          <g v-if="carrying?.moved" pointer-events="none" opacity="0.9">
            <rect
              :x="carrying.wx - carrying.dx"
              :y="carrying.wy - carrying.dy"
              :width="NODE_W"
              :height="NODE_H"
              rx="8"
              fill="var(--sf-surface-3)"
              stroke="var(--sf-accent)"
              stroke-width="1.4"
            />
            <text
              :x="carrying.wx - carrying.dx + 14"
              :y="carrying.wy - carrying.dy + 23"
              fill="var(--sf-ink)"
              font-size="12.5"
              font-weight="600"
            >
              {{ carrying.row.alias }}
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
