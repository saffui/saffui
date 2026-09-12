<script setup lang="ts">
// The policy graph and the decision simulator, on the same canvas engine as
// the flow editor. Policies are laid out by depth: leaves left, composites
// to the right of everything they are built from, permissions (policies
// binding resources) drawn against their resources. The simulator asks the
// server's own engine and lights the nodes the trace names.
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import DangerDialog from "@/components/DangerDialog.vue";
import AppHint from "@/components/AppHint.vue";
import AppToggle from "@/components/AppToggle.vue";
import UserSubjectField from "@/components/UserSubjectField.vue";
import PageTabs from "@/components/PageTabs.vue";
import {
  createPolicy,
  createResource,
  eraseAuthzRoute,
  eraseRelation,
  protectClient,
  writeRelation,
} from "@/services/authz";
import {
  createAuthzScope,
  eraseAuthzScope,
  erasePolicy,
  eraseResource,
  evaluate,
  listAuthzRoutes,
  listAuthzScopes,
  listPolicies,
  listResources,
  publishRebacSchema,
  readRebacSchema,
  readRelations,
  reworkAuthzScope,
  reworkPolicy,
  reworkResource,
  writeAuthzRoute,
} from "@/services/authz";
import { ApiError } from "@/services/http";
import { afterWrites } from "@/services/writes";
import type {
  EvaluateAnswer,
  EvaluateQuestion,
  PolicyRow,
  ResourceRow,
  ScopeRow,
  AuthzRoute,
} from "@/models/authz";
import type { ClientBrief } from "@/models/client";
import { authorizationClients, selectedClient } from "./authorizationClients";
import { canWriteAuthorization } from "./authorizationSetup";
import { emptyTimeDraft, timeDraftFrom, timeWindowFrom, TIME_FIELDS } from "./timePolicy";

const NODE_W = 190;
const NODE_H = 56;
const GAP_X = 80;
const GAP_Y = 22;

const route = useRoute();
const router = useRouter();
const realm = computed(() => String(route.params.realm));
const clientId = ref("");
const clients = ref<ClientBrief[]>([]);
let clientLoad = 0;
let resourceLoad = 0;
const policies = ref<PolicyRow[]>([]);
const resources = ref<ResourceRow[]>([]);
const scopes = ref<ScopeRow[]>([]);
const failed = ref("");
const unprotected = ref(false);
const loading = ref(false);
const canWrite = computed(() => canWriteAuthorization(clientId.value, loading.value, unprotected.value));
const selected = ref<PolicyRow | null>(null);

/// The design's boards. Each reads what `load` already holds, so moving
/// between them costs nothing: the three listings were fetched together the
/// moment a resource server was named.
const BOARDS = ["models", "resources", "scopes", "policies", "permissions", "routes", "graph", "evaluator"];

const board = computed(() => {
  const asked = String(route.query.board ?? "models");
  return BOARDS.includes(asked) ? asked : "models";
});

watch(board, (named) => {
  if (named === "graph") void readGraph();
  if (named === "routes") void loadRoutes();
});

function boardAt(leaf: string): string {
  const client = clientId.value ? `&client=${encodeURIComponent(clientId.value)}` : "";
  return leaf === "evaluator"
    ? `/${realm.value}/evaluator${clientId.value ? `?client=${encodeURIComponent(clientId.value)}` : ""}`
    : `/${realm.value}/authorization?board=${leaf}${client}`;
}

function chooseClient() {
  drawer.value = "";
  void router.replace({ query: { ...route.query, client: clientId.value || undefined } });
  void load();
}

/// A policy that binds a resource or a scope is a permission; one that binds
/// neither is a rule a permission can be built from. One door answers for
/// both, so the two boards are one listing read two ways.
const binding = computed(() =>
  policies.value.filter((held) => held.resources.length > 0 || held.scopes.length > 0),
);
const unbound = computed(() =>
  policies.value.filter((held) => held.resources.length === 0 && held.scopes.length === 0),
);

const view = ref({ x: -40, y: -200, zoom: 0.95 });
const dragging = ref<{ px: number; py: number; ox: number; oy: number } | null>(null);

const subject = ref("");
const askedPolicy = ref("");
const verdict = ref<EvaluateAnswer | null>(null);
const litPolicies = ref<Set<string>>(new Set());

async function load() {
  const current = ++resourceLoad;
  loading.value = Boolean(clientId.value);
  failed.value = "";
  unprotected.value = false;
  verdict.value = null;
  litPolicies.value = new Set();
  selected.value = null;
  policies.value = [];
  resources.value = [];
  scopes.value = [];
  askedPolicy.value = "";
  if (!clientId.value) return;
  try {
    const [foundPolicies, foundResources, foundScopes] = await Promise.all([
      listPolicies(realm.value, clientId.value),
      listResources(realm.value, clientId.value),
      listAuthzScopes(realm.value, clientId.value),
    ]);
    if (current !== resourceLoad) return;
    policies.value = foundPolicies;
    resources.value = foundResources;
    scopes.value = foundScopes;
    askedPolicy.value = policies.value[0]?.policy_id ?? "";
  } catch (refused) {
    if (current !== resourceLoad) return;
    if (refused instanceof ApiError && refused.status === 404) {
      unprotected.value = true;
      if (drawer.value === "policy" || drawer.value === "resource" || drawer.value === "scope") drawer.value = "";
      policies.value = [];
      resources.value = [];
      scopes.value = [];
      return;
    }
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    if (current === resourceLoad) loading.value = false;
  }
}
async function loadClients() {
  const current = ++clientLoad;
  drawer.value = "";
  ++resourceLoad;
  clientId.value = "";
  clients.value = [];
  policies.value = [];
  resources.value = [];
  scopes.value = [];
  unprotected.value = false;
  loading.value = false;
  failed.value = "";
  try {
    const found = await authorizationClients(realm.value);
    if (current !== clientLoad) return;
    clients.value = found;
    clientId.value = selectedClient(found, String(route.query.client ?? ""));
    await load();
  } catch (refused) {
    if (current === clientLoad) failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(loadClients);
watch(realm, loadClients);
onMounted(() => board.value === "routes" && loadRoutes());
// The graph is read where the rest of the page is read. Reading it at setup
// would run before the session holds a token on a cold load.
onMounted(() => board.value === "graph" && readGraph());
afterWrites(() => {
  void load();
  if (board.value === "routes") void loadRoutes();
});

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

/// The four families of evaluator this build carries, plus the one shown
/// unavailable so the palette reads as a place with room, not a closed set.
/// The kinds this editor can author, each with the list its rule is spelled
/// with. The engine holds more, and the graph draws every one it finds; a
/// kind whose rule needs fields this drawer has no box for is not offered
/// here, because a box that cannot say what the kind needs writes a rule
/// nobody asked for.
const EVALUATORS = [
  { type: "role", family: "who", list: "roles" },
  { type: "group", family: "who", list: "groups" },
  { type: "user", family: "who", list: "users" },
  { type: "client", family: "who", list: "clients" },
  { type: "client-scope", family: "who", list: "client_scopes" },
  { type: "time", family: "when", list: "" },
  { type: "aggregated", family: "composes", list: "" },
] as const;

/// What the rule's list is called for one kind.
function listNameOf(kind: string): string {
  return EVALUATORS.find((held) => held.type === kind)?.list ?? "";
}

const drawer = ref<"" | "protect" | "policy" | "resource" | "scope" | "relation" | "palette" | "route">("");
const routes = ref<AuthzRoute[]>([]);
const routeEditing = ref<AuthzRoute | null>(null);
const routeDraft = ref<Omit<AuthzRoute, "route_id">>({
  method: "GET",
  path: "",
  server_id: "",
  resource: "",
  scope: "",
  action: "invoke",
  priority: 100,
  enabled: true,
});

async function loadRoutes() {
  try {
    routes.value = await listAuthzRoutes(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
    routes.value = [];
  }
}

function openRoute(route?: AuthzRoute) {
  routeEditing.value = route ?? null;
  routeDraft.value = route
    ? { ...route }
    : {
        method: "GET",
        path: "",
        server_id: clientId.value,
        resource: "",
        scope: "",
        action: "invoke",
        priority: 100,
        enabled: true,
      };
  drawer.value = "route";
}

async function saveRoute() {
  const routeId = routeEditing.value?.route_id ?? crypto.randomUUID();
  if (!routeDraft.value.path.trim() || !routeDraft.value.resource.trim() || !routeDraft.value.scope.trim()) return;
  try {
    await writeAuthzRoute(realm.value, routeId, {
      ...routeDraft.value,
      method: routeDraft.value.method.trim().toUpperCase(),
      path: routeDraft.value.path.trim(),
      server_id: routeDraft.value.server_id.trim(),
      resource: routeDraft.value.resource.trim(),
      scope: routeDraft.value.scope.trim(),
      action: routeDraft.value.action.trim() || "invoke",
    });
    drawer.value = "";
    await loadRoutes();
  } catch {
    // The API toast contains the refusal.
  }
}

async function removeRoute(route: AuthzRoute) {
  try {
    await eraseAuthzRoute(realm.value, route.route_id);
    await loadRoutes();
  } catch {
    // The API toast contains the refusal.
  }
}

/// The row being reworked, or empty for a new one. The drawers already hold
/// the fields; what changes is whether the write creates or replaces, and
/// which identity it replaces.
const editing = ref("");
/// The row waiting to be taken away, with what a person recognises it by.
const erasing = ref<{ leaf: "policies" | "resources" | "scopes"; id: string; named: string } | null>(
  null,
);
const scopeDraft = ref({ name: "", display_name: "" });

/// The relation graph as published, and as it is being rewritten. Held apart
/// so what is on screen is never mistaken for what the engine decides by.
const schemaSource = ref("");
const schemaRevision = ref<number | null>(null);
const schemaFailed = ref("");

/// One object's tuples, looked at rather than walked.
const lookingAt = ref({ object_type: "", object_id: "", relation: "" });
const tuples = ref<{ subject_type: string; subject_id: string; subject_relation: string }[]>([]);
const tuplesFailed = ref("");

async function readGraph() {
  schemaFailed.value = "";
  try {
    const held = await readRebacSchema(realm.value);
    schemaSource.value = held.source;
    schemaRevision.value = held.revision;
  } catch {
    // A realm publishing none is the ordinary first state, not an error.
    schemaSource.value = "";
    schemaRevision.value = null;
  }
}

async function publishGraph() {
  schemaFailed.value = "";
  try {
    await publishRebacSchema(realm.value, schemaSource.value);
    await readGraph();
  } catch (refused) {
    // The compiler's own words, which is the only useful thing to show an
    // author whose graph did not compile.
    schemaFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function lookAtTuples() {
  tuplesFailed.value = "";
  const asked = lookingAt.value;
  if (!asked.object_type.trim() || !asked.object_id.trim() || !asked.relation.trim()) return;
  try {
    tuples.value = await readRelations(
      realm.value,
      asked.object_type.trim(),
      asked.object_id.trim(),
      asked.relation.trim(),
    );
  } catch (refused) {
    tuples.value = [];
    tuplesFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function openNew(which: "policy" | "resource" | "scope") {
  if (!canWrite.value) return;
  editing.value = "";
  if (which === "policy") {
    policyDraft.value = { name: "", policy_type: "role", description: "", terms: "" };
    timeDraft.value = emptyTimeDraft();
    timeFailed.value = false;
  }
  if (which === "resource") resourceDraft.value = { name: "", resource_type: "", uris: "", owner: "", shareable: false };
  if (which === "scope") scopeDraft.value = { name: "", display_name: "" };
  drawer.value = which;
}

function openPolicy(held: PolicyRow) {
  editing.value = held.policy_id;
  const listed = listNameOf(held.policy_type);
  const carried = listed ? ((held as unknown as Record<string, string[]>)[listed] ?? []) : [];
  policyDraft.value = {
    name: held.name,
    policy_type: held.policy_type,
    description: held.description,
    terms: carried.join("\n"),
  };
  timeDraft.value = timeDraftFrom(held as unknown as Record<string, unknown>);
  drawer.value = "policy";
}

function openResource(held: ResourceRow) {
  editing.value = held.resource_id;
  resourceDraft.value = {
    name: held.name,
    resource_type: "",
    uris: "",
    owner: "",
    shareable: held.user_managed_access ?? false,
  };
  drawer.value = "resource";
}

function openScope(held: ScopeRow) {
  editing.value = held.scope_id;
  scopeDraft.value = { name: held.name, display_name: held.name };
  drawer.value = "scope";
}

async function makeScope() {
  if (!canWrite.value) return;
  const named = scopeDraft.value.name.trim();
  if (!named) return;
  const body = {
    name: named,
    display_name: scopeDraft.value.display_name.trim() || named,
    description: "",
  };
  try {
    if (editing.value) {
      await reworkAuthzScope(realm.value, clientId.value, editing.value, body);
    } else {
      await createAuthzScope(realm.value, clientId.value, body);
    }
    drawer.value = "";
    editing.value = "";
    await load();
  } catch {
    // The toast already said.
  }
}

/// Take one away, once the person has typed what it is called.
async function eraseHeld() {
  const held = erasing.value;
  if (!held) return;
  try {
    if (held.leaf === "policies") await erasePolicy(realm.value, clientId.value, held.id, held.named);
    if (held.leaf === "resources") await eraseResource(realm.value, clientId.value, held.id, held.named);
    if (held.leaf === "scopes") await eraseAuthzScope(realm.value, clientId.value, held.id, held.named);
    erasing.value = null;
    await load();
  } catch {
    erasing.value = null;
  }
}
const protectDraft = ref({ enforcement: "enforcing", strategy: "affirmative", shareable: false });
async function doProtect() {
  try {
    await protectClient(
      realm.value,
      clientId.value,
      protectDraft.value.enforcement,
      protectDraft.value.strategy,
      protectDraft.value.shareable,
    );
    drawer.value = "";
    await load();
  } catch {
    // The toast already said.
  }
}

const policyDraft = ref({ name: "", policy_type: "role", description: "", terms: "" });
const timeDraft = ref(emptyTimeDraft());
const timeFailed = ref(false);
async function makePolicy() {
  if (!canWrite.value) return;
  if (!policyDraft.value.name.trim()) return;
  const named = policyDraft.value.terms
    .split(/[\n,]/)
    .map((held) => held.trim())
    .filter(Boolean);
  try {
    // The whole of what a policy carries. A partial body is not an edit of
    // some of the terms: the server takes the terms it is given, so anything
    // left out is a term set to nothing.
    const listed = listNameOf(policyDraft.value.policy_type);
    const body: Record<string, unknown> = {
      name: policyDraft.value.name.trim(),
      description: policyDraft.value.description,
      decision: "unanimous",
      logic: "positive",
      policy_owner: clientId.value,
      policies: [],
      resources: [],
      scopes: [],
      policy_type: policyDraft.value.policy_type,
    };
    if (listed) body[listed] = named;
    if (policyDraft.value.policy_type === "time") {
      const window = timeWindowFrom(timeDraft.value);
      if (!window) {
        timeFailed.value = true;
        return;
      }
      Object.assign(body, window);
    }
    timeFailed.value = false;
    if (editing.value) {
      await reworkPolicy(realm.value, clientId.value, editing.value, body);
    } else {
      await createPolicy(realm.value, clientId.value, body);
    }
    drawer.value = "";
    editing.value = "";
    policyDraft.value = { name: "", policy_type: "role", description: "", terms: "" };
    timeDraft.value = emptyTimeDraft();
    await load();
  } catch {
    // The toast already said.
  }
}

const resourceDraft = ref({ name: "", resource_type: "", uris: "", owner: "", shareable: false });
async function makeResource() {
  if (!canWrite.value) return;
  if (!resourceDraft.value.name.trim()) return;
  try {
    const body = {
      name: resourceDraft.value.name.trim(),
      display_name: resourceDraft.value.name.trim(),
      description: "",
      resource_type: resourceDraft.value.resource_type.trim(),
      resource_uris: resourceDraft.value.uris
        .split(/[\n,]/)
        .map((held) => held.trim())
        .filter(Boolean),
      resource_owner: resourceDraft.value.owner.trim() || clientId.value,
      user_managed_access: resourceDraft.value.shareable,
    };
    if (editing.value) {
      await reworkResource(realm.value, clientId.value, editing.value, body);
    } else {
      await createResource(realm.value, clientId.value, body);
    }
    drawer.value = "";
    editing.value = "";
    resourceDraft.value = { name: "", resource_type: "", uris: "", owner: "", shareable: false };
    await load();
  } catch {
    // The toast already said.
  }
}

const tuple = ref({
  subject_type: "user",
  subject_id: "",
  relation: "",
  object_type: "",
  object_id: "",
});
const tupleWritten = ref(false);
async function saveTuple(erase: boolean) {
  tupleWritten.value = false;
  const held = tuple.value;
  if (!held.subject_id.trim() || !held.relation.trim() || !held.object_id.trim()) return;
  try {
    if (erase) await eraseRelation(realm.value, { ...held });
    else await writeRelation(realm.value, { ...held });
    tupleWritten.value = true;
  } catch {
    // The toast already said.
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
  <div class="flex min-h-full min-w-0 flex-col">
    <div class="flex flex-wrap items-center gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("authz-title") }}</h1>
      <RouterLink
        :to="`/${realm}/decision-journal`"
        class="rounded-md border border-border px-2.5 py-1.5 text-xs text-muted hover:text-ink"
      >
        {{ say("decision-journal-title") }}
      </RouterLink>
      <form
        v-if="board !== 'routes' && board !== 'graph'"
        class="flex flex-wrap items-center gap-2 xl:ml-auto"
        @submit.prevent="load"
      >
        <label for="authorization-client" class="text-[11px] text-muted">{{ say("authz-server") }}</label>
        <select
          id="authorization-client"
          v-model="clientId"
          class="w-44 rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-ink"
          :disabled="!clients.length"
          @change="chooseClient"
        >
          <option v-if="!clients.length" value="">{{ say("authz-no-clients") }}</option>
          <option v-else value="" disabled>{{ say("authz-pick-client") }}</option>
          <option v-for="client in clients" :key="client.client_id" :value="client.client_id">
            {{ client.client_id }}
          </option>
        </select>
        <button
          type="submit"
          :disabled="!clientId"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
        >
          {{ say("authz-load") }}
        </button>
        <button
          type="button"
          :disabled="!clientId"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
          @click="drawer = 'protect'"
        >
          {{ say("authz-protect") }}
        </button>
        <button
          type="button"
          :disabled="!canWrite"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
          @click="drawer = 'policy'"
        >
          {{ say("authz-new-policy") }}
        </button>
        <button
          type="button"
          :disabled="!canWrite"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
          @click="drawer = 'resource'"
        >
          {{ say("authz-new-resource") }}
        </button>
        <button
          type="button"
          class="rounded-md border border-border px-2 py-1 text-xs hover:bg-surface-2"
          @click="drawer = 'relation'"
        >
          {{ say("authz-write-relation") }}
        </button>
        <button
          type="button"
          class="rounded-md border border-border px-2 py-1 text-xs text-muted hover:bg-surface-2"
          @click="drawer = 'palette'"
        >
          {{ say("authz-palette") }}
        </button>
      </form>
    </div>

    <PageTabs
      :leaves="BOARDS"
      :at="board"
      :to="boardAt"
      saying="authz-board"
      class="mt-3"
    />

    <p v-if="failed" class="mt-2 text-xs text-danger" role="alert">{{ failed }}</p>
    <p v-if="clients.length > 1 && !clientId && board !== 'routes' && board !== 'graph'" class="mt-2 text-xs text-muted">{{ say("authz-pick-client") }}</p>
    <div v-if="unprotected && clientId" class="mt-3 flex flex-wrap items-center gap-3 rounded-md border border-accent/40 bg-accent/5 px-3 py-2.5 text-xs">
      <p class="min-w-0 flex-1 text-ink">{{ say("authz-unprotected") }}</p>
      <button type="button" class="sf-button sf-button-primary" @click="drawer = 'protect'">
        {{ say("authz-protect") }}
      </button>
    </div>

    <div v-if="board === 'routes'" class="mt-3 min-w-0">
      <div class="flex flex-wrap items-center gap-2">
        <div>
          <h2 class="text-sm font-semibold">{{ say("authz-routes-title") }}</h2>
          <p class="mt-1 text-[11px] text-muted">{{ say("authz-routes-lede") }}</p>
        </div>
        <button type="button" class="sf-button sf-button-primary ml-auto" @click="openRoute()">
          {{ say("authz-route-new") }}
        </button>
      </div>
      <div class="sf-list mt-3 overflow-x-auto">
        <table class="sf-table">
          <thead>
            <tr>
              <th>{{ say("authz-route-method") }}</th>
              <th>{{ say("authz-route-path") }}</th>
              <th>{{ say("authz-route-server") }}</th>
              <th>{{ say("authz-route-permission") }}</th>
              <th>{{ say("authz-route-priority") }}</th>
              <th>{{ say("authz-route-status") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="route in routes" :key="route.route_id" class="border-b border-border/60 last:border-0">
              <td class="font-mono text-[11px]">{{ route.method }}</td>
              <td class="max-w-72 font-mono text-[11px] break-all">{{ route.path }}</td>
              <td class="font-mono text-[11px]">{{ route.server_id }}</td>
              <td class="font-mono text-[11px]">{{ route.resource }}:{{ route.scope }}</td>
              <td class="font-mono text-[11px]">{{ route.priority }}</td>
              <td>
                <span :class="route.enabled ? 'text-ok' : 'text-muted'">
                  {{ route.enabled ? say("authz-route-enabled") : say("authz-route-disabled") }}
                </span>
              </td>
              <td class="text-right whitespace-nowrap">
                <button type="button" class="text-xs text-accent hover:underline" @click="openRoute(route)">
                  {{ say("authz-route-edit") }}
                </button>
                <button type="button" class="ml-3 text-xs text-danger hover:underline" @click="removeRoute(route)">
                  {{ say("authz-route-delete") }}
                </button>
              </td>
            </tr>
            <tr v-if="!routes.length">
              <td colspan="7" class="text-muted">{{ say("authz-routes-none") }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="board === 'models'" class="mt-3 flex min-h-0 flex-1 flex-col gap-3 xl:flex-row">
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

      <aside class="flex w-full shrink-0 flex-col gap-3 xl:w-72">
        <div class="rounded-lg border border-border bg-surface p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("authz-simulator") }}
          </div>
          <form class="mt-2 flex flex-col gap-2 text-xs" @submit.prevent="simulate">
            <label class="text-[11px] font-medium text-muted">
              {{ say("authz-subject") }}
              <UserSubjectField
                v-model="subject"
                :realm="realm"
                :placeholder="say('subject-username-or-id')"
                class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
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
              class="sf-button sf-button-primary mt-1 justify-center"
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
    <div v-if="board === 'graph'" class="mt-3 grid gap-4 lg:grid-cols-2">
      <div>
        <div class="flex items-center gap-2">
          <span class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("graph-schema-title") }}
          </span>
          <AppHint name="graph-schema-help" />
          <span v-if="schemaRevision !== null" class="text-[10.5px] text-faint">
            {{ say("graph-schema-revision", { held: schemaRevision }) }}
          </span>
          <button
            type="button"
            class="sf-button sf-button-primary ml-auto"
            @click="publishGraph"
          >
            {{ say("graph-publish") }}
          </button>
        </div>
        <p v-if="schemaRevision === null" class="mt-2 text-[11px] text-muted">
          {{ say("graph-schema-none") }}
        </p>
        <textarea
          v-model="schemaSource"
          rows="18"
          spellcheck="false"
          class="sf-field mt-2 font-mono text-[11.5px] leading-relaxed"
        ></textarea>
        <p v-if="schemaFailed" class="mt-2 text-[11px] text-danger" role="alert">
          {{ schemaFailed }}
        </p>
      </div>

      <div>
        <div class="flex items-center gap-2">
          <span class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("graph-tuples-title") }}
          </span>
          <AppHint name="graph-tuples-help" />
        </div>
        <form class="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3" @submit.prevent="lookAtTuples">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("graph-object-type") }}
            <input
              v-model="lookingAt.object_type"
              placeholder="document"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("graph-object-id") }}
            <input v-model="lookingAt.object_id" spellcheck="false" class="sf-field mt-1 font-mono" />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("graph-relation") }}
            <input
              v-model="lookingAt.relation"
              placeholder="viewer"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <div class="col-span-3">
            <button type="submit" class="sf-button sf-button-secondary">
              {{ say("graph-look") }}
            </button>
          </div>
        </form>

        <div class="sf-list mt-3 overflow-x-auto">
          <table class="sf-table">
            <thead>
              <tr>
                <th>{{ say("graph-subject") }}</th>
                <th>{{ say("graph-relation") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="held in tuples" :key="held.subject_type + held.subject_id + held.subject_relation">
                <td class="font-mono text-[10.5px]">{{ held.subject_type }}:{{ held.subject_id }}</td>
                <td class="text-muted">
                  {{ held.subject_relation || say("value-none") }}
                </td>
              </tr>
              <tr v-if="!tuples.length">
                <td colspan="2" class="text-muted">{{ say("graph-tuples-none") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="tuplesFailed" class="mt-2 text-[11px] text-danger" role="alert">
          {{ tuplesFailed }}
        </p>
      </div>
    </div>

    <div v-if="board === 'resources'" class="mt-3 flex justify-end">
      <button type="button" class="sf-button sf-button-secondary" :disabled="!canWrite" @click="openNew('resource')">
        {{ say("authz-add-resource") }}
      </button>
    </div>
    <div v-if="board === 'resources'" class="sf-list mt-3 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
              <th>{{ say("authz-column-name") }}</th>
              <th>{{ say("authz-column-id") }}</th>
              <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="held in resources" :key="held.resource_id">
              <td>{{ held.name }}</td>
              <td class="font-mono text-[10.5px] text-faint">{{ held.resource_id }}</td>
              <td class="text-right whitespace-nowrap">
                <button
                  type="button"
                  class="text-[11px] text-faint hover:text-ink"
                  @click="openResource(held)"
                >
                  {{ say("authz-edit") }}
                </button>
                <button
                  type="button"
                  class="ml-3 text-[11px] text-faint hover:text-danger"
                  @click="erasing = { leaf: 'resources', id: held.resource_id, named: held.name }"
                >
                  {{ say("authz-erase") }}
                </button>
              </td>
          </tr>
          <tr v-if="!resources.length">
            <td colspan="3" class="text-muted">{{ say("authz-none-here") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="board === 'scopes'" class="mt-3 flex justify-end">
      <button type="button" class="sf-button sf-button-secondary" :disabled="!canWrite" @click="openNew('scope')">
        {{ say("authz-add-scope") }}
      </button>
    </div>
    <div v-if="board === 'scopes'" class="sf-list mt-3 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
              <th>{{ say("authz-column-name") }}</th>
              <th>{{ say("authz-column-id") }}</th>
              <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="held in scopes" :key="held.scope_id">
              <td>{{ held.name }}</td>
              <td class="font-mono text-[10.5px] text-faint">{{ held.scope_id }}</td>
              <td class="text-right whitespace-nowrap">
                <button
                  type="button"
                  class="text-[11px] text-faint hover:text-ink"
                  @click="openScope(held)"
                >
                  {{ say("authz-edit") }}
                </button>
                <button
                  type="button"
                  class="ml-3 text-[11px] text-faint hover:text-danger"
                  @click="erasing = { leaf: 'scopes', id: held.scope_id, named: held.name }"
                >
                  {{ say("authz-erase") }}
                </button>
              </td>
          </tr>
          <tr v-if="!scopes.length">
            <td colspan="3" class="text-muted">{{ say("authz-none-here") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="board === 'policies'" class="mt-3 flex justify-end">
      <button type="button" class="sf-button sf-button-secondary" :disabled="!canWrite" @click="openNew('policy')">
        {{ say("authz-add-policy") }}
      </button>
    </div>
    <div v-if="board === 'policies'" class="sf-list mt-3 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
              <th>{{ say("authz-column-name") }}</th>
              <th>{{ say("authz-column-kind") }}</th>
              <th>{{ say("authz-column-about") }}</th>
              <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="held in unbound" :key="held.policy_id">
              <td>{{ held.name }}</td>
              <td>{{ held.policy_type }}</td>
              <td class="text-muted">{{ held.description || say('value-none') }}</td>
              <td class="text-right whitespace-nowrap">
                <button
                  type="button"
                  class="text-[11px] text-faint hover:text-ink"
                  @click="openPolicy(held)"
                >
                  {{ say("authz-edit") }}
                </button>
                <button
                  type="button"
                  class="ml-3 text-[11px] text-faint hover:text-danger"
                  @click="erasing = { leaf: 'policies', id: held.policy_id, named: held.name }"
                >
                  {{ say("authz-erase") }}
                </button>
              </td>
          </tr>
          <tr v-if="!unbound.length">
            <td colspan="4" class="text-muted">{{ say("authz-none-here") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="board === 'permissions'" class="mt-3 flex justify-end">
      <button type="button" class="sf-button sf-button-secondary" :disabled="!canWrite" @click="openNew('policy')">
        {{ say("authz-add-policy") }}
      </button>
    </div>
    <div v-if="board === 'permissions'" class="sf-list mt-3 overflow-x-auto">
      <table class="sf-table">
        <thead>
          <tr>
              <th>{{ say("authz-column-name") }}</th>
              <th>{{ say("authz-column-kind") }}</th>
              <th>{{ say("authz-column-binds") }}</th>
              <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="held in binding" :key="held.policy_id">
              <td>{{ held.name }}</td>
              <td>{{ held.policy_type }}</td>
              <td class="text-muted">{{ held.resources.length + held.scopes.length }}</td>
              <td class="text-right whitespace-nowrap">
                <button
                  type="button"
                  class="text-[11px] text-faint hover:text-ink"
                  @click="openPolicy(held)"
                >
                  {{ say("authz-edit") }}
                </button>
                <button
                  type="button"
                  class="ml-3 text-[11px] text-faint hover:text-danger"
                  @click="erasing = { leaf: 'policies', id: held.policy_id, named: held.name }"
                >
                  {{ say("authz-erase") }}
                </button>
              </td>
          </tr>
          <tr v-if="!binding.length">
            <td colspan="4" class="text-muted">{{ say("authz-none-here") }}</td>
          </tr>
        </tbody>
      </table>
    </div>


    <AppDrawer
      v-if="drawer === 'route'"
      :title="routeEditing ? say('authz-route-edit') : say('authz-route-new')"
      :subtitle="routeEditing?.route_id ?? say('authz-route-generated')"
      @close="drawer = ''"
    >
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveRoute">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-route-method") }}
          <select v-model="routeDraft.method" class="sf-field mt-1 font-mono">
            <option v-for="method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', '*']" :key="method" :value="method">
              {{ method }}
            </option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-route-path") }}
          <input v-model="routeDraft.path" placeholder="/api/orders/*" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-route-server") }}
          <input v-model="routeDraft.server_id" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-route-resource") }}
            <input v-model="routeDraft.resource" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-route-scope") }}
            <input v-model="routeDraft.scope" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-route-action") }}
          <input v-model="routeDraft.action" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-route-priority") }}
          <input v-model.number="routeDraft.priority" type="number" min="0" class="sf-field mt-1 font-mono" />
        </label>
        <AppToggle v-model="routeDraft.enabled">{{ say("authz-route-enabled") }}</AppToggle>
        <button type="submit" class="sf-button sf-button-primary justify-center">
          {{ routeEditing ? say("settings-save") : say("realm-create") }}
        </button>
      </form>
    </AppDrawer>

    <AppDrawer v-if="drawer === 'protect'" :title="say('authz-protect')" :subtitle="clientId" @close="drawer = ''">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="doProtect">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-enforcement") }} <AppHint name="authz-enforcement-help" />
          <select v-model="protectDraft.enforcement" class="sf-field mt-1 font-mono">
            <option value="enforcing">enforcing</option>
            <option value="permissive">permissive</option>
            <option value="disabled">disabled</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-strategy") }} <AppHint name="authz-strategy-help" />
          <select v-model="protectDraft.strategy" class="sf-field mt-1 font-mono">
            <option value="affirmative">affirmative</option>
            <option value="unanimous">unanimous</option>
            <option value="consensus">consensus</option>
          </select>
        </label>
        <AppToggle v-model="protectDraft.shareable">
          {{ say("authz-server-shareable") }} <AppHint name="authz-server-shareable-help" />
        </AppToggle>
        <div>
          <button type="submit" class="sf-button sf-button-primary">
            {{ say("authz-protect") }}
          </button>
        </div>
      </form>
    </AppDrawer>

    <AppDrawer v-if="drawer === 'policy'" :title="editing ? say('authz-edit-policy') : say('authz-new-policy')" :subtitle="clientId" @close="drawer = ''">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="makePolicy">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("settings-name") }}
          <input v-model="policyDraft.name" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-evaluator") }} <AppHint name="authz-evaluator-help" />
          <select v-model="policyDraft.policy_type" class="sf-field mt-1 font-mono">
            <option v-for="held in EVALUATORS" :key="held.type" :value="held.type">{{ held.type }}</option>
          </select>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("scopes-col-description") }}
          <input v-model="policyDraft.description" class="sf-field mt-1" />
        </label>
        <div v-if="policyDraft.policy_type === 'time'" class="grid gap-3 sm:grid-cols-2">
          <label v-for="field in ['not_before', 'not_on_or_after'] as const" :key="field" class="block text-[11px] font-medium text-muted">
            {{ say(`authz-time-${field}`) }}
            <input v-model="timeDraft[field]" type="datetime-local" class="sf-field mt-1" />
          </label>
          <label v-for="field in TIME_FIELDS" :key="field" class="block text-[11px] font-medium text-muted">
            {{ say(`authz-time-${field}`) }}
            <input v-model="timeDraft[field]" type="number" min="0" step="1" class="sf-field mt-1 font-mono" />
          </label>
          <p class="sm:col-span-2 text-[10.5px] text-muted">{{ say('authz-time-utc') }}</p>
          <p v-if="timeFailed" class="sm:col-span-2 text-[11px] text-danger" role="alert">{{ say('authz-time-invalid') }}</p>
        </div>
        <label v-else class="block text-[11px] font-medium text-muted">
          {{ say("authz-terms") }} <AppHint name="authz-terms-help" />
          <textarea v-model="policyDraft.terms" rows="2" :placeholder="say('policy-blacklist-hint')" class="sf-field mt-1 font-mono" spellcheck="false"></textarea>
        </label>
        <div>
          <button type="submit" class="sf-button sf-button-primary">
            {{ say("realm-create") }}
          </button>
        </div>
      </form>
    </AppDrawer>

    <AppDrawer v-if="drawer === 'resource'" :title="editing ? say('authz-edit-resource') : say('authz-new-resource')" :subtitle="clientId" @close="drawer = ''">
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="makeResource">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("settings-name") }}
          <input v-model="resourceDraft.name" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-resource-type") }} <AppHint name="authz-resource-type-help" />
          <input v-model="resourceDraft.resource_type" placeholder="document" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-resource-uris") }} <AppHint name="authz-resource-uris-help" />
          <textarea v-model="resourceDraft.uris" rows="2" :placeholder="say('policy-blacklist-hint')" class="sf-field mt-1 font-mono" spellcheck="false"></textarea>
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-resource-owner") }}
          <input v-model="resourceDraft.owner" :placeholder="clientId" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <AppToggle v-model="resourceDraft.shareable">
          {{ say("authz-shareable") }} <AppHint name="authz-shareable-help" />
        </AppToggle>
        <div>
          <button type="submit" class="sf-button sf-button-primary">
            {{ say("realm-create") }}
          </button>
        </div>
      </form>
    </AppDrawer>

    <DangerDialog
      :open="erasing !== null"
      :title="say('authz-erase-title')"
      :named="erasing?.named ?? ''"
      :lede="say('authz-erase-lede')"
      :facts="[]"
      :warning="say('authz-erase-warning')"
      :trail="say('authz-erase-trail')"
      :confirm-label="say('authz-erase')"
      @close="erasing = null"
      @confirm="eraseHeld"
    />

    <AppDrawer
      v-if="drawer === 'scope'"
      :title="editing ? say('authz-edit-scope') : say('authz-new-scope')"
      :subtitle="clientId"
      @close="drawer = ''"
    >
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="makeScope">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("settings-name") }} <AppHint name="authz-scope-name-help" />
          <input v-model="scopeDraft.name" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-column-name") }}
          <input v-model="scopeDraft.display_name" class="sf-field mt-1" />
        </label>
        <div>
          <button type="submit" class="sf-button sf-button-primary">
            {{ editing ? say("settings-save") : say("realm-create") }}
          </button>
        </div>
      </form>
    </AppDrawer>

    <AppDrawer v-if="drawer === 'relation'" :title="say('authz-write-relation')" :subtitle="realm" @close="drawer = ''">
      <p class="text-[11px] text-muted">{{ say("authz-relation-lede") }}</p>
      <form class="mt-3 flex flex-col gap-3 text-xs" @submit.prevent="saveTuple(false)">
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-subject-type") }}
            <input v-model="tuple.subject_type" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-subject-id") }}
            <UserSubjectField
              v-if="tuple.subject_type === 'user'"
              v-model="tuple.subject_id"
              :realm="realm"
              id-only
              class="sf-field mt-1 font-mono"
            />
            <input v-else v-model="tuple.subject_id" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("authz-relation-name") }} <AppHint name="authz-relation-help" />
          <input v-model="tuple.relation" placeholder="owner" class="sf-field mt-1 font-mono" spellcheck="false" />
        </label>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-object-type") }}
            <input v-model="tuple.object_type" placeholder="document" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("authz-object-id") }}
            <input v-model="tuple.object_id" placeholder="doc-42" class="sf-field mt-1 font-mono" spellcheck="false" />
          </label>
        </div>
        <div class="flex items-center gap-2">
          <button type="submit" class="sf-button sf-button-primary">
            {{ say("authz-write") }}
          </button>
          <button type="button" class="rounded-md border border-danger/40 px-3 py-1.5 text-xs text-danger hover:bg-surface-2" @click="saveTuple(true)">
            {{ say("authz-erase") }}
          </button>
          <span v-if="tupleWritten" class="text-[11px] text-ok">{{ say("authz-tuple-kept") }}</span>
        </div>
        <p class="text-[10.5px] text-faint">{{ say("authz-tuple-test") }}</p>
      </form>
    </AppDrawer>

    <AppDrawer v-if="drawer === 'palette'" :title="say('authz-palette')" :subtitle="say('authz-palette-sub')" @close="drawer = ''">
      <p class="text-[11px] text-muted">{{ say("authz-palette-lede") }}</p>
      <div class="mt-3 flex flex-col gap-1.5">
        <div v-for="held in EVALUATORS" :key="held.type" class="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
          <span class="font-mono text-[11.5px]">{{ held.type }}</span>
          <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">{{ say(`authz-family-${held.family}`) }}</span>
        </div>
        <div class="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs opacity-60">
          <span class="font-mono text-[11.5px]">uma-sharing</span>
          <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">{{ say("authz-family-owns") }}</span>
          <span class="ml-auto text-[10.5px] text-faint">{{ say("features-not-compiled") }}</span>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
