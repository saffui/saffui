<script setup lang="ts">
// Security-event receivers and outbound connectors are provider rows wearing
// a kind; this page reads them apart from the sign-in brokers, writes them,
// and lets an operator prove a pipe against the real far side.
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppDrawer from "@/components/AppDrawer.vue";
import AppHint from "@/components/AppHint.vue";
import AppPaging from "@/components/AppPaging.vue";
import AppToggle from "@/components/AppToggle.vue";
import {
  createIdp,
  deleteIdp,
  kindOf,
  listIdps,
  proveDelivery,
  updateIdp,
} from "@/services/federation";
import { getRealmSettings, listSignInEvents } from "@/services/settings";
import { drinkEvents, listDeadLetters, requeueDead } from "@/services/events";
import type { DeadLetter, LiveTold } from "@/services/events";
import { afterWrites } from "@/services/writes";
import type { DeliveryProof, IdpRow } from "@/models/federation";
import type { SignInEvent } from "@/models/events";
import type { Page } from "@/models/paging";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const idps = ref<IdpRow[]>([]);
const failed = ref("");

/// The sign-in log, when the realm switched it on; null says it is off.
const signIns = ref<Page<SignInEvent> | null>(null);
const recording = ref(false);
const first = ref(0);
const size = ref(25);
async function turn() {
  try {
    signIns.value = await listSignInEvents(realm.value, first.value, size.value);
  } catch {
    // The listing simply stays where it was.
  }
}
function resize(asked: number) {
  size.value = asked;
  first.value = 0;
  void turn();
}

const dead = ref<DeadLetter[]>([]);
async function requeue(letter: DeadLetter) {
  try {
    await requeueDead(realm.value, letter.event_id);
  } catch {
    // The toast already said.
  }
}

/// The live feed: at most the last thirty frames, newest first, drunk
/// while the switch is on and quietly dropped when it goes off.
const watching = ref(false);
const frames = ref<LiveTold[]>([]);
const feedFailed = ref("");
let pouring: AbortController | null = null;
function stopWatching() {
  pouring?.abort();
  pouring = null;
  watching.value = false;
}
async function startWatching() {
  feedFailed.value = "";
  frames.value = [];
  const controller = new AbortController();
  pouring = controller;
  watching.value = true;
  try {
    await drinkEvents(
      realm.value,
      (told) => {
        frames.value = [told, ...frames.value].slice(0, 30);
      },
      controller.signal,
    );
  } catch (refused) {
    if (!controller.signal.aborted) {
      feedFailed.value = refused instanceof Error ? refused.message : String(refused);
    }
  } finally {
    if (pouring === controller) {
      pouring = null;
      watching.value = false;
    }
  }
}
onUnmounted(stopWatching);

async function load() {
  try {
    idps.value = await listIdps(realm.value);
    dead.value = await listDeadLetters(realm.value);
    recording.value = (await getRealmSettings(realm.value)).events_enabled ?? false;
    if (recording.value) {
      signIns.value = await listSignInEvents(realm.value, first.value, size.value);
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

function instant(epoch: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}

const receivers = computed(() => idps.value.filter((row) => kindOf(row).startsWith("caep")));
const connectors = computed(() => idps.value.filter((row) => kindOf(row) === "scim-outbound"));
const webhooks = computed(() => idps.value.filter((row) => kindOf(row) === "webhook"));

function bagText(row: IdpRow, key: string): string {
  const held = row.configs?.[key];
  if (held === undefined) return "";
  if (typeof held === "string") return held;
  return held.Str ?? "";
}

/// The four events this transmitter emits, short name to full URI.
const KNOWN_EVENTS: [string, string][] = [
  ["session-revoked", "https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
  ["credential-change", "https://schemas.openid.net/secevent/caep/event-type/credential-change"],
  ["account-disabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled"],
  ["account-purged", "https://schemas.openid.net/secevent/risc/event-type/account-purged"],
];

type ConnectorKind = "caep-push" | "scim-outbound" | "webhook";
const editing = ref<null | { kind: ConnectorKind; alias: string | null }>(null);
const form = ref({
  alias: "",
  displayName: "",
  enabled: true,
  delivery: "push",
  endpoint: "",
  audience: "",
  events: [] as string[],
  baseUrl: "",
  bearer: "",
  url: "",
  filter: "*",
  secret: "",
});
const bearerOnFile = ref(false);
const secretOnFile = ref(false);
const saving = ref(false);
const doomName = ref("");

function openCreate(kind: ConnectorKind) {
  editing.value = { kind, alias: null };
  form.value = {
    alias: "",
    displayName: "",
    enabled: true,
    delivery: "push",
    endpoint: "",
    audience: "",
    events: [],
    baseUrl: "",
    bearer: "",
    url: "",
    filter: "*",
    secret: "",
  };
  bearerOnFile.value = false;
  secretOnFile.value = false;
  doomName.value = "";
}

function openEdit(row: IdpRow) {
  const named = kindOf(row);
  const kind: ConnectorKind =
    named === "scim-outbound" ? "scim-outbound" : named === "webhook" ? "webhook" : "caep-push";
  editing.value = { kind, alias: row.provider_id };
  form.value = {
    alias: row.provider_id,
    displayName: row.display_name,
    enabled: row.enabled !== false,
    delivery: bagText(row, "delivery") || "push",
    endpoint: bagText(row, "endpoint"),
    audience: bagText(row, "audience"),
    events: bagText(row, "events").split(/\s+/).filter(Boolean),
    baseUrl: bagText(row, "base_url"),
    bearer: "",
    url: bagText(row, "url"),
    filter: bagText(row, "filter") || "*",
    secret: "",
  };
  bearerOnFile.value = bagText(row, "bearer") === "**********";
  secretOnFile.value = bagText(row, "secret") === "**********";
  doomName.value = "";
}

/// The bag as the server reads it: only the keys the kind knows, and the
/// bearer only when the operator typed a new one.
function bagged(kind: ConnectorKind): Record<string, { Str: string }> {
  const bag: Record<string, { Str: string }> = { kind: { Str: kind } };
  if (kind === "webhook") {
    bag.url = { Str: form.value.url.trim() };
    bag.filter = { Str: form.value.filter.trim() || "*" };
    const secret = form.value.secret.trim();
    if (secret && secret !== "**********") bag.secret = { Str: secret };
    return bag;
  }
  if (kind === "scim-outbound") {
    bag.base_url = { Str: form.value.baseUrl.trim() };
  } else {
    bag.delivery = { Str: form.value.delivery };
    if (form.value.delivery === "push") bag.endpoint = { Str: form.value.endpoint.trim() };
    if (form.value.audience.trim()) bag.audience = { Str: form.value.audience.trim() };
    if (form.value.events.length) bag.events = { Str: form.value.events.join(" ") };
  }
  const bearer = form.value.bearer.trim();
  if (bearer && bearer !== "**********") bag.bearer = { Str: bearer };
  return bag;
}

async function save() {
  if (!editing.value) return;
  saving.value = true;
  try {
    const alias = editing.value.alias ?? form.value.alias.trim();
    const body = {
      provider_id: alias,
      name: alias,
      display_name: form.value.displayName.trim(),
      description: "",
      enabled: form.value.enabled,
      trust_email: false,
      configs: bagged(editing.value.kind),
    };
    if (editing.value.alias) await updateIdp(realm.value, editing.value.alias, body);
    else await createIdp(realm.value, body);
    editing.value = null;
    idps.value = await listIdps(realm.value);
  } catch {
    // The toast already said.
  } finally {
    saving.value = false;
  }
}

async function drop() {
  if (!editing.value?.alias) return;
  try {
    await deleteIdp(realm.value, editing.value.alias);
    editing.value = null;
    idps.value = await listIdps(realm.value);
  } catch {
    // The toast already said.
  }
}

/// One proof per row, kept where its row shows it; asking again replaces it.
const proofs = ref<Record<string, DeliveryProof>>({});
const proving = ref("");
async function prove(row: IdpRow) {
  proving.value = row.provider_id;
  try {
    proofs.value[row.provider_id] = await proveDelivery(realm.value, row.provider_id);
  } catch (refused) {
    proofs.value[row.provider_id] = {
      proven: false,
      how: "refused",
      status: null,
      said: refused instanceof Error ? refused.message : String(refused),
    };
  } finally {
    proving.value = "";
  }
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("events-title") }}</h1>
    <p class="mt-1 text-xs text-muted">{{ say("events-lede") }}</p>

    <div class="mt-5 flex max-w-3xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("events-live") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="watching ? stopWatching() : startWatching()"
      >
        {{ watching ? say("events-live-stop") : say("events-live-start") }}
      </button>
    </div>
    <p v-if="feedFailed" class="mt-2 text-xs text-danger" role="alert">{{ feedFailed }}</p>
    <p v-else-if="!watching && !frames.length" class="mt-2 text-xs text-muted">
      {{ say("events-live-off") }}
    </p>
    <p v-else-if="watching && !frames.length" class="mt-2 text-xs text-muted">
      {{ say("events-live-empty") }}
    </p>
    <ul v-if="frames.length" class="mt-2 max-w-3xl rounded-lg border border-border bg-surface">
      <li
        v-for="told in frames"
        :key="told.event_id"
        class="flex items-center gap-2 border-b border-border/60 px-3 py-1.5 text-xs last:border-0"
      >
        <span class="font-mono text-[10.5px] text-faint">#{{ told.event_id }}</span>
        <span class="font-mono text-[11px]">{{ told.kind }}</span>
        <span class="text-muted">{{ told.user_id }}</span>
        <span class="ml-auto text-[10.5px] text-faint">{{
          new Date(told.occurred_at).toLocaleTimeString()
        }}</span>
      </li>
    </ul>
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("signin-events-title") }}
    </h2>
    <p v-if="!recording" class="mt-1.5 text-xs text-muted">
      {{ say("signin-events-off") }}
      <router-link :to="`/${realm}/settings`" class="text-accent hover:text-ink">{{
        say("signin-events-off-link")
      }}</router-link>
    </p>
    <div
      v-else-if="signIns"
      class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface"
    >
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("signin-col-kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-who") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-client") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("signin-col-from") }}</th>
            <th class="px-3 py-2 text-right font-medium">{{ say("journal-col-when") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="held in signIns.items"
            :key="held.id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2">
              <span
                class="rounded border px-1.5 py-0.5 font-mono text-[10.5px]"
                :class="
                  held.kind === 'sign_in_failed'
                    ? 'border-danger/40 text-danger'
                    : 'border-border text-muted'
                "
                >{{ held.kind }}</span
              >
            </td>
            <td class="px-3 py-2 font-mono text-[11px]">{{ held.user_id || "·" }}</td>
            <td class="px-3 py-2 font-mono text-[11px]">{{ held.client_id || "·" }}</td>
            <td class="px-3 py-2 font-mono text-[10.5px] text-faint">{{ held.ip || "·" }}</td>
            <td class="px-3 py-2 text-right font-mono text-[10.5px] text-faint">
              {{ instant(held.recorded_at) }}
            </td>
          </tr>
          <tr v-if="!signIns.items.length">
            <td colspan="5" class="px-3 py-3 text-muted">{{ say("signin-events-none") }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPaging
      v-if="signIns"
      :first="first"
      :count="signIns.items.length"
      :size="size"
      @update:first="(held) => { first = held; void turn(); }"
      @update:size="resize"
    />

    <div class="mt-6 flex max-w-3xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("events-receivers") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="openCreate('caep-push')"
      >
        {{ say("events-add-receiver") }}
      </button>
    </div>
    <p v-if="!receivers.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-receivers") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in receivers"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="font-medium hover:text-accent"
            @click="openEdit(row)"
          >
            {{ row.display_name || row.name }}
          </button>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
            {{ bagText(row, "delivery") || "push" }}
          </span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
          <button
            type="button"
            class="rounded-md border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-2 hover:text-ink disabled:opacity-40"
            :disabled="proving === row.provider_id"
            @click="prove(row)"
          >
            {{ proving === row.provider_id ? say("connector-proving") : say("connector-prove") }}
          </button>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">
          {{ bagText(row, "endpoint") || bagText(row, "audience") }}
        </div>
        <p
          v-if="proofs[row.provider_id]"
          class="mt-1.5 text-[10.5px]"
          :class="proofs[row.provider_id].proven ? 'text-ok' : 'text-danger'"
          role="status"
        >
          {{ proofs[row.provider_id].proven ? say("connector-proven") : say("connector-unproven") }}
          {{ proofs[row.provider_id].said
          }}<template v-if="proofs[row.provider_id].status !== null">
            ({{ proofs[row.provider_id].status }})</template
          >
        </p>
      </div>
    </div>

    <div class="mt-6 flex max-w-3xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("events-connectors") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="openCreate('scim-outbound')"
      >
        {{ say("events-add-connector") }}
      </button>
    </div>
    <p v-if="!connectors.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-connectors") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in connectors"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-3">
          <button
            type="button"
            class="font-medium hover:text-accent"
            @click="openEdit(row)"
          >
            {{ row.display_name || row.name }}
          </button>
          <span class="font-mono text-[10.5px] text-faint">{{ bagText(row, "base_url") }}</span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
          <button
            type="button"
            class="rounded-md border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-2 hover:text-ink disabled:opacity-40"
            :disabled="proving === row.provider_id"
            @click="prove(row)"
          >
            {{ proving === row.provider_id ? say("connector-proving") : say("connector-prove") }}
          </button>
        </div>
        <p
          v-if="proofs[row.provider_id]"
          class="mt-1.5 text-[10.5px]"
          :class="proofs[row.provider_id].proven ? 'text-ok' : 'text-danger'"
          role="status"
        >
          {{ proofs[row.provider_id].proven ? say("connector-proven") : say("connector-unproven") }}
          {{ proofs[row.provider_id].said
          }}<template v-if="proofs[row.provider_id].status !== null">
            ({{ proofs[row.provider_id].status }})</template
          >
        </p>
      </div>
    </div>

      <div class="mt-6 flex max-w-3xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("events-webhooks") }}
      </h2>
      <button
        type="button"
        class="ml-auto rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:bg-surface-2 hover:text-ink"
        @click="openCreate('webhook')"
      >
        {{ say("events-add-webhook") }}
      </button>
    </div>
    <p v-if="!webhooks.length" class="mt-2 text-xs text-muted">
      {{ say("events-no-webhooks") }}
    </p>
    <div v-else class="mt-2 grid max-w-3xl gap-2">
      <div
        v-for="row in webhooks"
        :key="row.internal_id"
        class="rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <button type="button" class="font-medium hover:text-accent" @click="openEdit(row)">
            {{ row.display_name || row.name }}
          </button>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
            {{ bagText(row, "filter") || "*" }}
          </span>
          <span
            class="ml-auto text-[10.5px]"
            :class="row.enabled === false ? 'text-danger' : 'text-faint'"
          >
            {{ row.enabled === false ? say("users-disabled") : say("users-active") }}
          </span>
          <button
            type="button"
            class="rounded-md border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-2 hover:text-ink disabled:opacity-40"
            :disabled="proving === row.provider_id"
            @click="prove(row)"
          >
            {{ proving === row.provider_id ? say("connector-proving") : say("connector-prove") }}
          </button>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">{{ bagText(row, "url") }}</div>
        <p
          v-if="proofs[row.provider_id]"
          class="mt-1.5 text-[10.5px]"
          :class="proofs[row.provider_id].proven ? 'text-ok' : 'text-danger'"
          role="status"
        >
          {{ proofs[row.provider_id].proven ? say("connector-proven") : say("connector-unproven") }}
          {{ proofs[row.provider_id].said
          }}<template v-if="proofs[row.provider_id].status !== null">
            ({{ proofs[row.provider_id].status }})</template
          >
        </p>
      </div>
    </div>

    <div class="mt-6 flex max-w-3xl items-center">
      <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("events-dead") }}
      </h2>
      <span
        v-if="dead.length"
        class="ml-2 rounded bg-warn/12 px-1.5 py-0.5 text-[10px] text-warn"
        >{{ dead.length }}</span
      >
    </div>
    <p v-if="!dead.length" class="mt-2 text-xs text-muted">{{ say("events-no-dead") }}</p>
    <div v-else class="mt-2 overflow-x-auto rounded-lg border border-border bg-surface max-w-3xl">
      <table class="w-full text-left text-xs">
        <thead>
          <tr class="border-b border-border text-[11px] text-muted">
            <th class="px-3 py-2 font-medium">{{ say("events-dead-col-kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("events-dead-col-who") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("events-dead-col-attempts") }}</th>
            <th class="px-3 py-2 font-medium">{{ say("events-dead-col-when") }}</th>
            <th class="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="letter in dead"
            :key="letter.event_id"
            class="border-b border-border/60 last:border-0"
          >
            <td class="px-3 py-2 font-mono text-[11px]">{{ letter.kind }}</td>
            <td class="px-3 py-2 font-mono text-[11px]">{{ letter.user_id }}</td>
            <td class="px-3 py-2 text-muted">{{ letter.attempts }}</td>
            <td class="px-3 py-2 text-[10.5px] text-muted">
              {{ new Date(letter.occurred_at).toLocaleString() }}
            </td>
            <td class="px-3 py-2 text-right">
              <button
                type="button"
                class="rounded-md border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-2 hover:text-ink"
                @click="requeue(letter)"
              >
                {{ say("events-dead-requeue") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

  <AppDrawer
      v-if="editing"
      :title="
        editing.alias ??
        say(
          editing.kind === 'scim-outbound'
            ? 'events-new-connector'
            : editing.kind === 'webhook'
              ? 'events-new-webhook'
              : 'events-new-receiver',
        )
      "
      :subtitle="editing.kind"
      @close="editing = null"
    >
      <form class="flex flex-col gap-3 text-xs" @submit.prevent="save">
        <label v-if="!editing.alias" class="block text-[11px] font-medium text-muted">
          {{ say("connector-alias") }}
          <input
            v-model="form.alias"
            required
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("connector-display") }}
          <input
            v-model="form.displayName"
            class="sf-field mt-1"
          />
        </label>
        <AppToggle v-model="form.enabled">{{ say("connector-enabled") }}</AppToggle>

        <template v-if="editing.kind === 'webhook'">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("events-webhook-url") }}
            <input
              v-model="form.url"
              required
              spellcheck="false"
              placeholder="https://siem.example/hooks/saffui"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("events-webhook-filter") }} <AppHint name="events-webhook-filter-help" />
            <input
              v-model="form.filter"
              required
              spellcheck="false"
              placeholder="user.* session.revoked"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("events-webhook-secret") }} <AppHint name="events-webhook-secret-help" />
            <input
              v-model="form.secret"
              :required="!secretOnFile"
              :placeholder="secretOnFile ? '**********' : ''"
              spellcheck="false"
              autocomplete="off"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </template>
        <template v-else-if="editing.kind === 'scim-outbound'">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("connector-base-url") }}
            <input
              v-model="form.baseUrl"
              required
              spellcheck="false"
              placeholder="https://app.example/scim/v2"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </template>
        <template v-else>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("connector-delivery") }}
            <select
              v-model="form.delivery"
              class="sf-field mt-1"
            >
              <option value="push">{{ say("connector-delivery-push") }}</option>
              <option value="poll">{{ say("connector-delivery-poll") }}</option>
            </select>
          </label>
          <label v-if="form.delivery === 'push'" class="block text-[11px] font-medium text-muted">
            {{ say("connector-endpoint") }}
            <input
              v-model="form.endpoint"
              required
              spellcheck="false"
              placeholder="https://soc.example/events"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("connector-audience") }}
            <input
              v-model="form.audience"
              spellcheck="false"
              :required="form.delivery === 'poll'"
              class="sf-field mt-1 font-mono"
            />
            <span v-if="form.delivery === 'push'" class="mt-0.5 block font-normal text-faint">
              {{ say("connector-audience-hint") }}
            </span>
          </label>
          <fieldset class="block text-[11px] font-medium text-muted">
            <legend>{{ say("connector-events") }}</legend>
            <div class="mt-1 grid gap-1">
              <label
                v-for="[short, uri] in KNOWN_EVENTS"
                :key="uri"
                class="flex cursor-pointer items-center gap-2 font-normal"
              >
                <input v-model="form.events" type="checkbox" :value="uri" class="accent-current" />
                <span class="font-mono text-[10.5px]">{{ short }}</span>
              </label>
            </div>
            <span class="mt-0.5 block font-normal text-faint">
              {{ say("connector-events-hint") }}
            </span>
          </fieldset>
        </template>

        <label v-if="editing.kind !== 'webhook'" class="block text-[11px] font-medium text-muted">
          {{ say("connector-bearer") }}
          <input
            v-model="form.bearer"
            type="password"
            autocomplete="off"
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
          <span v-if="bearerOnFile" class="mt-0.5 block font-normal text-faint">
            {{ say("connector-bearer-kept") }}
          </span>
        </label>

        <button
          type="submit"
          :disabled="saving"
          class="self-start rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink disabled:opacity-40"
        >
          {{ say("settings-save") }}
        </button>

        <div v-if="editing.alias" class="mt-2 rounded-lg border border-danger/40 p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
            {{ say("settings-danger") }}
          </div>
          <p class="mt-1 text-[11px] text-muted">{{ say("connector-delete-lede") }}</p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomName"
              :placeholder="editing.alias"
              spellcheck="false"
              class="sf-field font-mono"
            />
            <button
              type="button"
              class="sf-button sf-button-danger disabled:opacity-40"
              :disabled="doomName !== editing.alias"
              @click="drop"
            >
              {{ say("connector-delete") }}
            </button>
          </div>
        </div>
      </form>
    </AppDrawer>
  </div>
</template>
