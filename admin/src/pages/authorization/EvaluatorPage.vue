<script setup lang="ts">
// One place to ask what a person would get: the token they would carry, and
// the four ways this build decides. Decides nothing itself: the questions
// are put the way a resource server puts them, and the answers are the
// engine's own, recorded in the same log as any live decision.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import PageTabs from "@/components/PageTabs.vue";
import {
  evaluate,
  listAuthzScopes,
  listDecisions,
  listDisagreements,
  listPolicies,
  listResources,
} from "@/services/authz";
import { listClients, previewToken, type PreviewedClaim } from "@/services/clients";
import { afterWrites } from "@/services/writes";
import type {
  DecisionRow,
  EvaluateAnswer,
  EvaluateQuestion,
  PolicyRow,
  ResourceRow,
  ScopeRow,
} from "@/models/authz";
import type { ClientBrief } from "@/models/client";

const route = useRoute();

/// The evaluator keeps its own sidebar entry and is also a board of the
/// authorization screen, so both paths lead here.
function boardAt(leaf: string): string {
  return leaf === "evaluator"
    ? `/${realm.value}/evaluator`
    : `/${realm.value}/authorization?board=${leaf}`;
}
const realm = computed(() => String(route.params.realm));
const failed = ref("");

/// The families, by the names people use for them, each tied to what this
/// build actually runs. Role and attribute families are the same door, the
/// policy question, told apart by the kind of policy they name; a
/// relationship is its own engine and needs no policy at all.
const RBAC_KINDS = ["role", "group", "user", "client", "client-scope"];
const ABAC_KINDS = ["attribute", "regex", "time"];

type Asking = "token" | "permission" | "rbac" | "abac" | "rebac";
const asking = ref<Asking>("permission");

const subject = ref("");
const organization = ref("");
const clientId = ref("");
const policyId = ref("");
const resource = ref("");
const scope = ref("");
const objectType = ref("");
const objectId = ref("");
const relation = ref("");
const tokenScope = ref("openid profile");

const clients = ref<ClientBrief[]>([]);
const policies = ref<PolicyRow[]>([]);
const resources = ref<ResourceRow[]>([]);
const scopes = ref<ScopeRow[]>([]);
const verdict = ref<EvaluateAnswer | null>(null);
const claims = ref<PreviewedClaim[] | null>(null);
const copied = ref(false);

const decisions = ref<DecisionRow[]>([]);
const disagreements = ref<DecisionRow[]>([]);

/// Only the policies of the family being asked about, so the picker of an
/// RBAC question never offers an attribute rule.
const offered = computed(() => {
  const kinds = asking.value === "rbac" ? RBAC_KINDS : ABAC_KINDS;
  const kept = policies.value.filter((held) => kinds.includes(held.policy_type));
  // An aggregated policy composes others and belongs to whichever family
  // its parts do, which nothing here can know: it is offered to both.
  return [...kept, ...policies.value.filter((held) => held.policy_type === "aggregated")];
});

async function load() {
  failed.value = "";
  try {
    [decisions.value, disagreements.value] = await Promise.all([
      listDecisions(realm.value),
      listDisagreements(realm.value),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function loadServer() {
  policyId.value = "";
  if (!clientId.value) return;
  try {
    [policies.value, resources.value, scopes.value] = await Promise.all([
      listPolicies(realm.value, clientId.value),
      listResources(realm.value, clientId.value),
      listAuthzScopes(realm.value, clientId.value),
    ]);
  } catch {
    // A client with no decision point holds none of these, which is an
    // answer rather than a failure: the pickers stay empty.
    policies.value = [];
    resources.value = [];
    scopes.value = [];
  }
}

onMounted(async () => {
  try {
    clients.value = (await listClients(realm.value, 0, 100)).items;
    clientId.value = clients.value[0]?.client_id ?? "";
    await loadServer();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
  await load();
});
// An evaluation is journalled like any decision, so a question asked here
// lands in the log below it.
afterWrites(load);

function question(): EvaluateQuestion | null {
  if (asking.value === "rbac" || asking.value === "abac") {
    if (!clientId.value || !policyId.value) return null;
    return { kind: "policy", server_id: clientId.value, policy_id: policyId.value };
  }
  if (asking.value === "permission") {
    if (!clientId.value || !resource.value.trim() || !scope.value.trim()) return null;
    return {
      kind: "permission",
      server_id: clientId.value,
      resource: resource.value.trim(),
      scope: scope.value.trim(),
    };
  }
  if (!objectType.value.trim() || !objectId.value.trim() || !relation.value.trim()) return null;
  return {
    kind: "relationship",
    object_type: objectType.value.trim(),
    object_id: objectId.value.trim(),
    relation: relation.value.trim(),
  };
}

async function ask() {
  failed.value = "";
  verdict.value = null;
  claims.value = null;
  copied.value = false;
  if (!subject.value.trim()) return;
  try {
    if (asking.value === "token") {
      if (!clientId.value) return;
      claims.value = (
        await previewToken(realm.value, {
          user_id: subject.value.trim(),
          client_id: clientId.value,
          scope: tokenScope.value.trim() || undefined,
        })
      ).claims;
      return;
    }
    const asked = question();
    if (!asked) return;
    verdict.value = await evaluate(
      realm.value,
      subject.value.trim(),
      asked,
      organization.value.trim() || undefined,
    );
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

/// The same call, as the caller would make it. What is copied is what was
/// asked, so a question that reproduces is a question that can be reported.
async function copyAsRequest() {
  const asked = asking.value === "token" ? null : question();
  const body =
    asking.value === "token"
      ? { user_id: subject.value.trim(), client_id: clientId.value, scope: tokenScope.value.trim() }
      : { subject: subject.value.trim(), organization: organization.value.trim() || undefined, question: asked };
  const leaf = asking.value === "token" ? "token-preview" : "authz/evaluate";
  const text = `POST /admin/realms/${realm.value}/${leaf}\n${JSON.stringify(body, null, 2)}`;
  try {
    await navigator.clipboard.writeText(text);
    copied.value = true;
  } catch {
    // A browser that refuses the clipboard says nothing here: the question
    // is on screen already.
  }
}

/// The reasons as the engine words them: a tagged record whose `reason` is
/// the slug and whose other fields name what it is about. Rendered as they
/// came, because the engine grows arms and a reader that only knows today's
/// would drop tomorrow's silently.
function reasons(detail: { reasons?: unknown[] }): { slug: string; said: string }[] {
  return (detail.reasons ?? []).map((held) => {
    if (held && typeof held === "object") {
      const { reason, ...rest } = held as Record<string, unknown>;
      const said = Object.entries(rest)
        .map(([name, value]) => `${name}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
        .join(", ");
      return { slug: String(reason ?? "reason"), said };
    }
    return { slug: String(held), said: "" };
  });
}

function parted(row: DecisionRow): boolean {
  return row.reported.toLowerCase() !== row.computed;
}
function instant(millis: number | null): string {
  return millis ? new Date(millis).toLocaleTimeString() : "";
}
function worded(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}
</script>

<template>
  <div>
    <PageTabs
      :leaves="['models', 'resources', 'scopes', 'policies', 'permissions', 'evaluator']"
      at="evaluator"
      :to="boardAt"
      saying="authz-board"
      class="mb-3"
    />

    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("evaluator-title") }}</h1>
        <p class="mt-1 max-w-2xl text-xs text-muted">
          {{ say("evaluator-lede") }} <AppHint name="evaluator-lede-help" />
        </p>
      </div>
      <button
        type="button"
        class="rounded-md border border-border px-2.5 py-1.5 text-xs font-medium text-muted hover:text-ink"
        @click="copyAsRequest"
      >
        {{ copied ? say("evaluator-copied") : say("evaluator-copy") }}
      </button>
    </div>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="mt-4 grid min-w-0 gap-4 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
      <form class="rounded-lg border border-border bg-surface p-4" @submit.prevent="ask">
        <div class="flex flex-wrap gap-1">
          <button
            v-for="held in (['token', 'permission', 'rbac', 'abac', 'rebac'] as const)"
            :key="held"
            type="button"
            class="rounded-md px-2 py-1 text-[11px] font-semibold"
            :class="asking === held ? 'bg-accent/12 text-accent' : 'text-muted hover:text-ink'"
            @click="asking = held"
          >
            {{ say(`evaluator-ask-${held}`) }}
          </button>
        </div>
        <p class="mt-2 text-[11px] text-muted">{{ say(`evaluator-said-${asking}`) }}</p>

        <label class="mt-3 block text-[11px] font-medium text-muted">
          {{ say("evaluator-subject") }}
          <input
            v-model="subject"
            placeholder="ada"
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
        </label>

        <label
          v-if="asking !== 'token' && asking !== 'rebac'"
          class="mt-3 block text-[11px] font-medium text-muted"
        >
          {{ say("evaluator-organization") }} <AppHint name="evaluator-organization-help" />
          <input
            v-model="organization"
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
        </label>

        <label v-if="asking !== 'rebac'" class="mt-3 block text-[11px] font-medium text-muted">
          {{ asking === "token" ? say("clients-title") : say("evaluator-server") }}
          <select
            v-model="clientId"
            class="sf-field mt-1 font-mono"
            @change="loadServer"
          >
            <option v-for="held in clients" :key="held.client_id" :value="held.client_id">
              {{ held.client_id }}
            </option>
          </select>
        </label>

        <label v-if="asking === 'token'" class="mt-3 block text-[11px] font-medium text-muted">
          {{ say("preview-scope") }}
          <input
            v-model="tokenScope"
            spellcheck="false"
            class="sf-field mt-1 font-mono"
          />
        </label>

        <template v-if="asking === 'rbac' || asking === 'abac'">
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-policy") }}
            <select
              v-model="policyId"
              class="sf-field mt-1"
            >
              <option value="">{{ say("evaluator-pick-policy") }}</option>
              <option v-for="held in offered" :key="held.policy_id" :value="held.policy_id">
                {{ held.name }} ({{ held.policy_type }})
              </option>
            </select>
          </label>
          <p v-if="!offered.length" class="mt-1.5 text-[11px] text-muted">
            {{ say("evaluator-no-policy") }}
          </p>
        </template>

        <template v-if="asking === 'permission'">
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-resource") }}
            <input
              v-model="resource"
              list="evaluator-resources"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
            <datalist id="evaluator-resources">
              <option v-for="held in resources" :key="held.resource_id" :value="held.name" />
            </datalist>
          </label>
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-scope") }}
            <input
              v-model="scope"
              list="evaluator-scopes"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
            <datalist id="evaluator-scopes">
              <option v-for="held in scopes" :key="held.scope_id" :value="held.name" />
            </datalist>
          </label>
        </template>

        <template v-if="asking === 'rebac'">
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-object-type") }}
            <input
              v-model="objectType"
              placeholder="document"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-object-id") }}
            <input
              v-model="objectId"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("evaluator-relation") }}
            <input
              v-model="relation"
              placeholder="viewer"
              spellcheck="false"
              class="sf-field mt-1 font-mono"
            />
          </label>
        </template>

        <button
          type="submit"
          class="sf-button sf-button-primary mt-4 w-full justify-center"
        >
          {{ say("evaluator-run") }}
        </button>
      </form>

      <div class="min-w-0">
        <div v-if="verdict" class="rounded-lg border border-border bg-surface p-4">
          <div class="flex flex-wrap items-center gap-3">
            <span
              class="rounded px-2.5 py-1 text-sm font-semibold"
              :class="
                verdict.computed === 'permit'
                  ? 'bg-ok/12 text-ok'
                  : verdict.computed === 'deny'
                    ? 'bg-danger/12 text-danger'
                    : 'bg-warn/12 text-warn'
              "
              >{{ say(`evaluator-verdict-${verdict.computed}`) }}</span
            >
            <span
              v-if="verdict.reported.toLowerCase() !== verdict.computed"
              class="rounded bg-warn/12 px-2 py-0.5 text-[11px] font-semibold text-warn"
              >{{ say("evaluator-disagreement") }}</span
            >
            <span class="ml-auto font-mono text-[10.5px] text-faint">{{ verdict.decision_id }}</span>
          </div>

          <template v-if="verdict.walk">
            <div class="mt-4 flex items-center gap-2">
              <span class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("graph-walk-title") }}
              </span>
              <AppHint name="graph-walk-help" />
              <span v-if="verdict.walk.stopped" class="text-[11px] text-warn">
                {{ verdict.walk.stopped }}
              </span>
            </div>
            <ol class="mt-2 flex flex-col gap-0.5">
              <li
                v-for="(step, at) in verdict.walk.steps"
                :key="`${at}-${step.asked}`"
                class="flex items-baseline gap-2 text-[11px]"
                :style="{ paddingLeft: `${step.depth * 14}px` }"
              >
                <span
                  class="w-14 shrink-0 text-right text-[10px]"
                  :class="
                    step.answered === null
                      ? 'text-faint'
                      : step.answered
                        ? 'text-ok'
                        : 'text-muted'
                  "
                >
                  {{
                    step.answered === null
                      ? ""
                      : step.answered
                        ? say("graph-walk-reached")
                        : say("graph-walk-missed")
                  }}
                </span>
                <span class="font-mono text-ink">{{ step.asked }}</span>
                <span class="truncate text-faint">{{ step.rule }}</span>
                <span v-if="step.note" class="text-faint italic">{{ step.note }}</span>
              </li>
            </ol>
            <p v-if="verdict.walk.cut > 0" class="mt-2 text-[10.5px] text-faint">
              {{ say("graph-walk-cut", { held: verdict.walk.cut }) }}
            </p>
          </template>
          <div class="mt-3 grid gap-2 sm:grid-cols-2">
            <div class="rounded-md border border-border px-3 py-2">
              <div class="text-[10px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("evaluator-col-reported") }}
              </div>
              <div class="mt-0.5 font-mono text-xs">{{ verdict.reported }}</div>
            </div>
            <div class="rounded-md border border-border px-3 py-2">
              <div class="text-[10px] font-semibold tracking-[0.08em] text-faint uppercase">
                {{ say("evaluator-col-computed") }}
              </div>
              <div class="mt-0.5 font-mono text-xs">{{ verdict.computed }}</div>
            </div>
          </div>
          <p
            v-if="verdict.reported.toLowerCase() !== verdict.computed"
            class="mt-2 rounded-md bg-warn/8 px-3 py-2 text-[11px] text-warn"
          >
            {{ say("evaluator-parted-said") }}
          </p>
          <ul v-if="reasons(verdict.detail).length" class="mt-3 space-y-1.5">
            <li
              v-for="(row, at) in reasons(verdict.detail)"
              :key="at"
              class="flex flex-wrap items-baseline gap-2 border-b border-border/60 pb-1.5 last:border-0"
            >
              <span class="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px]">{{
                row.slug
              }}</span>
              <span class="font-mono text-[10.5px] text-muted">{{ row.said }}</span>
            </li>
          </ul>
          <p v-else class="mt-3 text-xs text-muted">{{ say("evaluator-no-reasons") }}</p>
        </div>

        <div
          v-if="claims"
          class="sf-list overflow-x-auto"
        >
          <table class="sf-table">
            <thead>
              <tr>
                <th>{{ say("preview-col-claim") }}</th>
                <th>{{ say("preview-col-value") }}</th>
                <th>{{ say("preview-col-origin") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in claims"
                :key="row.claim + row.origin"
                class="border-b border-border/60 last:border-0"
              >
                <td class="font-mono text-[11.5px]">{{ row.claim }}</td>
                <td class="max-w-80 px-3 py-2 font-mono text-[10.5px] break-all">
                  {{ worded(row.value) }}
                </td>
                <td class="text-[10.5px] text-muted">{{ row.origin }}</td>
              </tr>
            </tbody>
          </table>
          <p v-if="!claims.length" class="px-3 py-3 text-xs text-muted">{{ say("preview-none") }}</p>
        </div>

        <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-muted uppercase">
          {{ say("evaluator-log-recent") }}
        </h2>
        <p v-if="!decisions.length" class="mt-2 text-xs text-muted">
          {{ say("evaluator-log-empty") }}
        </p>
        <div v-else class="sf-list mt-2 overflow-x-auto">
          <table class="sf-table">
            <thead>
              <tr>
                <th>{{ say("evaluator-col-when") }}</th>
                <th>{{ say("evaluator-col-subject") }}</th>
                <th>{{ say("evaluator-col-asked") }}</th>
                <th>{{ say("evaluator-col-reported") }}</th>
                <th>{{ say("evaluator-col-computed") }}</th>
                <th>{{ say("evaluator-col-took") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in decisions"
                :key="row.decision_id"
                class="border-b border-border/60 last:border-0"
                :class="parted(row) ? 'bg-warn/6' : ''"
              >
                <td class="text-[10.5px] text-muted">
                  {{ instant(row.occurred_at_millis) }}
                </td>
                <td class="font-mono text-[11px]">{{ row.subject_id }}</td>
                <td class="font-mono text-[10.5px] break-all">
                  {{ row.action }} {{ row.resource_kind
                  }}<template v-if="row.resource_ref">:{{ row.resource_ref }}</template>
                </td>
                <td class="font-mono text-[10.5px]">{{ row.reported }}</td>
                <td>
                  <span
                    class="rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                    :class="
                      row.computed === 'permit' ? 'bg-ok/12 text-ok' : 'bg-danger/12 text-danger'
                    "
                    >{{ row.computed }}</span
                  >
                </td>
                <td class="text-[10.5px] text-faint">{{ row.duration_us }}&#181;s</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2 class="mt-5 flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-muted uppercase">
          {{ say("evaluator-log-parted") }}
          <span class="rounded bg-warn/12 px-1.5 py-0.5 text-[10px] text-warn">{{
            disagreements.length
          }}</span>
          <AppHint name="evaluator-parted-help" />
        </h2>
        <p v-if="!disagreements.length" class="mt-2 text-xs text-muted">
          {{ say("evaluator-none-parted") }}
        </p>
        <ul v-else class="mt-2 rounded-lg border border-border bg-surface">
          <li
            v-for="row in disagreements"
            :key="row.decision_id"
            class="flex flex-wrap items-center gap-2 border-b border-border/60 px-3 py-2 text-xs last:border-0"
          >
            <span class="font-mono text-[11px]">{{ row.subject_id }}</span>
            <span class="font-mono text-[10.5px] text-muted break-all"
              >{{ row.action }} {{ row.resource_kind
              }}<template v-if="row.resource_ref">:{{ row.resource_ref }}</template></span
            >
            <span class="ml-auto font-mono text-[10.5px]">
              <span class="text-muted">{{ row.reported }}</span>
              <span class="mx-1 text-faint">&#8594;</span>
              <span class="font-semibold text-danger">{{ row.computed }}</span>
            </span>
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>
