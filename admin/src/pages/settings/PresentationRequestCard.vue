<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { askPresentation, readPresentation } from "@/services/presentations";
import type { PresentationMade, PresentationStanding } from "@/models/presentations";
import { buildPresentationQuery, readLines, readStatus } from "./presentationRequest";
import type { PresentationDraft } from "./presentationRequest";

const props = defineProps<{
  realm: string;
  /// Whether the process runs the verifier, `null` until it is known.
  running: boolean | null;
}>();

/// How often a pending request is read again.
const FOLLOW_EVERY_MS = 2_000;

const draft = ref<PresentationDraft>({ format: "ldp_vc", types: "", claims: "" });
const made = ref<PresentationMade | null>(null);
const standing = ref<PresentationStanding | null>(null);
const unread = ref<string | null>(null);
const now = ref(new Date());
let following: number | undefined;

const status = computed(() => (standing.value ? readStatus(standing.value, now.value) : null));
const qrImage = computed(() =>
  made.value?.qr ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(made.value.qr)}` : null,
);
const statusClass = computed(() => {
  switch (status.value) {
    case "verified":
      return "border-ok/40 text-ok";
    case "failed":
    case "refused":
      return "border-danger/40 text-danger";
    case "expired":
      return "border-warn/40 text-warn";
    default:
      return "border-border text-muted";
  }
});

/// A stored instant, as this browser writes one.
function stamp(at: string): string {
  return new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(new Date(at));
}

function stopFollowing() {
  if (following !== undefined) {
    window.clearInterval(following);
    following = undefined;
  }
}

function forget() {
  stopFollowing();
  made.value = null;
  standing.value = null;
  unread.value = null;
}

async function ask() {
  forget();
  try {
    made.value = await askPresentation(props.realm, buildPresentationQuery(draft.value));
  } catch {
    // The server's words are on the toast rail.
    return;
  }
  await follow();
  if (status.value === "pending") following = window.setInterval(follow, FOLLOW_EVERY_MS);
}

/// Read where the request stands, until an answer settles it or its window
/// closes.
async function follow() {
  now.value = new Date();
  if (!made.value) return;
  try {
    standing.value = await readPresentation(props.realm, made.value.id);
    now.value = new Date();
  } catch (refused) {
    unread.value = refused instanceof Error ? refused.message : String(refused);
    stopFollowing();
    return;
  }
  if (status.value !== "pending") stopFollowing();
}

async function copyLink() {
  if (!made.value) return;
  try {
    await navigator.clipboard.writeText(made.value.uri);
  } catch {
    // The link stays selectable; copying by hand still works.
  }
}

watch(() => props.realm, forget);
onBeforeUnmount(stopFollowing);
</script>

<template>
  <div class="mt-4 flex w-full flex-col gap-3 rounded-lg border border-border bg-surface p-4 text-xs">
    <div class="flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("presentations-title") }} <AppHint name="presentations-help" />
      <span class="rounded border border-border px-1.5 py-0.5 text-[10px] tracking-normal normal-case">{{
        say("settings-experimental")
      }}</span>
    </div>
    <p v-if="running === false" class="text-[11px] leading-5 text-muted">
      {{ say("presentations-not-running") }}
    </p>
    <form class="grid gap-2 sm:grid-cols-2" @submit.prevent="ask">
      <label class="block text-[11px] font-medium text-muted sm:col-span-2">
        {{ say("presentations-format") }}
        <select v-model="draft.format" class="sf-field mt-1 w-fit">
          <option value="ldp_vc">{{ say("presentations-format-ldp") }}</option>
          <option value="dc+sd-jwt">{{ say("presentations-format-sd-jwt") }}</option>
        </select>
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say(draft.format === "ldp_vc" ? "presentations-types-ldp" : "presentations-types-sd-jwt") }}
        <AppHint :name="draft.format === 'ldp_vc' ? 'presentations-types-ldp-help' : 'presentations-types-sd-jwt-help'" />
        <textarea
          v-model="draft.types"
          rows="3"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
          :placeholder="
            draft.format === 'ldp_vc'
              ? 'https://www.w3.org/2018/credentials#VerifiableCredential'
              : 'urn:eudi:pid:1'
          "
        ></textarea>
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("presentations-claims") }} <AppHint name="presentations-claims-help" />
        <textarea
          v-model="draft.claims"
          rows="3"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
          :placeholder="draft.format === 'ldp_vc' ? 'credentialSubject.fullName' : 'given_name'"
        ></textarea>
      </label>
      <button
        type="submit"
        :disabled="!readLines(draft.types).length"
        class="w-fit sf-button sf-button-primary"
      >
        {{ say("presentations-ask") }}
      </button>
    </form>

    <div v-if="made" class="flex flex-wrap items-start gap-4 rounded-md border border-border bg-surface-2 p-3">
      <img
        v-if="qrImage && status === 'pending'"
        :src="qrImage"
        :alt="say('presentations-qr-alt')"
        class="h-44 w-44 shrink-0 rounded"
      />
      <div class="grid min-w-0 flex-1 gap-2">
        <div class="flex flex-wrap items-center gap-2">
          <span
            v-if="status"
            class="inline-flex items-center rounded border px-1.5 py-0.5 text-[10.5px]"
            :class="statusClass"
          >
            {{ say(`presentations-status-${status}`) }}
          </span>
          <span v-if="status === 'pending'" class="text-[10.5px] text-muted">
            {{ say("presentations-waits-until", { at: stamp(made.expires_at) }) }}
          </span>
        </div>
        <template v-if="status === 'pending'">
          <div class="font-mono text-[10.5px] break-all text-faint">{{ made.uri }}</div>
          <button
            type="button"
            class="w-fit rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface"
            @click="copyLink"
          >
            {{ say("presentations-copy-link") }}
          </button>
        </template>
        <p v-if="unread" class="text-[11px] text-danger">
          {{ say("presentations-unread", { why: unread }) }}
        </p>
        <ul v-if="status === 'verified' && standing?.outcome?.credentials" class="grid gap-1.5">
          <li
            v-for="credential in standing.outcome.credentials"
            :key="credential.id"
            class="rounded-md border border-border bg-surface px-3 py-2"
          >
            <div class="font-mono text-[11px] break-all text-ink">{{ credential.issuer }}</div>
            <div v-if="credential.vct" class="font-mono text-[10.5px] break-all text-muted">
              {{ credential.vct }}
            </div>
            <div
              v-for="held in credential.types ?? []"
              :key="held"
              class="font-mono text-[10.5px] break-all text-muted"
            >
              {{ held }}
            </div>
            <div v-if="credential.claims.length" class="mt-1 text-[10.5px] text-faint">
              {{ say("presentations-claims-held", { claims: credential.claims.join(", ") }) }}
            </div>
          </li>
        </ul>
        <p v-if="status === 'refused'" class="text-[11px] text-danger">
          {{ say("presentations-refused-by-wallet", { why: standing?.outcome?.error ?? "" }) }}
        </p>
        <p v-if="status === 'failed'" class="text-[11px] text-danger">
          {{ say("presentations-failed-because", { why: standing?.outcome?.reason ?? "" }) }}
        </p>
        <p v-if="status === 'expired'" class="text-[11px] text-warn">
          {{ say("presentations-expired") }}
        </p>
      </div>
    </div>
  </div>
</template>
