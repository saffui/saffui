<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import {
  forgetCredentialIssuer,
  nameCredentialIssuer,
  readCredentialIssuerKeys,
  trustCredentialIssuer,
} from "@/services/settings";
import type { CredentialIssuerBrief, CredentialIssuerList } from "@/models/credentialIssuers";
import type { TrustAnchorBrief } from "@/models/trustAnchors";
import {
  buildIssuerWrite,
  buildTrustWrite,
  emptyIssuerDraft,
  isIssuerReady,
  isTrustReady,
  nameAuthorities,
  readTrustDraft,
} from "./credentialIssuerForm";
import type { TrustDraft } from "./credentialIssuerForm";

const props = defineProps<{
  realm: string;
  /// The issuers the realm names, `null` until they are read.
  issuers: CredentialIssuerList | null;
  /// The authorities the realm trusts, the only ones an issuer is trusted
  /// through.
  anchors: TrustAnchorBrief[];
}>();
/// The page owns the list, and reads it again when told it changed.
const emit = defineEmits<{ changed: [] }>();

const draft = ref(emptyIssuerDraft());
/// The issuer whose trust is being changed, and the change as typed.
const retrusting = ref<{ id: string; trust: TrustDraft } | null>(null);

const ready = computed(() => isIssuerReady(draft.value));

/// A stored instant, as this browser writes one.
function stamp(at: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(at),
  );
}

// Each refusal is on the toast rail, in the server's words, and what was
// typed stays to be fixed.
async function name() {
  try {
    await nameCredentialIssuer(props.realm, buildIssuerWrite(draft.value));
  } catch {
    return;
  }
  draft.value = emptyIssuerDraft();
  emit("changed");
}

async function readAgain(issuer: string) {
  try {
    await readCredentialIssuerKeys(props.realm, issuer);
  } catch {
    // The keys read before are kept.
    return;
  }
  emit("changed");
}

function retrust(named: CredentialIssuerBrief) {
  retrusting.value = { id: named.id, trust: readTrustDraft(named) };
}

async function keepTrust() {
  const change = retrusting.value;
  if (!change) return;
  try {
    await trustCredentialIssuer(props.realm, change.id, buildTrustWrite(change.trust));
  } catch {
    return;
  }
  retrusting.value = null;
  emit("changed");
}

async function forget(issuer: string) {
  try {
    await forgetCredentialIssuer(props.realm, issuer);
  } catch {
    return;
  }
  if (retrusting.value?.id === issuer) retrusting.value = null;
  emit("changed");
}

watch(
  () => props.realm,
  () => {
    draft.value = emptyIssuerDraft();
    retrusting.value = null;
  },
);
</script>

<template>
  <div class="mt-4 flex w-full flex-col gap-3 rounded-lg border border-border bg-surface p-4 text-xs">
    <div class="flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("credential-issuers-title") }} <AppHint name="credential-issuers-help" />
      <span class="rounded border border-border px-1.5 py-0.5 text-[10px] tracking-normal normal-case">{{
        say("settings-experimental")
      }}</span>
    </div>
    <p v-if="issuers && !issuers.running" class="text-[11px] leading-5 text-muted">
      {{ say("credential-issuers-not-running") }}
    </p>
    <p v-if="issuers && !issuers.items.length" class="text-[11px] text-faint">
      {{ say("credential-issuers-empty") }}
    </p>
    <ul v-if="issuers?.items.length" class="grid gap-1.5">
      <li
        v-for="named in issuers.items"
        :key="named.id"
        class="grid gap-2 rounded-md border border-border bg-surface-2 px-3 py-2"
      >
        <div class="flex items-start gap-3">
          <div class="min-w-0 flex-1">
            <div class="text-[12px] font-medium text-ink">{{ named.name }}</div>
            <div class="mt-0.5 font-mono text-[11px] break-all text-muted">{{ named.issuer }}</div>
            <template v-if="named.trusted_by === 'certificate'">
              <div class="mt-0.5 text-[10.5px] text-muted">{{ say("credential-issuers-through") }}</div>
              <div
                v-for="authority in nameAuthorities(named, anchors)"
                :key="authority"
                class="font-mono text-[10px] break-all text-faint"
              >
                {{ authority }}
              </div>
              <div class="mt-0.5 text-[10.5px] text-muted">{{ say("credential-issuers-issues") }}</div>
              <div
                v-for="issued in named.credential_types"
                :key="issued"
                class="font-mono text-[10px] break-all text-faint"
              >
                {{ issued }}
              </div>
            </template>
            <template v-else>
              <div class="mt-0.5 text-[10.5px] text-muted">
                {{
                  say("credential-issuers-read", {
                    count: named.keys.length,
                    at: named.read_at ? stamp(named.read_at) : "",
                  })
                }}
              </div>
              <div class="font-mono text-[10px] break-all text-faint">{{ named.read_from }}</div>
            </template>
          </div>
          <div class="flex shrink-0 flex-col gap-1.5">
            <button
              v-if="named.trusted_by === 'certificate'"
              type="button"
              class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface"
              @click="retrust(named)"
            >
              {{ say("credential-issuers-retrust") }}
            </button>
            <button
              v-else
              type="button"
              class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface"
              @click="readAgain(named.id)"
            >
              {{ say("credential-issuers-read-again") }}
            </button>
            <button
              type="button"
              class="rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface"
              @click="forget(named.id)"
            >
              {{ say("credential-issuers-forget") }}
            </button>
          </div>
        </div>
        <form
          v-if="retrusting?.id === named.id"
          class="grid gap-2 border-t border-border pt-2 sm:grid-cols-2"
          @submit.prevent="keepTrust"
        >
          <fieldset class="block text-[11px] font-medium text-muted">
            <legend>
              {{ say("credential-issuers-anchors") }} <AppHint name="credential-issuers-anchors-help" />
            </legend>
            <div class="mt-1 grid gap-1">
              <label
                v-for="anchor in anchors"
                :key="anchor.id"
                class="flex cursor-pointer items-start gap-2 font-normal"
              >
                <input
                  v-model="retrusting.trust.anchors"
                  type="checkbox"
                  :value="anchor.id"
                  class="mt-0.5 accent-accent"
                />
                <span class="font-mono text-[10.5px] break-all">{{ anchor.subject }}</span>
              </label>
            </div>
          </fieldset>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("credential-issuers-types") }} <AppHint name="credential-issuers-types-help" />
            <textarea
              v-model="retrusting.trust.types"
              rows="3"
              class="sf-field mt-1 font-mono"
              spellcheck="false"
              placeholder="urn:eudi:pid:1"
            ></textarea>
          </label>
          <div class="flex gap-2 sm:col-span-2">
            <button
              type="submit"
              :disabled="!isTrustReady(retrusting.trust)"
              class="w-fit sf-button sf-button-primary"
            >
              {{ say("credential-issuers-keep-trust") }}
            </button>
            <button
              type="button"
              class="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface"
              @click="retrusting = null"
            >
              {{ say("action-cancel") }}
            </button>
          </div>
        </form>
      </li>
    </ul>
    <form class="grid gap-2 sm:grid-cols-2" @submit.prevent="name">
      <label class="block text-[11px] font-medium text-muted">
        {{ say("credential-issuers-name") }}
        <input v-model="draft.name" class="sf-field mt-1" maxlength="200" />
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("credential-issuers-issuer") }} <AppHint name="credential-issuers-issuer-help" />
        <input
          v-model="draft.issuer"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
          placeholder="https://issuer.example.org"
        />
      </label>
      <label class="block text-[11px] font-medium text-muted sm:col-span-2">
        {{ say("credential-issuers-trusted-by") }} <AppHint name="credential-issuers-trusted-by-help" />
        <select v-model="draft.trusted_by" class="sf-field mt-1 block w-fit">
          <option value="metadata">{{ say("credential-issuers-by-metadata") }}</option>
          <option value="certificate">{{ say("credential-issuers-by-certificate") }}</option>
        </select>
      </label>
      <template v-if="draft.trusted_by === 'certificate'">
        <fieldset class="block text-[11px] font-medium text-muted">
          <legend>
            {{ say("credential-issuers-anchors") }} <AppHint name="credential-issuers-anchors-help" />
          </legend>
          <p v-if="!anchors.length" class="mt-1 font-normal text-faint">
            {{ say("credential-issuers-no-anchor") }}
          </p>
          <div class="mt-1 grid gap-1">
            <label
              v-for="anchor in anchors"
              :key="anchor.id"
              class="flex cursor-pointer items-start gap-2 font-normal"
            >
              <input v-model="draft.anchors" type="checkbox" :value="anchor.id" class="mt-0.5 accent-accent" />
              <span class="font-mono text-[10.5px] break-all">{{ anchor.subject }}</span>
            </label>
          </div>
        </fieldset>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("credential-issuers-types") }} <AppHint name="credential-issuers-types-help" />
          <textarea
            v-model="draft.types"
            rows="3"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
            placeholder="urn:eudi:pid:1"
          ></textarea>
        </label>
        <p class="text-[11px] leading-5 text-muted sm:col-span-2">
          {{ say("credential-issuers-certificate-note") }}
        </p>
      </template>
      <button type="submit" :disabled="!ready" class="w-fit sf-button sf-button-primary sm:col-span-2">
        {{ say("credential-issuers-name-it") }}
      </button>
    </form>
  </div>
</template>
