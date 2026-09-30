<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { keepWalletIdentity, readWalletIdentity } from "@/services/walletIdentity";
import { afterWrites } from "@/services/writes";
import type { WalletIdentity } from "@/models/walletIdentity";
import type { CredentialIssuerBrief } from "@/models/credentialIssuers";
import {
  buildWalletIdentity,
  listDraftClaims,
  readWalletIdentityDraft,
} from "./walletIdentityForm";
import type { WalletIdentityDraft } from "./walletIdentityForm";

const props = defineProps<{
  realm: string;
  /// Whether the process runs the verifier, `null` until it is known.
  running: boolean | null;
  /// The issuers the realm names, the only ones a profile may name.
  issuers: CredentialIssuerBrief[];
}>();

const held = ref<WalletIdentity | null>(null);
const unread = ref("");
const draft = ref<WalletIdentityDraft>({
  format: "ldp_vc",
  types: "",
  claims: "",
  issuer: "",
  identifier: "",
});

const claims = computed(() => listDraftClaims(draft.value));
/// A profile names types, an issuer, and one of its claims as the identifier.
const ready = computed(
  () =>
    draft.value.types.trim() !== "" &&
    draft.value.issuer !== "" &&
    claims.value.includes(draft.value.identifier),
);
/// Whether saving would change the issuer or the claim every linked identity
/// was digested from, which leaves those identities answering nobody.
const reshapes = computed(
  () =>
    held.value !== null &&
    (held.value.issuer !== draft.value.issuer ||
      held.value.identifier_path.join(".") !== draft.value.identifier),
);

/// A stored instant, as this browser writes one.
function stamp(at: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(at),
  );
}

async function load() {
  unread.value = "";
  try {
    held.value = await readWalletIdentity(props.realm);
  } catch (refused) {
    unread.value = refused instanceof Error ? refused.message : String(refused);
    return;
  }
  if (held.value) draft.value = readWalletIdentityDraft(held.value);
}

async function keep() {
  try {
    held.value = await keepWalletIdentity(props.realm, buildWalletIdentity(draft.value));
  } catch {
    // The server's words are on the toast rail.
  }
}

onMounted(load);
afterWrites(load);
watch(() => props.realm, load);
</script>

<template>
  <div class="mt-4 flex w-full flex-col gap-3 rounded-lg border border-border bg-surface p-4 text-xs">
    <div class="flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("wallet-identity-title") }} <AppHint name="wallet-identity-help" />
      <span class="rounded border border-border px-1.5 py-0.5 text-[10px] tracking-normal normal-case">{{
        say("settings-experimental")
      }}</span>
    </div>
    <p v-if="running === false" class="text-[11px] leading-5 text-muted">
      {{ say("wallet-identity-not-running") }}
    </p>
    <p v-if="unread" class="text-[11px] text-danger">{{ unread }}</p>
    <p v-else-if="held" class="text-[11px] text-muted">
      {{ say("wallet-identity-kept", { by: held.updated_by, at: stamp(held.updated_at) }) }}
    </p>
    <p v-else class="text-[11px] text-faint">{{ say("wallet-identity-none") }}</p>
    <p v-if="!issuers.length" class="text-[11px] leading-5 text-muted">
      {{ say("wallet-identity-no-issuer") }}
    </p>
    <form class="grid gap-2 sm:grid-cols-2" @submit.prevent="keep">
      <label class="block text-[11px] font-medium text-muted">
        {{ say("presentations-format") }}
        <select v-model="draft.format" class="sf-field mt-1 w-fit">
          <option value="ldp_vc">{{ say("presentations-format-ldp") }}</option>
          <option value="dc+sd-jwt">{{ say("presentations-format-sd-jwt") }}</option>
        </select>
      </label>
      <label class="block text-[11px] font-medium text-muted">
        {{ say("wallet-identity-issuer") }} <AppHint name="wallet-identity-issuer-help" />
        <select v-model="draft.issuer" class="sf-field mt-1">
          <option value="" disabled>{{ say("wallet-identity-issuer-pick") }}</option>
          <option v-for="named in issuers" :key="named.id" :value="named.issuer">
            {{ named.name }} ({{ named.issuer }})
          </option>
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
        {{ say("presentations-claims") }} <AppHint name="wallet-identity-claims-help" />
        <textarea
          v-model="draft.claims"
          rows="3"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
          :placeholder="draft.format === 'ldp_vc' ? 'credentialSubject.UIN' : 'personal_administrative_number'"
        ></textarea>
      </label>
      <label class="block text-[11px] font-medium text-muted sm:col-span-2">
        {{ say("wallet-identity-identifier") }} <AppHint name="wallet-identity-identifier-help" />
        <select v-model="draft.identifier" class="sf-field mt-1 w-fit font-mono">
          <option value="" disabled>{{ say("wallet-identity-identifier-pick") }}</option>
          <option v-for="claim in claims" :key="claim" :value="claim">{{ claim }}</option>
        </select>
      </label>
      <p v-if="reshapes" class="text-[11px] leading-5 text-warn sm:col-span-2">
        {{ say("wallet-identity-reshapes") }}
      </p>
      <button type="submit" :disabled="!ready" class="w-fit sf-button sf-button-primary">
        {{ say("wallet-identity-keep") }}
      </button>
    </form>
  </div>
</template>
