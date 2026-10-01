<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import {
  keepVerifierSettings,
  readVerifier,
  requestVerifierCertificate,
  takeVerifierCertificate,
  withdrawVerifierKey,
} from "@/services/verifier";
import { afterWrites } from "@/services/writes";
import type { Verifier } from "@/models/verifier";
import {
  buildSubject,
  buildVerifierWrite,
  findKey,
  isCertificateValid,
  readVerifierDraft,
} from "./verifierIdentityForm";
import type { SubjectDraft, VerifierDraft } from "./verifierIdentityForm";

const props = defineProps<{ realm: string }>();

const held = ref<Verifier | null>(null);
const unread = ref("");
const draft = ref<VerifierDraft>({ identity: "did-web", dataset: "", registration: "" });
/// The draft as the realm's settings last read: one typed away from it
/// survives another write landing.
const read = ref<VerifierDraft | null>(null);
const subject = ref<SubjectDraft>({
  common_name: "",
  organization: "",
  organization_identifier: "",
  country: "",
});
const chain = ref("");
const now = ref(new Date());

const serving = computed(() => (held.value ? findKey(held.value.keys, "serving") : undefined));
const awaiting = computed(() => (held.value ? findKey(held.value.keys, "awaiting") : undefined));
const certified = computed(
  () => !!serving.value?.certificate && isCertificateValid(serving.value.certificate, now.value),
);
const write = computed(() => buildVerifierWrite(draft.value));
/// A serving key is withdrawn only while the realm presents itself otherwise.
const withdrawable = computed(() => held.value?.identity !== "x509-hash");

/// A stored instant, as this browser writes one.
function stamp(at: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(at),
  );
}

async function load() {
  unread.value = "";
  now.value = new Date();
  try {
    held.value = await readVerifier(props.realm);
  } catch (refused) {
    unread.value = refused instanceof Error ? refused.message : String(refused);
    return;
  }
  const fresh = readVerifierDraft(held.value);
  if (!read.value || isSameDraft(draft.value, read.value)) draft.value = fresh;
  read.value = fresh;
}

function isSameDraft(one: VerifierDraft, other: VerifierDraft): boolean {
  return (
    one.identity === other.identity &&
    one.dataset === other.dataset &&
    one.registration === other.registration
  );
}

// Each write's outcome is on the toast rail, in the server's words; the
// card is read again after every write that landed.
async function keep() {
  if (!write.value) return;
  try {
    const kept = await keepVerifierSettings(props.realm, write.value);
    draft.value = readVerifierDraft(kept);
    read.value = readVerifierDraft(kept);
  } catch {
    // Refused in the server's words, on the toast rail.
  }
}

async function draw() {
  try {
    await requestVerifierCertificate(props.realm, buildSubject(subject.value));
  } catch {
    return;
  }
  subject.value = { common_name: "", organization: "", organization_identifier: "", country: "" };
}

async function take() {
  try {
    await takeVerifierCertificate(props.realm, chain.value);
  } catch {
    return;
  }
  chain.value = "";
}

async function withdraw(kid: string) {
  try {
    await withdrawVerifierKey(props.realm, kid);
  } catch {
    // Refused in the server's words, on the toast rail.
  }
}

async function copyRequest() {
  if (!awaiting.value) return;
  try {
    await navigator.clipboard.writeText(awaiting.value.request);
  } catch {
    // The request stays selectable; copying by hand still works.
  }
}

onMounted(load);
afterWrites(load);
watch(
  () => props.realm,
  () => {
    read.value = null;
    void load();
  },
);
</script>

<template>
  <div class="mt-4 flex w-full flex-col gap-3 rounded-lg border border-border bg-surface p-4 text-xs">
    <div class="flex items-center gap-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
      {{ say("verifier-identity-title") }} <AppHint name="verifier-identity-help" />
      <span class="rounded border border-border px-1.5 py-0.5 text-[10px] tracking-normal normal-case">{{
        say("settings-experimental")
      }}</span>
    </div>
    <p v-if="held && !held.running" class="text-[11px] leading-5 text-muted">
      {{ say("verifier-identity-not-running") }}
    </p>
    <p v-if="unread" class="text-[11px] text-danger">{{ unread }}</p>
    <template v-else-if="held">
      <p class="text-[11px] text-muted">
        <template v-if="held.identity === 'x509-hash' && serving?.certificate">
          {{ say("verifier-identity-by-certificate") }}
          <span class="font-mono break-all text-ink">{{ serving.certificate.client_id }}</span>
        </template>
        <template v-else>{{ say("verifier-identity-by-did") }}</template>
      </p>

      <div
        v-if="serving?.certificate"
        class="flex items-start gap-3 rounded-md border border-border bg-surface-2 px-3 py-2"
      >
        <div class="min-w-0 flex-1">
          <div class="text-[10.5px] font-semibold text-muted">{{ say("verifier-serving") }}</div>
          <div class="text-[11px] break-all text-ink">
            {{
              say("verifier-serving-issued", {
                subject: serving.certificate.subjects[0] ?? "",
                issuer: serving.certificate.subjects[1] ?? "",
              })
            }}
          </div>
          <div :class="['text-[10.5px]', certified ? 'text-muted' : 'text-warn']">
            {{
              certified
                ? say("verifier-serving-until", { at: stamp(serving.certificate.not_after) })
                : say("verifier-serving-ran-out", { at: stamp(serving.certificate.not_after) })
            }}
          </div>
          <div v-if="held.identity !== 'x509-hash'" class="font-mono text-[10px] break-all text-faint">
            {{ serving.certificate.client_id }}
          </div>
        </div>
        <button
          v-if="withdrawable"
          type="button"
          class="shrink-0 rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface"
          @click="withdraw(serving.kid)"
        >
          {{ say("verifier-withdraw") }}
        </button>
      </div>

      <div v-if="awaiting" class="grid gap-2 rounded-md border border-border bg-surface-2 px-3 py-2">
        <div class="flex items-start gap-3">
          <div class="min-w-0 flex-1">
            <div class="text-[10.5px] font-semibold text-muted">{{ say("verifier-awaiting") }}</div>
            <div class="text-[11px] break-all text-ink">
              {{
                [awaiting.subject.common_name, awaiting.subject.organization, awaiting.subject.country]
                  .filter(Boolean)
                  .join(", ")
              }}
            </div>
            <div class="text-[10.5px] leading-5 text-muted">
              {{ say("verifier-awaiting-drawn", { by: awaiting.created_by, at: stamp(awaiting.created_at) }) }}
            </div>
          </div>
          <button
            type="button"
            class="shrink-0 rounded-md border border-border px-3 py-1.5 text-xs text-danger hover:bg-surface"
            @click="withdraw(awaiting.kid)"
          >
            {{ say("verifier-withdraw") }}
          </button>
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-request") }}
          <textarea
            :value="awaiting.request"
            readonly
            rows="4"
            class="sf-field mt-1 font-mono text-[10.5px]"
            spellcheck="false"
          ></textarea>
        </label>
        <button
          type="button"
          class="w-fit rounded-md border border-border px-3 py-1.5 text-xs hover:bg-surface"
          @click="copyRequest"
        >
          {{ say("verifier-copy-request") }}
        </button>
        <form class="grid gap-2" @submit.prevent="take">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("verifier-chain") }} <AppHint name="verifier-chain-help" />
            <textarea
              v-model="chain"
              rows="4"
              class="sf-field mt-1 font-mono"
              spellcheck="false"
              placeholder="-----BEGIN CERTIFICATE-----"
            ></textarea>
          </label>
          <button type="submit" :disabled="!chain.trim()" class="w-fit sf-button sf-button-primary">
            {{ say("verifier-take") }}
          </button>
        </form>
      </div>

      <form v-else class="grid gap-2 sm:grid-cols-2" @submit.prevent="draw">
        <div class="flex items-center gap-1 text-[10.5px] font-semibold text-muted sm:col-span-2">
          {{ say("verifier-draw-title") }} <AppHint name="verifier-draw-help" />
        </div>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-common-name") }}
          <input v-model="subject.common_name" class="sf-field mt-1" maxlength="64" placeholder="Acme verifier" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-organization") }}
          <input v-model="subject.organization" class="sf-field mt-1" maxlength="64" placeholder="Acme SA" />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-organization-identifier") }}
          <AppHint name="verifier-organization-identifier-help" />
          <input
            v-model="subject.organization_identifier"
            class="sf-field mt-1 font-mono"
            maxlength="64"
            spellcheck="false"
            placeholder="VATFR-12345678901"
          />
        </label>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-country") }}
          <input
            v-model="subject.country"
            class="sf-field mt-1 block w-20 font-mono uppercase"
            maxlength="2"
            spellcheck="false"
            placeholder="FR"
          />
        </label>
        <button
          type="submit"
          :disabled="!subject.common_name.trim()"
          class="w-fit sf-button sf-button-primary sm:col-span-2"
        >
          {{ say("verifier-draw") }}
        </button>
      </form>

      <form class="grid gap-2 border-t border-border pt-3" @submit.prevent="keep">
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-identity-choice") }} <AppHint name="verifier-identity-choice-help" />
          <select v-model="draft.identity" class="sf-field mt-1 w-fit">
            <option value="did-web">{{ say("verifier-identity-did-web") }}</option>
            <option value="x509-hash">{{ say("verifier-identity-x509-hash") }}</option>
          </select>
        </label>
        <p v-if="draft.identity === 'x509-hash' && !certified" class="text-[11px] leading-5 text-warn">
          {{ say("verifier-identity-no-certificate") }}
        </p>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-dataset") }} <AppHint name="verifier-dataset-help" />
          <textarea
            v-model="draft.dataset"
            rows="6"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
            placeholder='{ "identifier": [{ "type": "http://data.europa.eu/eudi/id/VATIN", "identifier": "FR12345678901" }] }'
          ></textarea>
        </label>
        <p v-if="!write" class="text-[11px] text-danger">{{ say("verifier-dataset-unreadable") }}</p>
        <label class="block text-[11px] font-medium text-muted">
          {{ say("verifier-registration") }} <AppHint name="verifier-registration-help" />
          <textarea
            v-model="draft.registration"
            rows="3"
            class="sf-field mt-1 font-mono"
            spellcheck="false"
            placeholder="eyJ0eXAiOiJyYy13cnArand0Ii..."
          ></textarea>
        </label>
        <button type="submit" :disabled="!write" class="w-fit sf-button sf-button-primary">
          {{ say("verifier-keep") }}
        </button>
      </form>
    </template>
  </div>
</template>
