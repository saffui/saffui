<script setup lang="ts">
// What a token would carry, header and body, assembled by the same code that
// issues. Signs nothing: the assembly is issuance's own, the signature is not.
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { say } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import UserSubjectField from "@/components/UserSubjectField.vue";
import { previewToken, type Foreseen, type ShownToken } from "@/services/clients";
import type { ClientBrief } from "@/models/client";
import { authorizationClients, selectedClient } from "@/pages/authorization/authorizationClients";
import { asMoment, headerLines, linesOf, windowOf } from "./tokenPreview";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const clients = ref<ClientBrief[]>([]);
const failed = ref("");
const userId = ref("");
const clientId = ref("");
const scope = ref("openid profile");
const foreseen = ref<Foreseen | null>(null);

onMounted(async () => {
  try {
    clients.value = await authorizationClients(realm.value);
    clientId.value = selectedClient(clients.value, String(route.query.client ?? ""));
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
});

async function ask() {
  failed.value = "";
  foreseen.value = null;
  if (!userId.value.trim() || !clientId.value) return;
  try {
    foreseen.value = await previewToken(realm.value, {
      user_id: userId.value.trim(),
      client_id: clientId.value,
      scope: scope.value.trim() || undefined,
    });
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

const shown = computed(() => {
  const held = foreseen.value;
  if (!held) return [];
  const tokens: { name: string; token: ShownToken }[] = [
    { name: say("preview-token-access"), token: held.access },
  ];
  if (held.identity) tokens.push({ name: say("preview-token-identity"), token: held.identity });
  return tokens;
});

function body(token: ShownToken) {
  return foreseen.value ? linesOf(token, foreseen.value) : [];
}

/// The moment a bounding claim names, beside the seconds it carries: a reader
/// checking a window should not have to convert an epoch in their head.
function moment(token: ShownToken, key: string): string {
  return asMoment(key, token.body[key]);
}
</script>

<template>
  <div>
    <h1 class="text-lg font-semibold tracking-tight">{{ say("preview-title") }}</h1>
    <p class="mt-1 max-w-2xl text-xs text-muted">
      {{ say("preview-lede") }} <AppHint name="preview-lede-help" />
    </p>
    <p v-if="failed" class="mt-3 text-xs text-danger" role="alert">{{ failed }}</p>

    <form class="mt-4 flex max-w-3xl items-end gap-2 text-xs" @submit.prevent="ask">
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("signin-col-who") }}
        <UserSubjectField
          v-model="userId"
          :realm="realm"
          :placeholder="say('subject-username-or-id')"
          class="sf-field mt-1 font-mono"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("clients-title") }}
        <select v-model="clientId" class="sf-field mt-1 font-mono">
          <option value="" disabled>{{ say("authz-pick-client") }}</option>
          <option v-for="held in clients" :key="held.client_id" :value="held.client_id">
            {{ held.client_id }}
          </option>
        </select>
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("preview-scope") }} <AppHint name="preview-scope-help" />
        <input v-model="scope" class="sf-field mt-1 font-mono" spellcheck="false" />
      </label>
      <button type="submit" class="sf-button sf-button-primary">{{ say("preview-ask") }}</button>
    </form>

    <div v-if="foreseen" class="mt-5 grid gap-4 xl:grid-cols-2">
      <section
        v-for="held in shown"
        :key="held.name"
        class="rounded-lg border border-border bg-surface"
      >
        <header class="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
          <h2 class="text-sm font-semibold">{{ held.name }}</h2>
          <span
            v-if="windowOf(held.token) !== null"
            class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted"
          >
            {{ say("preview-window", { seconds: windowOf(held.token) ?? 0 }) }}
            <AppHint name="preview-window-help" />
          </span>
        </header>

        <div class="border-l-2 border-info/60 px-4 py-3">
          <p class="text-[10px] font-medium tracking-wide text-muted uppercase">
            {{ say("preview-part-header") }}
          </p>
          <dl class="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
            <template v-for="line in headerLines(held.token)" :key="line.key">
              <dt class="text-muted">{{ line.key }}</dt>
              <dd class="break-all text-ink">{{ line.value }}</dd>
            </template>
          </dl>
        </div>

        <div class="border-t border-l-2 border-t-border border-l-accent/60 px-4 py-3">
          <p class="text-[10px] font-medium tracking-wide text-muted uppercase">
            {{ say("preview-part-body") }}
          </p>
          <dl class="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
            <template v-for="line in body(held.token)" :key="line.key">
              <dt class="text-muted">{{ line.key }}</dt>
              <dd class="break-all text-ink">
                {{ line.value }}
                <span v-if="moment(held.token, line.key)" class="ml-1 text-[10px] text-faint">
                  {{ moment(held.token, line.key) }}
                </span>
                <span
                  v-if="line.author"
                  class="ml-1 rounded border border-info/40 px-1 py-px text-[9.5px] text-info"
                >
                  {{ say("preview-by") }} {{ line.author }}
                  <AppHint name="preview-origin-help" />
                </span>
                <span v-if="line.drawn" class="ml-1 text-[9.5px] text-faint">
                  {{ say("preview-drawn") }} <AppHint name="preview-drawn-help" />
                </span>
              </dd>
            </template>
          </dl>
        </div>

        <div class="border-t border-l-2 border-t-border border-l-border px-4 py-3">
          <p class="text-[10px] font-medium tracking-wide text-muted uppercase">
            {{ say("preview-part-signature") }}
          </p>
          <p class="mt-1.5 text-[11px] text-muted">
            {{ say("preview-unsigned") }} <AppHint name="preview-unsigned-help" />
          </p>
        </div>
      </section>

      <p v-if="!foreseen.identity" class="self-start text-xs text-muted xl:mt-3">
        {{ say("preview-no-identity") }}
      </p>
    </div>
  </div>
</template>
