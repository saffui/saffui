<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppHint from "@/components/AppHint.vue";
import AppIcon from "@/components/AppIcon.vue";
import { say } from "@/i18n";
import type { RealmKeys, RealmKeyView } from "@/models/keys";
import { disableRealmKey, getRealmKeys, rotateKey } from "@/services/settings";
import { afterWrites } from "@/services/writes";
import { groupKeys, keyCreatedAt, publishedKeyCount } from "./keyPresentation";

const ALGORITHMS = [
  "ES256",
  "EdDSA",
  "PS256",
  "RS256",
  "ES384",
  "ES512",
  "PS384",
  "PS512",
  "RS384",
  "RS512",
] as const;

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const jwksPath = computed(
  () => `/realms/${encodeURIComponent(realm.value)}/protocol/openid-connect/certs`,
);
const keys = ref<RealmKeys | null>(null);
const failed = ref("");
const algorithm = ref<string>("ES256");
const rotating = ref(false);
const disabling = ref("");
const confirming = ref("");
const shown = ref(new Set<string>());
const signingGroups = computed(() => groupKeys(keys.value?.signing ?? []));
const encryptionGroups = computed(() => groupKeys(keys.value?.encryption ?? []));
const published = computed(() => publishedKeyCount(keys.value?.signing ?? []));
let loadSequence = 0;

function toggleShown(kid: string) {
  const held = new Set(shown.value);
  if (!held.delete(kid)) held.add(kid);
  shown.value = held;
}

function veiled(kid: string): string {
  return "\u2022".repeat(Math.min(kid.length, 24));
}

function created(key: RealmKeyView): string {
  const date = keyCreatedAt(key);
  return date
    ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date)
    : say("value-none");
}

function statusClass(status: string): string {
  if (status === "active") return "border-ok/40 bg-ok/5 text-ok";
  if (status === "disabled") return "border-border bg-surface-2 text-faint";
  return "border-warn/40 bg-warn/5 text-warn";
}

async function load() {
  const sequence = ++loadSequence;
  try {
    const held = await getRealmKeys(realm.value);
    if (sequence !== loadSequence) return;
    failed.value = "";
    keys.value = held;
  } catch (refused) {
    if (sequence !== loadSequence) return;
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

async function rotate() {
  rotating.value = true;
  failed.value = "";
  try {
    await rotateKey(realm.value, algorithm.value);
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    rotating.value = false;
  }
}

async function disable(key: RealmKeyView) {
  if (confirming.value !== key.kid) {
    confirming.value = key.kid;
    return;
  }
  disabling.value = key.kid;
  failed.value = "";
  try {
    await disableRealmKey(realm.value, key.kid);
    confirming.value = "";
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    disabling.value = "";
  }
}
</script>

<template>
  <div class="min-w-0">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold tracking-tight">{{ say("keys-title") }}</h1>
        <p class="mt-1 max-w-3xl text-[11.5px] leading-5 text-muted">{{ say("keys-lede") }}</p>
      </div>
      <span class="rounded border border-border bg-surface px-2 py-1 font-mono text-[10.5px] text-muted">
        {{ realm }}
      </span>
    </div>

    <p v-if="failed" class="mt-4 rounded border border-danger-line bg-danger/5 px-3 py-2 text-xs text-danger" role="alert">
      {{ failed }}
    </p>

    <div v-if="keys" class="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
      <main class="min-w-0 space-y-6">
        <section>
          <div class="flex items-center justify-between gap-3">
            <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("keys-signing") }} <AppHint name="keys-signing-help" />
            </h2>
            <span class="font-mono text-[10.5px] text-faint">{{ keys.signing.length }}</span>
          </div>
          <p v-if="!keys.signing.length" class="mt-2 rounded-lg border border-border bg-surface px-4 py-6 text-center text-xs text-muted">
            {{ say("keys-none") }}
          </p>

          <div v-for="grouped in signingGroups" :key="grouped.algorithm" class="mt-3 overflow-hidden rounded-lg border border-border bg-surface">
            <div class="flex items-center justify-between border-b border-border bg-surface-2 px-3 py-2">
              <div class="flex items-center gap-2">
                <AppIcon name="key" :size="13" class="text-accent" />
                <span class="font-mono text-xs font-semibold text-ink">{{ grouped.algorithm }}</span>
              </div>
              <span class="text-[10.5px] text-faint">{{ say("keys-count", { count: grouped.keys.length }) }}</span>
            </div>
            <div class="overflow-x-auto">
              <table class="sf-table min-w-[760px]">
                <thead>
                  <tr>
                    <th>{{ say("keys-kid") }}</th>
                    <th>{{ say("keys-use") }}</th>
                    <th>{{ say("keys-type") }}</th>
                    <th>{{ say("keys-status") }}</th>
                    <th>{{ say("keys-created") }}</th>
                    <th class="text-right">{{ say("keys-actions") }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="key in grouped.keys" :key="key.kid">
                    <td>
                      <div class="flex max-w-[300px] items-center gap-1.5">
                        <code class="min-w-0 truncate text-[10.5px] text-ink">{{ shown.has(key.kid) ? key.kid : veiled(key.kid) }}</code>
                        <button type="button" class="grid size-6 shrink-0 place-items-center rounded text-faint hover:bg-surface-2 hover:text-muted" :aria-label="say(shown.has(key.kid) ? 'keys-hide' : 'keys-reveal')" @click="toggleShown(key.kid)">
                          <AppIcon :name="shown.has(key.kid) ? 'eye-off' : 'eye'" :size="12" />
                        </button>
                      </div>
                    </td>
                    <td class="font-mono text-[10.5px]">{{ key.key_use ?? "sig" }}</td>
                    <td class="font-mono text-[10.5px]">{{ key.key_type ?? say("value-none") }}</td>
                    <td><span class="rounded border px-1.5 py-0.5 text-[10px]" :class="statusClass(key.status)">{{ key.status }}</span></td>
                    <td class="whitespace-nowrap text-[10.5px] text-muted">{{ created(key) }}</td>
                    <td class="text-right">
                      <button v-if="key.status === 'passive'" type="button" class="rounded border px-2 py-1 text-[10.5px]" :class="confirming === key.kid ? 'border-danger-line text-danger' : 'border-border text-muted hover:bg-surface-2'" :disabled="disabling === key.kid" @click="disable(key)">
                        {{ say(confirming === key.kid ? "keys-disable-confirm" : "keys-disable") }}
                      </button>
                      <span v-else class="text-[10.5px] text-faint">{{ say("value-none") }}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section v-if="keys.encryption.length">
          <div class="flex items-center justify-between gap-3">
            <h2 class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("keys-encryption") }} <AppHint name="keys-encryption-help" />
            </h2>
            <span class="font-mono text-[10.5px] text-faint">{{ keys.encryption.length }}</span>
          </div>
          <div v-for="grouped in encryptionGroups" :key="grouped.algorithm" class="mt-3 overflow-hidden rounded-lg border border-border bg-surface">
            <div class="flex items-center gap-2 border-b border-border bg-surface-2 px-3 py-2">
              <AppIcon name="key" :size="13" class="text-faint" />
              <span class="font-mono text-xs font-semibold">{{ grouped.algorithm }}</span>
            </div>
            <div class="overflow-x-auto">
              <table class="sf-table min-w-[620px]">
                <thead><tr><th>{{ say("keys-kid") }}</th><th>{{ say("keys-use") }}</th><th>{{ say("keys-status") }}</th><th>{{ say("keys-actions") }}</th></tr></thead>
                <tbody>
                  <tr v-for="key in grouped.keys" :key="key.kid">
                    <td>
                      <div class="flex max-w-[340px] items-center gap-1.5">
                        <code class="min-w-0 truncate text-[10.5px]">{{ shown.has(key.kid) ? key.kid : veiled(key.kid) }}</code>
                        <button type="button" class="grid size-6 shrink-0 place-items-center rounded text-faint hover:bg-surface-2 hover:text-muted" :aria-label="say(shown.has(key.kid) ? 'keys-hide' : 'keys-reveal')" @click="toggleShown(key.kid)">
                          <AppIcon :name="shown.has(key.kid) ? 'eye-off' : 'eye'" :size="12" />
                        </button>
                      </div>
                    </td>
                    <td class="font-mono text-[10.5px]">enc</td>
                    <td><span class="rounded border px-1.5 py-0.5 text-[10px]" :class="statusClass(key.status)">{{ key.status }}</span></td>
                    <td>{{ say("value-none") }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </main>

      <aside class="space-y-4 xl:sticky xl:top-4 xl:self-start">
        <section class="rounded-lg border border-border bg-surface p-4">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">{{ say("keys-jwks") }}</div>
          <div class="mt-3 rounded border border-border bg-surface-2 p-2.5">
            <code class="block break-all text-[10.5px] leading-4 text-muted">{{ jwksPath }}</code>
          </div>
          <dl class="mt-3 grid grid-cols-[1fr_auto] gap-2 text-[10.5px]">
            <dt class="text-faint">{{ say("keys-published") }}</dt>
            <dd class="font-mono text-ink">{{ published }}</dd>
            <dt class="text-faint">{{ say("keys-private-material") }}</dt>
            <dd class="text-ok">{{ say("keys-server-only") }}</dd>
          </dl>
        </section>

        <form class="rounded-lg border border-border bg-surface p-4" @submit.prevent="rotate">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("keys-rotation") }} <AppHint name="keys-rotate-help" />
          </div>
          <p class="mt-2 text-[10.5px] leading-4 text-muted">{{ say("keys-rotation-lede") }}</p>
          <label class="mt-3 block text-[11px] font-medium text-muted">
            {{ say("keys-algorithm") }}
            <select v-model="algorithm" class="sf-field mt-1 font-mono">
              <option v-for="held in ALGORITHMS" :key="held" :value="held">{{ held }}</option>
            </select>
          </label>
          <button type="submit" class="sf-button sf-button-primary mt-3 w-full justify-center disabled:opacity-50" :disabled="rotating">
            {{ say(rotating ? "keys-rotating" : "keys-rotate") }}
          </button>
          <p class="mt-3 border-t border-border pt-3 text-[10px] leading-4 text-faint">{{ say("keys-capability-note") }}</p>
        </form>
      </aside>
    </div>
  </div>
</template>
