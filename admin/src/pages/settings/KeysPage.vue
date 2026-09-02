<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import { getRealmKeys, rotateKey } from "@/services/settings";
import type { RealmKeys } from "@/models/keys";

/// Every algorithm the build's signer mints: crypto's SignAlg::ALL, in the
/// order worth recommending. The 384 and 512 variants exist for peers that
/// demand them; they add bits, not strength that matters.
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

/// Key identities stay covered until asked for: a kid is not a secret, but
/// it is a correlator, and a screen share should not hand it out by default.
const shown = ref(new Set<string>());
function toggleShown(kid: string) {
  const held = new Set(shown.value);
  if (!held.delete(kid)) held.add(kid);
  shown.value = held;
}
function veiled(kid: string): string {
  return "\u2022".repeat(Math.min(kid.length, 24));
}

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const keys = ref<RealmKeys | null>(null);
const failed = ref("");
const algorithm = ref<string>("ES256");
const rotating = ref(false);

async function load() {
  try {
    keys.value = await getRealmKeys(realm.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

async function rotate() {
  rotating.value = true;
  try {
    await rotateKey(realm.value, algorithm.value);
    await load();
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  } finally {
    rotating.value = false;
  }
}
</script>

<template>
  <div>
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("keys-title") }}</h1>
      <form class="flex items-center gap-2" @submit.prevent="rotate">
        <select
          v-model="algorithm"
          class="rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
        >
          <option v-for="held in ALGORITHMS" :key="held" :value="held">{{ held }}</option>
        </select>
        <button
          type="submit"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong disabled:opacity-50"
          :disabled="rotating"
        >
          {{ say("keys-rotate") }}
        </button>
        <AppHint name="keys-rotate-help" />
      </form>
    </div>
    <p class="mt-1 text-xs text-muted">{{ say("keys-lede") }}</p>

    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <template v-if="keys">
      <h2 class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("keys-signing") }} <AppHint name="keys-signing-help" />
      </h2>
      <p v-if="!keys.signing.length" class="mt-2 text-xs text-muted">
        {{ say("keys-none") }}
      </p>
      <div class="mt-2 grid max-w-3xl gap-2">
        <div
          v-for="key in keys.signing"
          :key="key.kid"
          class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
        >
          <AppIcon name="key" :size="14" class="shrink-0 text-accent" />
          <span class="min-w-0 truncate font-mono text-[11.5px]">{{
            shown.has(key.kid) ? key.kid : veiled(key.kid)
          }}</span>
          <button
            type="button"
            class="grid size-6 shrink-0 place-items-center rounded text-faint hover:bg-surface-2 hover:text-muted"
            :aria-label="say(shown.has(key.kid) ? 'keys-hide' : 'keys-reveal')"
            @click="toggleShown(key.kid)"
          >
            <AppIcon :name="shown.has(key.kid) ? 'eye-off' : 'eye'" :size="13" />
          </button>
          <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px]">{{
            key.algorithm
          }}</span>
          <span
            class="ml-auto rounded border px-1.5 py-0.5 text-[10.5px]"
            :class="
              key.status === 'active'
                ? 'border-ok/40 text-ok'
                : 'border-border text-muted'
            "
            >{{ key.status }}</span
          >
        </div>
      </div>

      <template v-if="keys.encryption.length">
        <h2 class="mt-6 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("keys-encryption") }} <AppHint name="keys-encryption-help" />
        </h2>
        <div class="mt-2 grid max-w-3xl gap-2">
          <div
            v-for="key in keys.encryption"
            :key="key.kid"
            class="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
          >
            <AppIcon name="key" :size="14" class="shrink-0 text-faint" />
            <span class="min-w-0 truncate font-mono text-[11.5px]">{{
              shown.has(key.kid) ? key.kid : veiled(key.kid)
            }}</span>
            <button
              type="button"
              class="grid size-6 shrink-0 place-items-center rounded text-faint hover:bg-surface-2 hover:text-muted"
              :aria-label="say(shown.has(key.kid) ? 'keys-hide' : 'keys-reveal')"
              @click="toggleShown(key.kid)"
            >
              <AppIcon :name="shown.has(key.kid) ? 'eye-off' : 'eye'" :size="13" />
            </button>
            <span class="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px]">{{
              key.algorithm
            }}</span>
            <span class="ml-auto text-[10.5px] text-muted">{{ key.status }}</span>
          </div>
        </div>
      </template>
    </template>
  </div>
</template>
