<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import type { Challenge } from "saffui-js";
import AppHint from "@/components/AppHint.vue";
import AppIcon from "@/components/AppIcon.vue";
import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { readTongue, say } from "@/i18n";
import { checkRecentSignIn, listFactors, type OwnFactors } from "@/services/factors";
import { StepUpNeeded } from "@/services/http";
import { enrolFactor, isStepUpRecent, session, stepUp, type Ceremony } from "@/services/session";
import {
  carryOutRemoval,
  checkPasswordForm,
  composeRemovalConfirmation,
  describeKeptBecause,
  formatDay,
  nameApp,
  submitPasswordChange,
  type Outcome,
  type PasswordForm,
  type Removal,
} from "./security";

const realm = session.realm;
const tongue = readTongue();
const route = useRoute();
const router = useRouter();
const factors = ref<OwnFactors | null>(null);
const unreadable = ref(false);
const challenge = ref<Challenge | null>(null);
const outcome = ref<Outcome | null>(null);
const pending = ref<Removal | null>(null);
const busy = ref(false);
const form = ref<PasswordForm>({ current: "", replacement: "", again: "" });
const formProblem = ref("");
const confirmation = computed(() =>
  pending.value ? composeRemovalConfirmation(pending.value) : null,
);
const notEnough = computed(() => challenge.value !== null && isStepUpRecent());

async function loadFactors() {
  try {
    factors.value = await listFactors(realm);
    unreadable.value = false;
  } catch {
    unreadable.value = true;
  }
  try {
    await checkRecentSignIn(realm);
    challenge.value = null;
  } catch (refused) {
    challenge.value = refused instanceof StepUpNeeded ? refused.challenge : null;
  }
}

// A step-up or a ceremony refused on the sign-in pages lands back here told so, and
// the address is cleaned of it once said.
function readRefusal() {
  const refused = route.query.refused;
  if (refused === "enrol") {
    outcome.value = { tone: "danger", text: say("security-enrol-refused", { realm }), stepUp: null };
  } else if (refused === "step-up") {
    outcome.value = { tone: "danger", text: say("security-step-up-refused"), stepUp: null };
  }
  if (refused) void router.replace({ query: {} });
}

async function signInAgain() {
  if (challenge.value) await stepUp(challenge.value, route.path);
}

async function addFactor(ceremony: Ceremony) {
  await enrolFactor(ceremony, route.path);
}

async function sendPasswordChange() {
  outcome.value = null;
  const ready = checkPasswordForm(form.value);
  if (ready === "missing") {
    formProblem.value = say("security-password-missing");
    return;
  }
  if (ready === "mismatch") {
    formProblem.value = say("security-password-repeat-differs");
    return;
  }
  formProblem.value = "";
  busy.value = true;
  const told = await submitPasswordChange(realm, form.value);
  busy.value = false;
  const changed = told.tone === "ok";
  form.value = {
    current: "",
    replacement: changed ? "" : form.value.replacement,
    again: changed ? "" : form.value.again,
  };
  outcome.value = told;
  if (told.stepUp) challenge.value = told.stepUp;
}

async function confirmRemoval() {
  const removal = pending.value;
  if (!removal) return;
  busy.value = true;
  const told = await carryOutRemoval(realm, removal);
  busy.value = false;
  pending.value = null;
  outcome.value = told;
  await loadFactors();
  if (told.stepUp) challenge.value = told.stepUp;
}

onMounted(async () => {
  readRefusal();
  await loadFactors();
});
</script>

<template>
  <header class="page-head">
    <h1>{{ say("security-title") }}</h1>
    <p class="lead">{{ say("security-lead", { realm }) }}</p>
  </header>

  <section v-if="challenge" class="notice notice-step-up" aria-labelledby="security-step-up">
    <p id="security-step-up">
      <template v-if="notEnough">{{ say("security-step-up-not-enough") }}</template>
      <template v-else>{{ say("security-step-up-lead") }}</template>
    </p>
    <div class="notice-actions">
      <button type="button" class="button button-primary" @click="signInAgain">
        {{ say("security-step-up") }}
      </button>
      <AppHint :text="say('security-step-up-help')" />
    </div>
  </section>

  <p
    v-if="outcome"
    class="notice"
    :class="outcome.tone === 'ok' ? 'notice-ok' : 'notice-danger'"
    role="status"
  >
    {{ outcome.text }}
  </p>

  <p v-if="unreadable" class="notice notice-danger" role="alert">
    {{ say("security-unreadable") }}
  </p>

  <template v-else-if="factors">
    <section class="card" aria-labelledby="security-password">
      <h2 id="security-password" class="card-title">{{ say("security-password") }}</h2>
      <form v-if="factors.password" class="form" @submit.prevent="sendPasswordChange">
        <label class="field">
          <span class="field-label">{{ say("security-password-current") }}</span>
          <input
            v-model="form.current"
            type="password"
            autocomplete="current-password"
            :disabled="challenge !== null || busy"
          />
        </label>
        <label class="field">
          <span class="field-label">
            {{ say("security-password-new") }}
            <AppHint :text="say('security-password-new-help', { realm })" />
          </span>
          <input
            v-model="form.replacement"
            type="password"
            autocomplete="new-password"
            :disabled="challenge !== null || busy"
          />
        </label>
        <label class="field">
          <span class="field-label">{{ say("security-password-again") }}</span>
          <input
            v-model="form.again"
            type="password"
            autocomplete="new-password"
            :disabled="challenge !== null || busy"
          />
        </label>
        <p v-if="formProblem" class="field-problem" role="alert">{{ formProblem }}</p>
        <div class="form-actions">
          <button type="submit" class="button button-primary" :disabled="challenge !== null || busy">
            {{ say("security-password-change") }}
          </button>
          <AppHint :text="say('security-password-change-help')" />
        </div>
      </form>
      <p v-else class="absent">{{ say("security-password-none") }}</p>
    </section>

    <section class="card" aria-labelledby="security-apps">
      <h2 id="security-apps" class="card-title">{{ say("security-apps") }}</h2>
      <ul v-if="factors.apps.length" class="factors">
        <li v-for="app in factors.apps" :key="app.id" class="factor">
          <span class="factor-glyph" aria-hidden="true"><AppIcon name="app" :size="18" /></span>
          <div>
            <p class="factor-name">{{ nameApp(app) }}</p>
            <p v-if="app.created_at" class="factor-facts">
              {{ say("security-added", { when: formatDay(app.created_at, tongue) }) }}
            </p>
          </div>
          <div class="factor-actions">
            <AppHint v-if="app.kept_because" :text="describeKeptBecause(app.kept_because)" />
            <button
              type="button"
              class="button button-danger-quiet"
              :disabled="app.kept_because !== null || challenge !== null"
              @click="pending = { kind: 'app', app }"
            >
              {{ say("security-remove") }}
            </button>
          </div>
        </li>
      </ul>
      <p v-else class="absent">{{ say("security-apps-none") }}</p>
      <div class="card-actions">
        <button type="button" class="button" @click="addFactor('configure-totp')">
          <AppIcon name="add" :size="15" />
          <span>{{ say("security-apps-add") }}</span>
        </button>
        <AppHint :text="say('security-apps-add-help')" />
      </div>
    </section>

    <section class="card" aria-labelledby="security-keys">
      <h2 id="security-keys" class="card-title">{{ say("security-keys") }}</h2>
      <ul v-if="factors.keys.length" class="factors">
        <li v-for="key in factors.keys" :key="key.id" class="factor">
          <span class="factor-glyph" aria-hidden="true"><AppIcon name="key" :size="18" /></span>
          <div>
            <p class="factor-name">{{ key.label }}</p>
            <p class="factor-facts">
              <span v-if="key.enrolled_at">
                {{ say("security-added", { when: formatDay(key.enrolled_at, tongue) }) }}
              </span>
              <span v-if="key.last_used_at">
                {{ say("security-used", { when: formatDay(key.last_used_at, tongue) }) }}
              </span>
            </p>
          </div>
          <div class="factor-actions">
            <AppHint v-if="key.kept_because" :text="describeKeptBecause(key.kept_because)" />
            <button
              type="button"
              class="button button-danger-quiet"
              :disabled="key.kept_because !== null || challenge !== null"
              @click="pending = { kind: 'key', key }"
            >
              {{ say("security-remove") }}
            </button>
          </div>
        </li>
      </ul>
      <p v-else class="absent">{{ say("security-keys-none") }}</p>
      <div class="card-actions">
        <button type="button" class="button" @click="addFactor('configure-webauthn')">
          <AppIcon name="add" :size="15" />
          <span>{{ say("security-keys-add") }}</span>
        </button>
        <AppHint :text="say('security-keys-add-help')" />
      </div>
    </section>

    <section class="card" aria-labelledby="security-codes">
      <h2 id="security-codes" class="card-title">{{ say("security-codes") }}</h2>
      <p>{{ say("security-codes-left", { count: factors.recovery_codes }) }}</p>
      <div class="card-actions">
        <button type="button" class="button" @click="addFactor('configure-recovery-codes')">
          {{ say("security-codes-new") }}
        </button>
        <AppHint :text="say('security-codes-new-help')" />
        <button
          v-if="factors.recovery_codes > 0"
          type="button"
          class="button button-danger-quiet"
          :disabled="challenge !== null"
          @click="pending = { kind: 'recovery-codes', count: factors.recovery_codes }"
        >
          {{ say("security-codes-remove") }}
        </button>
      </div>
    </section>
  </template>

  <p v-else class="loading" aria-busy="true">{{ say("loading") }}</p>

  <ConfirmDialog
    v-if="confirmation"
    :title="confirmation.title"
    :body="confirmation.body"
    :confirm="confirmation.confirm"
    :busy="busy"
    @confirm="confirmRemoval"
    @cancel="pending = null"
  />
</template>
