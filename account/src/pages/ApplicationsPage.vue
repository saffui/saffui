<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import AppHint from "@/components/AppHint.vue";
import AppIcon from "@/components/AppIcon.vue";
import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { readTongue, say } from "@/i18n";
import { listApplications, type HeldApplication } from "@/services/applications";
import { session } from "@/services/session";
import { formatDay } from "./security";
import { formatMoment } from "./sessions";
import {
  carryOutGesture,
  composeConfirmation,
  describeScope,
  type Gesture,
  type Outcome,
} from "./applications";

const realm = session.realm;
const tongue = readTongue();
const applications = ref<HeldApplication[] | null>(null);
const unreadable = ref(false);
const pending = ref<Gesture | null>(null);
const busy = ref(false);
const outcome = ref<Outcome | null>(null);
const confirmation = computed(() => (pending.value ? composeConfirmation(pending.value) : null));

async function loadApplications() {
  try {
    applications.value = await listApplications(realm);
    unreadable.value = false;
  } catch {
    unreadable.value = true;
  }
}

async function confirmGesture() {
  const gesture = pending.value;
  if (!gesture) return;
  busy.value = true;
  outcome.value = await carryOutGesture(realm, gesture);
  busy.value = false;
  pending.value = null;
  await loadApplications();
}

onMounted(loadApplications);
</script>

<template>
  <header class="page-head">
    <h1>{{ say("applications-title") }}</h1>
    <p class="lead">{{ say("applications-lead") }}</p>
  </header>

  <p
    v-if="outcome"
    class="notice"
    :class="outcome.tone === 'ok' ? 'notice-ok' : 'notice-danger'"
    role="status"
  >
    {{ outcome.text }}
  </p>

  <p v-if="unreadable" class="notice notice-danger" role="alert">
    {{ say("applications-unreadable") }}
  </p>

  <template v-else-if="applications">
    <p v-if="applications.length === 0" class="absent">{{ say("applications-none") }}</p>

    <section
      v-for="application in applications"
      :key="application.client_id"
      class="card application"
      :aria-label="application.name"
    >
      <div class="application-head">
        <span class="login-glyph" aria-hidden="true"><AppIcon name="application" :size="20" /></span>
        <h2 class="login-device">{{ application.name }}</h2>
        <a
          v-if="application.home"
          class="button button-quiet"
          :href="application.home"
          target="_blank"
          rel="noopener noreferrer"
          :title="say('applications-visit-help', { application: application.name })"
        >
          <AppIcon name="visit" :size="15" />
          <span>{{ say("applications-visit") }}</span>
        </a>
      </div>

      <div v-if="application.consent" class="application-part">
        <h3 class="card-title">{{ say("applications-consent") }}</h3>
        <ul class="scopes">
          <li v-for="scope in application.consent.scopes" :key="scope" class="badge badge-unverified">
            {{ describeScope(scope) }}
          </li>
        </ul>
        <p class="factor-facts">
          {{ say("applications-agreed", { when: formatDay(application.consent.granted_at, tongue) }) }}
        </p>
        <div class="card-actions">
          <button
            type="button"
            class="button button-danger-quiet"
            @click="pending = { kind: 'withdraw-consent', application }"
          >
            {{ say("applications-withdraw-consent") }}
          </button>
          <AppHint v-if="application.consent.asks_consent" :text="say('applications-withdraw-consent-help')" />
          <AppHint v-else :text="say('applications-withdraw-consent-help-unasked')" />
        </div>
      </div>

      <div v-if="application.access" class="application-part">
        <h3 class="card-title">{{ say("applications-access") }}</h3>
        <p class="application-access">
          <span>{{ say("applications-access-logins", { count: application.access.logins }) }}</span>
          <template v-if="application.access.offline">
            <span class="badge badge-unverified">{{ say("sessions-offline") }}</span>
            <AppHint :text="say('sessions-offline-help', { application: application.name })" />
          </template>
        </p>
        <p v-if="application.access.expiration" class="factor-facts">
          {{ say("applications-access-until", { when: formatMoment(application.access.expiration, tongue) }) }}
        </p>
        <div class="card-actions">
          <button
            type="button"
            class="button button-danger-quiet"
            @click="pending = { kind: 'take-back-access', application }"
          >
            {{ say("applications-take-back-access") }}
          </button>
          <AppHint :text="say('applications-take-back-access-help')" />
        </div>
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
    @confirm="confirmGesture"
    @cancel="pending = null"
  />
</template>
