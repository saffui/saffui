<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import AppHint from "@/components/AppHint.vue";
import AppIcon from "@/components/AppIcon.vue";
import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { readTongue, say } from "@/i18n";
import { ApiError } from "@/services/http";
import { ACCOUNT_CONSOLE, forgetSignIn, session } from "@/services/session";
import {
  endLogin,
  endOtherLogins,
  listLogins,
  revokeGrant,
  type HeldGrant,
  type HeldLogin,
} from "@/services/sessions";
import { countOtherLogins, describeDevice, formatMoment, orderLogins } from "./sessions";

/// What the person is about to do, held while they confirm it.
type Gesture =
  | { kind: "end"; login: HeldLogin }
  | { kind: "end-others" }
  | { kind: "take-back"; login: HeldLogin; grant: HeldGrant };

const realm = session.realm;
const tongue = readTongue();
const router = useRouter();
const logins = ref<HeldLogin[] | null>(null);
const unreadable = ref(false);
const pending = ref<Gesture | null>(null);
const busy = ref(false);
const outcome = ref<{ tone: "ok" | "danger"; text: string } | null>(null);
const others = computed(() => (logins.value ? countOtherLogins(logins.value) : 0));

async function loadLogins() {
  try {
    logins.value = orderLogins(await listLogins(realm));
    unreadable.value = false;
  } catch {
    unreadable.value = true;
  }
}

// Each gesture says what it does before it happens: ending a login and taking back
// what one application got are two gestures with two consequences.
const asking = computed(() => {
  const gesture = pending.value;
  if (gesture?.kind === "end" && gesture.login.current) {
    return {
      title: say("confirm-end-current-title"),
      body: say("confirm-end-current-body"),
      confirm: say("confirm-end-current"),
    };
  }
  if (gesture?.kind === "end") {
    return {
      title: say("confirm-end-title"),
      body: say("confirm-end-body", { device: describeDevice(gesture.login) }),
      confirm: say("confirm-end"),
    };
  }
  if (gesture?.kind === "end-others") {
    return {
      title: say("confirm-end-others-title"),
      body: say("confirm-end-others-body"),
      confirm: say("confirm-end-others"),
    };
  }
  if (gesture?.kind === "take-back") {
    return {
      title: say("confirm-take-back-title", { application: gesture.grant.name }),
      body: say("confirm-take-back-body", { application: gesture.grant.name }),
      confirm: say("confirm-take-back"),
    };
  }
  return null;
});

async function carryOutGesture() {
  const gesture = pending.value;
  if (!gesture) return;
  busy.value = true;
  try {
    if (gesture.kind === "end") {
      await endLogin(realm, gesture.login.session_id);
      if (gesture.login.current) {
        forgetSignIn();
        await router.replace("/signed-out");
        return;
      }
      outcome.value = { tone: "ok", text: say("sessions-ended") };
    } else if (gesture.kind === "end-others") {
      const { ended_sessions } = await endOtherLogins(realm);
      outcome.value = { tone: "ok", text: say("sessions-ended-others", { count: ended_sessions }) };
    } else {
      await revokeGrant(realm, gesture.login.session_id, gesture.grant.client_id);
      outcome.value = {
        tone: "ok",
        text: say("sessions-taken-back", { application: gesture.grant.name }),
      };
    }
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) {
      outcome.value = { tone: "ok", text: say("sessions-gone") };
    } else {
      outcome.value = { tone: "danger", text: say("sessions-failed") };
    }
  } finally {
    busy.value = false;
    pending.value = null;
  }
  await loadLogins();
}

onMounted(loadLogins);
</script>

<template>
  <header class="page-head">
    <h1>{{ say("sessions-title") }}</h1>
    <p class="lead">{{ say("sessions-lead") }}</p>
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
    {{ say("sessions-unreadable") }}
  </p>

  <template v-else-if="logins">
    <div class="toolbar">
      <button
        type="button"
        class="button"
        :disabled="others === 0"
        @click="pending = { kind: 'end-others' }"
      >
        {{ say("sessions-end-others") }}
      </button>
      <AppHint v-if="others > 0" :text="say('sessions-end-others-help')" />
      <AppHint v-else :text="say('sessions-no-others')" />
    </div>

    <section
      v-for="login in logins"
      :key="login.session_id"
      class="card login"
      :aria-label="describeDevice(login)"
    >
      <div class="login-head">
        <span class="login-glyph" aria-hidden="true">
          <AppIcon :name="login.mobile ? 'mobile' : 'desktop'" :size="20" />
        </span>
        <div class="login-what">
          <h2 class="login-device">{{ describeDevice(login) }}</h2>
          <p class="login-facts">
            <span class="numeric">
              {{ say("sessions-started", { when: formatMoment(login.started_at, tongue) }) }}
            </span>
            <span v-if="login.ip_address" class="numeric">
              {{ say("sessions-from", { address: login.ip_address }) }}
            </span>
            <span v-if="login.auth_method === 'broker' && login.provider">
              {{ say("sessions-through", { provider: login.provider }) }}
            </span>
            <span v-if="login.expiration" class="numeric">
              {{ say("sessions-ends", { when: formatMoment(login.expiration, tongue) }) }}
            </span>
          </p>
        </div>
        <div class="login-marks">
          <template v-if="login.current">
            <span class="badge badge-verified">{{ say("sessions-this-browser") }}</span>
            <AppHint :text="say('sessions-this-browser-help')" />
          </template>
          <template v-if="!login.open">
            <span class="badge badge-unverified">{{ say("sessions-closed") }}</span>
            <AppHint :text="say('sessions-closed-help')" />
          </template>
        </div>
      </div>

      <div class="login-grants">
        <h3 class="card-title">{{ say("sessions-applications") }}</h3>
        <ul v-if="login.grants.length" class="grants">
          <li v-for="grant in login.grants" :key="grant.client_id" class="grant">
            <span class="grant-name">{{ grant.name }}</span>
            <template v-if="grant.offline">
              <span class="badge badge-unverified">{{ say("sessions-offline") }}</span>
              <AppHint :text="say('sessions-offline-help', { application: grant.name })" />
            </template>
            <button
              v-if="grant.client_id !== ACCOUNT_CONSOLE"
              type="button"
              class="button button-quiet grant-action"
              :title="say('sessions-take-back-help', { application: grant.name })"
              @click="pending = { kind: 'take-back', login, grant }"
            >
              {{ say("sessions-take-back") }}
            </button>
          </li>
        </ul>
        <p v-else class="absent">{{ say("sessions-no-applications") }}</p>
      </div>

      <div class="login-actions">
        <button
          type="button"
          class="button button-danger-quiet"
          @click="pending = { kind: 'end', login }"
        >
          <template v-if="login.current">{{ say("sessions-end-current") }}</template>
          <template v-else>{{ say("sessions-end") }}</template>
        </button>
      </div>
    </section>
  </template>

  <p v-else class="loading" aria-busy="true">{{ say("loading") }}</p>

  <ConfirmDialog
    v-if="asking"
    :title="asking.title"
    :body="asking.body"
    :confirm="asking.confirm"
    :busy="busy"
    @confirm="carryOutGesture"
    @cancel="pending = null"
  />
</template>
