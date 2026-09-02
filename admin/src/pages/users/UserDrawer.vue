<script setup lang="ts">
import { onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  closeSession,
  getLockout,
  getUser,
  liftLockout,
  listConsents,
  listEffectiveRoles,
  listMemberGroups,
  listMemberOrganizations,
  listSessions,
  listWebAuthnKeys,
  revokeWebAuthnKey,
} from "@/services/users";
import type {
  ConsentBrief,
  GroupBrief,
  KeyBrief,
  Lockout,
  OrgBrief,
  RoleBrief,
  SessionBrief,
  UserBrief,
} from "@/models/user";

const props = defineProps<{ realm: string; userId: string }>();
const emit = defineEmits<{ close: [] }>();

const TABS = ["overview", "credentials", "sessions", "memberships", "consents"] as const;
const tab = ref<(typeof TABS)[number]>("overview");

const user = ref<UserBrief | null>(null);
const lockout = ref<Lockout | null>(null);
const keys = ref<KeyBrief[]>([]);
const sessions = ref<SessionBrief[]>([]);
const consents = ref<ConsentBrief[]>([]);
const roles = ref<RoleBrief[]>([]);
const groups = ref<GroupBrief[]>([]);
const organizations = ref<OrgBrief[]>([]);
const failed = ref("");

async function load() {
  failed.value = "";
  try {
    [
      user.value,
      lockout.value,
      keys.value,
      sessions.value,
      consents.value,
      roles.value,
      groups.value,
      organizations.value,
    ] = await Promise.all([
      getUser(props.realm, props.userId),
      getLockout(props.realm, props.userId),
      listWebAuthnKeys(props.realm, props.userId),
      listSessions(props.realm, props.userId),
      listConsents(props.realm, props.userId),
      listEffectiveRoles(props.realm, props.userId),
      listMemberGroups(props.realm, props.userId),
      listMemberOrganizations(props.realm, props.userId),
    ]);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

async function onLift() {
  await liftLockout(props.realm, props.userId);
  lockout.value = await getLockout(props.realm, props.userId);
}
async function onRevokeKey(credentialId: string) {
  await revokeWebAuthnKey(props.realm, props.userId, credentialId);
  keys.value = await listWebAuthnKeys(props.realm, props.userId);
}
async function onCloseSession(sessionId: string) {
  await closeSession(props.realm, props.userId, sessionId);
  sessions.value = await listSessions(props.realm, props.userId);
}

function instant(epoch: number | null | undefined): string {
  if (!epoch) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(epoch * 1000));
}
</script>

<template>
  <AppDrawer
    :title="user?.user_name ?? '…'"
    :subtitle="props.userId"
    @close="emit('close')"
  >
    <p v-if="failed" class="text-xs text-danger" role="alert">{{ failed }}</p>

    <div class="flex gap-1 border-b border-border pb-2">
      <button
        v-for="held in TABS"
        :key="held"
        type="button"
        class="rounded-md px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-ink"
        :class="tab === held && 'bg-surface-2 font-medium text-ink'"
        @click="tab = held"
      >
        {{ say(`user-tab-${held}`) }}
      </button>
    </div>

    <div v-if="tab === 'overview' && user" class="mt-4 flex flex-col gap-4">
      <div
        v-if="lockout?.locked"
        class="flex items-center gap-3 rounded-lg border border-danger/40 px-3 py-2.5"
      >
        <span class="text-xs">{{ say("user-locked", { until: instant(lockout.until) }) }}</span>
        <button
          type="button"
          class="ml-auto rounded-md border border-border px-2 py-1 text-[11px] hover:bg-surface-2"
          @click="onLift"
        >
          {{ say("user-lift-lock") }}
        </button>
      </div>

      <dl class="grid grid-cols-[140px_1fr] gap-y-2 text-xs">
        <dt class="text-muted">{{ say("users-col-email") }}</dt>
        <dd class="flex items-center gap-1.5">
          {{ user.email }}
          <AppIcon v-if="user.email_verified" name="verified" :size="12" class="text-ok" />
        </dd>
        <dt class="text-muted">{{ say("users-col-name") }}</dt>
        <dd>{{ [user.given_name, user.family_name].filter(Boolean).join(" ") || "·" }}</dd>
        <dt class="text-muted">{{ say("user-phone") }}</dt>
        <dd>{{ user.phone_number || "·" }}</dd>
        <dt class="text-muted">{{ say("users-col-state") }}</dt>
        <dd>{{ user.enabled ? say("users-active") : say("users-disabled") }}</dd>
      </dl>

      <div v-if="user.required_actions.length">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-required-actions") }}
        </div>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="action in user.required_actions"
            :key="action"
            class="rounded border border-warn/40 px-1.5 py-0.5 font-mono text-[10.5px] text-warn"
            >{{ action }}</span
          >
        </div>
      </div>
    </div>

    <div v-if="tab === 'credentials'" class="mt-4">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("user-webauthn") }}
      </div>
      <p v-if="!keys.length" class="mt-2 text-xs text-muted">{{ say("user-no-keys") }}</p>
      <div
        v-for="key in keys"
        :key="key.credential_id"
        class="mt-2 flex items-center gap-3 rounded-lg border border-border px-3 py-2.5 text-xs"
      >
        <div class="min-w-0">
          <div class="font-medium">{{ key.label || say("user-key-unnamed") }}</div>
          <div class="mt-0.5 font-mono text-[10.5px] text-faint">
            {{ say("user-key-enrolled") }} {{ instant(key.enrolled_at) }}
            <template v-if="key.last_used_at">
              &middot; {{ say("user-key-last-used") }} {{ instant(key.last_used_at) }}
            </template>
          </div>
        </div>
        <button
          type="button"
          class="ml-auto rounded-md border border-border px-2 py-1 text-[11px] text-danger hover:bg-surface-2"
          @click="onRevokeKey(key.credential_id)"
        >
          {{ say("user-revoke") }}
        </button>
      </div>
    </div>

    <div v-if="tab === 'sessions'" class="mt-4">
      <p v-if="!sessions.length" class="text-xs text-muted">{{ say("user-no-sessions") }}</p>
      <div
        v-for="session in sessions"
        :key="session.session_id"
        class="mt-2 rounded-lg border border-border px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="font-medium">
            {{ [session.browser, session.system].filter(Boolean).join(" · ") || say("user-session-unknown") }}
          </span>
          <span v-if="session.ip_address" class="font-mono text-[10.5px] text-faint">{{
            session.ip_address
          }}</span>
          <button
            type="button"
            class="ml-auto rounded-md border border-border px-2 py-1 text-[11px] text-danger hover:bg-surface-2"
            @click="onCloseSession(session.session_id)"
          >
            {{ say("user-session-close") }}
          </button>
        </div>
        <div class="mt-1 font-mono text-[10.5px] text-faint">
          {{ say("user-session-started") }} {{ instant(session.started_at) }}
        </div>
        <div v-if="session.grants.length" class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="grant in session.grants"
            :key="grant.client_id"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px] text-muted"
          >
            {{ grant.client_id }}<template v-if="grant.offline"> &middot; offline</template>
          </span>
        </div>
      </div>
    </div>

    <div v-if="tab === 'memberships'" class="mt-4 flex flex-col gap-5">
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-roles") }}
        </div>
        <p v-if="!roles.length" class="mt-1.5 text-xs text-muted">{{ say("user-no-roles") }}</p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="role in roles"
            :key="role.role_id"
            class="inline-flex items-center gap-1.5 rounded border border-border px-1.5 py-0.5 text-[11px]"
            :title="role.description"
          >
            {{ role.display_name || role.name }}
            <span v-if="role.client_id" class="font-mono text-[10px] text-faint">{{
              role.client_id
            }}</span>
          </span>
        </div>
      </div>
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-groups") }}
        </div>
        <p v-if="!groups.length" class="mt-1.5 text-xs text-muted">{{ say("user-no-groups") }}</p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="group in groups"
            :key="group.group_id"
            class="rounded border border-border px-1.5 py-0.5 text-[11px]"
            :title="group.description"
            >{{ group.display_name || group.name }}</span
          >
        </div>
      </div>
      <div>
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-organizations") }}
        </div>
        <p v-if="!organizations.length" class="mt-1.5 text-xs text-muted">
          {{ say("user-no-organizations") }}
        </p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="org in organizations"
            :key="org.org_id"
            class="inline-flex items-center gap-1.5 rounded border border-border px-1.5 py-0.5 text-[11px]"
          >
            {{ org.display_name || org.name }}
            <span v-if="!org.enabled" class="text-[10px] text-danger">{{
              say("users-disabled")
            }}</span>
          </span>
        </div>
      </div>
    </div>

    <div v-if="tab === 'consents'" class="mt-4">
      <p v-if="!consents.length" class="text-xs text-muted">{{ say("user-no-consents") }}</p>
      <div
        v-for="consent in consents"
        :key="consent.client_id"
        class="mt-2 rounded-lg border border-border px-3 py-2.5 text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="font-mono text-[11.5px]">{{ consent.client_id }}</span>
          <span class="ml-auto font-mono text-[10.5px] text-faint">{{
            instant(consent.granted_at)
          }}</span>
        </div>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span
            v-for="scope in consent.scopes"
            :key="scope"
            class="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px] text-muted"
            >{{ scope }}</span
          >
        </div>
      </div>
    </div>
  </AppDrawer>
</template>
