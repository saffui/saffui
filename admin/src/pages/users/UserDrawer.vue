<script setup lang="ts">
import { onMounted, ref } from "vue";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import {
  closeSession,
  deleteUser,
  getLockout,
  getUser,
  grantRoleToUser,
  joinGroup,
  leaveGroup,
  liftLockout,
  listConsents,
  listEffectiveRoles,
  listMemberGroups,
  listMemberOrganizations,
  listSessions,
  listWebAuthnKeys,
  revokeRoleFromUser,
  revokeWebAuthnKey,
  setUserPassword,
  updateUser,
} from "@/services/users";
import { listRoles, listGroups } from "@/services/directory";
import AppToggle from "@/components/AppToggle.vue";
import AppHint from "@/components/AppHint.vue";
import AppPicker from "@/components/AppPicker.vue";
import { useRouter } from "vue-router";
import { Eye, EyeOff } from "lucide-vue-next";
import type {
  ConsentBrief,
  GroupBrief,
  KeyBrief,
  Lockout,
  OrgBrief,
  RoleBrief,
  SessionBrief,
  UserFull,
} from "@/models/user";

const props = defineProps<{ realm: string; userId: string }>();
const emit = defineEmits<{ close: [] }>();

const TABS = ["overview", "credentials", "sessions", "memberships", "consents"] as const;
const tab = ref<(typeof TABS)[number]>("overview");

const user = ref<UserFull | null>(null);
const lockout = ref<Lockout | null>(null);
const keys = ref<KeyBrief[]>([]);
const sessions = ref<SessionBrief[]>([]);
const consents = ref<ConsentBrief[]>([]);
const roles = ref<RoleBrief[]>([]);
const groups = ref<GroupBrief[]>([]);
const organizations = ref<OrgBrief[]>([]);
const failed = ref("");
const router = useRouter();

/// The custom attributes: the bag minus the profile keys shown as fields.
const PROFILE_KEYS = new Set(["given_name", "family_name"]);
function customAttributes(held: UserFull): [string, string][] {
  const bag = held.attributes ?? {};
  return Object.entries(bag)
    .filter(([key]) => !PROFILE_KEYS.has(key))
    .map(([key, value]) => [
      key,
      typeof value === "string" ? value : (value?.Str ?? JSON.stringify(value)),
    ]);
}
function born(held: UserFull): string {
  if (!held.created_at) return "";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(held.created_at),
  );
}
const showPassword = ref(false);

/// The editable half of the overview, adopted from the loaded user.
const profile = ref({
  email: "",
  given_name: "",
  family_name: "",
  phone_number: "",
  enabled: true,
});
const REQUIRED_ACTIONS = [
  "update-password",
  "verify-email",
  "configure-totp",
  "configure-webauthn",
] as const;
const askedActions = ref<string[]>([]);
const askOpen = ref(false);

const newPassword = ref("");
const newPasswordAgain = ref("");
const doomName = ref("");
const picker = ref<"" | "role" | "group">("");
const pickRows = ref<{ id: string; label: string; held: boolean }[]>([]);

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
    const held = user.value;
    if (held) {
      profile.value = {
        email: held.email ?? "",
        given_name: held.given_name ?? "",
        family_name: held.family_name ?? "",
        phone_number: held.phone_number ?? "",
        enabled: held.enabled,
      };
      askedActions.value = [...held.required_actions];
    }
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);

async function saveProfile() {
  try {
    await updateUser(props.realm, props.userId, {
      email: profile.value.email || undefined,
      given_name: profile.value.given_name || undefined,
      family_name: profile.value.family_name || undefined,
      phone_number: profile.value.phone_number || undefined,
      enabled: profile.value.enabled,
      required_actions: askedActions.value,
    });
    await load();
  } catch {
    // The toast already said.
  }
}

function dropAction(action: string) {
  askedActions.value = askedActions.value.filter((held) => held !== action);
}
function askFor(action: string) {
  if (!askedActions.value.includes(action)) askedActions.value.push(action);
  askOpen.value = false;
}

async function savePassword() {
  if (!newPassword.value || newPassword.value !== newPasswordAgain.value) {
    failed.value = say("user-password-mismatch");
    return;
  }
  try {
    await setUserPassword(props.realm, props.userId, newPassword.value);
    newPassword.value = "";
    newPasswordAgain.value = "";
    failed.value = "";
  } catch {
    // The toast already said.
  }
}

async function dropUser() {
  try {
    await deleteUser(props.realm, props.userId);
    emit("close");
    router.replace(`/${props.realm}/users`);
  } catch {
    // The toast already said.
  }
}

async function openPicker(kind: "role" | "group") {
  picker.value = kind;
  if (kind === "role") {
    const page = await listRoles(props.realm, 0, 200);
    const held = new Set(roles.value.map((row) => row.role_id));
    pickRows.value = page.items.map((row) => ({
      id: row.role_id,
      label: row.name,
      held: held.has(row.role_id),
    }));
  } else {
    const page = await listGroups(props.realm, 0, 200);
    const held = new Set(groups.value.map((row) => row.group_id));
    pickRows.value = page.items.map((row) => ({
      id: row.group_id,
      label: row.name,
      held: held.has(row.group_id),
    }));
  }
}

async function pickAdd(id: string) {
  try {
    if (picker.value === "role") await grantRoleToUser(props.realm, id, props.userId);
    else await joinGroup(props.realm, id, props.userId);
    picker.value = "";
    await load();
  } catch {
    // The toast already said.
  }
}

async function dropRole(roleId: string) {
  await revokeRoleFromUser(props.realm, roleId, props.userId);
  await load();
}
async function dropGroup(groupId: string) {
  await leaveGroup(props.realm, groupId, props.userId);
  await load();
}

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
        v-if="user"
        class="grid grid-cols-2 gap-x-4 gap-y-1.5 rounded-lg border border-border bg-surface px-3 py-2.5 text-[11px]"
      >
        <div class="flex items-center gap-1.5">
          <span class="text-muted">{{ say("user-identifier") }}</span>
          <AppHint name="user-identifier-help" />
          <code class="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px]">{{
            user.user_id
          }}</code>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="text-muted">{{ say("user-born") }}</span>
          <span class="font-mono text-[10.5px]">{{ born(user) || say("user-born-unknown") }}</span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="text-muted">{{ say("user-origin") }}</span>
          <span class="rounded border border-border px-1.5 py-0.5 text-[10px]">{{
            user.origin ?? "local"
          }}</span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="text-muted">{{ say("user-idp-links") }}</span>
          <template v-if="user.identity_providers?.length">
            <span
              v-for="alias in user.identity_providers"
              :key="alias"
              class="rounded border border-info/40 px-1.5 py-0.5 font-mono text-[10px] text-info"
              >{{ alias }}</span
            >
          </template>
          <span v-else class="text-faint">{{ say("user-idp-none") }}</span>
        </div>
      </div>

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

      <form class="flex flex-col gap-3 text-xs" @submit.prevent="saveProfile">
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-[11px] font-medium text-muted">
            {{ say("users-col-email") }}
            <span class="inline-flex items-center gap-1">
              <AppIcon v-if="user.email_verified" name="verified" :size="12" class="text-ok" />
            </span>
            <input
              v-model="profile.email"
              type="email"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-phone") }}
            <input
              v-model="profile.phone_number"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-given") }}
            <input
              v-model="profile.given_name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
          <label class="block text-[11px] font-medium text-muted">
            {{ say("user-family") }}
            <input
              v-model="profile.family_name"
              class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
            />
          </label>
        </div>
        <AppToggle v-model="profile.enabled">
          {{ say("users-active") }} <AppHint name="user-enabled-help" />
        </AppToggle>

        <div>
          <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
            {{ say("user-required-actions") }} <AppHint name="user-required-actions-help" />
          </div>
          <div class="relative mt-1.5 flex flex-wrap items-center gap-1.5">
            <span
              v-for="action in askedActions"
              :key="action"
              class="inline-flex items-center gap-1 rounded border border-warn/40 px-1.5 py-0.5 font-mono text-[10.5px] text-warn"
            >
              {{ action }}
              <button type="button" class="hover:text-danger" @click="dropAction(action)">
                &times;
              </button>
            </span>
            <button
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-muted hover:bg-surface-2"
              @click="askOpen = !askOpen"
            >
              {{ say("user-ask-for") }}
            </button>
            <div
              v-if="askOpen"
              class="absolute top-full left-0 z-40 mt-1 w-56 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
            >
              <button
                v-for="action in REQUIRED_ACTIONS.filter((a) => !askedActions.includes(a))"
                :key="action"
                type="button"
                class="block w-full rounded px-2 py-1 text-left font-mono text-[11px] hover:bg-surface-2"
                @click="askFor(action)"
              >
                {{ action }}
              </button>
            </div>
          </div>
        </div>

        <div>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("settings-save") }}
          </button>
        </div>

        <div class="mt-2 rounded-lg border border-danger/40 p-3">
          <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
            {{ say("settings-danger") }}
          </div>
          <p class="mt-1 text-[11px] text-muted">{{ say("user-delete-lede") }}</p>
          <div class="mt-2 flex items-center gap-2">
            <input
              v-model="doomName"
              :placeholder="user.user_name"
              class="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
              spellcheck="false"
            />
            <button
              type="button"
              class="rounded-md bg-danger px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
              :disabled="doomName !== user.user_name"
              @click="dropUser"
            >
              {{ say("user-delete") }}
            </button>
          </div>
        </div>
      </form>

      <div v-if="user && customAttributes(user).length">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-attributes") }} <AppHint name="user-attributes-help" />
        </div>
        <div class="mt-1.5 grid max-w-lg gap-1">
          <div
            v-for="[key, value] in customAttributes(user)"
            :key="key"
            class="flex items-center gap-2 rounded border border-border bg-surface px-2 py-1 text-[11px]"
          >
            <code class="font-mono text-[10.5px] text-muted">{{ key }}</code>
            <span class="font-mono text-[10.5px]">{{ value }}</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="tab === 'credentials'" class="mt-4">
      <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {{ say("user-set-password") }} <AppHint name="user-set-password-help" />
      </div>
      <form class="mt-2 flex items-end gap-2" @submit.prevent="savePassword">
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("user-new-password") }}
          <span class="relative mt-1 block">
            <input
              v-model="newPassword"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="new-password"
              class="w-full rounded-md border border-border bg-surface-2 py-1.5 pr-7 pl-2.5 text-xs text-ink"
            />
            <button
              type="button"
              class="absolute inset-y-0 right-1.5 grid place-items-center text-faint hover:text-muted"
              :aria-label="say('user-password-reveal')"
              @click="showPassword = !showPassword"
            >
              <EyeOff v-if="showPassword" :size="13" :stroke-width="1.6" />
              <Eye v-else :size="13" :stroke-width="1.6" />
            </button>
          </span>
        </label>
        <label class="flex-1 text-[11px] font-medium text-muted">
          {{ say("user-new-password-again") }}
          <input
            v-model="newPasswordAgain"
            :type="showPassword ? 'text' : 'password'"
            autocomplete="new-password"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <button
          type="submit"
          class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
        >
          {{ say("settings-save") }}
        </button>
      </form>

      <div class="mt-5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
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
      <div class="relative">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-roles") }}
        </div>
        <p v-if="!roles.length" class="mt-1.5 text-xs text-muted">{{ say("user-no-roles") }}</p>
        <div class="mt-1.5 flex flex-wrap items-center gap-1.5">
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
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropRole(role.role_id)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('role')"
          >
            {{ say("user-grant-role") }}
          </button>
        </div>
        <AppPicker
          v-if="picker === 'role'"
          :rows="pickRows"
          :title="say('user-grant-role')"
          @add="pickAdd"
          @close="picker = ''"
        />
      </div>
      <div class="relative">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("user-groups") }}
        </div>
        <p v-if="!groups.length" class="mt-1.5 text-xs text-muted">{{ say("user-no-groups") }}</p>
        <div class="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            v-for="group in groups"
            :key="group.group_id"
            class="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[11px]"
            :title="group.description"
          >
            {{ group.display_name || group.name }}
            <button
              type="button"
              class="text-faint hover:text-danger"
              :aria-label="say('action-remove')"
              @click="dropGroup(group.group_id)"
            >
              &times;
            </button>
          </span>
          <button
            type="button"
            class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-2"
            @click="openPicker('group')"
          >
            {{ say("user-join-group") }}
          </button>
        </div>
        <AppPicker
          v-if="picker === 'group'"
          :rows="pickRows"
          :title="say('user-join-group')"
          @add="pickAdd"
          @close="picker = ''"
        />
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
