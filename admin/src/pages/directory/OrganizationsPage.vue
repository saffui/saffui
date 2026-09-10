<script setup lang="ts">
import PageTabs from "@/components/PageTabs.vue";
import { computed, onMounted, ref } from "vue";
import { afterWrites } from "@/services/writes";
import { useRoute } from "vue-router";
import AppDrawer from "@/components/AppDrawer.vue";
import { say } from "@/i18n";
import AppPaging from "@/components/AppPaging.vue";
import {
  claimDomain,
  createOrganization,
  deleteOrganization,
  dropDomain,
  forgetOrganizationTheme,
  getOrganization,
  getOrganizationTheme,
  listOrganizationMembers,
  listOrganizations,
  writeOrganizationTheme,
  verifyDomain,
} from "@/services/directory";
import AppHint from "@/components/AppHint.vue";
import type { Page } from "@/models/paging";
import type { OrganizationRow, OrgMember } from "@/models/directory";
import type { RealmTheme } from "@/models/realm";
import DirectoryTable from "./DirectoryTable.vue";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
const page = ref<Page<OrganizationRow> | null>(null);
const first = ref(0);
const size = ref(25);
function resize(asked: number) {
  size.value = asked;
  first.value = 0;
  void turn();
}
async function turn() {
  try {
    page.value = await listOrganizations(realm.value, first.value, size.value);
  } catch {
    // The listing simply stays where it was.
  }
}

const failed = ref("");
const opened = ref<OrganizationRow | null>(null);
const members = ref<OrgMember[] | null>(null);
const themeHalf = ref<"light" | "dark">("light");
const orgTheme = ref<{ light: Record<string, string>; dark: Record<string, string> }>({ light: {}, dark: {} });
const themeWorn = ref(false);
const themeFailed = ref("");
const THEME_TOKENS = ["brand-primary", "brand-on-primary", "bg", "surface", "ink", "muted", "border", "danger", "radius", "font-sans", "card-border-width", "card-shadow", "logo-display", "logo-radius", "field-bg"];

async function load() {
  try {
    page.value = await listOrganizations(realm.value, first.value, size.value);
  } catch (refused) {
    failed.value = refused instanceof Error ? refused.message : String(refused);
  }
}
onMounted(load);
afterWrites(load);

const making = ref(false);
const newName = ref("");
const newDisplay = ref("");
async function makeOrg() {
  if (!newName.value.trim()) return;
  try {
    await createOrganization(realm.value, {
      name: newName.value.trim(),
      display_name: newDisplay.value.trim() || newName.value.trim(),
    });
    making.value = false;
    newName.value = "";
    newDisplay.value = "";
    page.value = await listOrganizations(realm.value, first.value, size.value);
  } catch {
    // The toast already said.
  }
}

/// The TXT challenge to publish, one copyable line, checked only when the
/// operator says so: a check that silently retries forever hides a typo.
const newDomain = ref("");
const challenge = ref<{ domain: string; line: string } | null>(null);
async function claim() {
  if (!opened.value || !newDomain.value.trim()) return;
  try {
    const answered = await claimDomain(realm.value, opened.value.org_id, newDomain.value.trim());
    challenge.value = {
      domain: answered.domain,
      line: `${answered.domain}. IN TXT "${answered.challenge}"`,
    };
    newDomain.value = "";
    opened.value = await getOrganization(realm.value, opened.value.org_id);
  } catch {
    // The toast already said.
  }
}
async function copyChallenge() {
  if (!challenge.value) return;
  try {
    await navigator.clipboard.writeText(challenge.value.line);
  } catch {
    // Selectable by hand.
  }
}
async function verify(domain: string) {
  if (!opened.value) return;
  try {
    await verifyDomain(realm.value, opened.value.org_id, domain);
    opened.value = await getOrganization(realm.value, opened.value.org_id);
  } catch {
    // The toast already said.
  }
}
async function drop(domain: string) {
  if (!opened.value) return;
  await dropDomain(realm.value, opened.value.org_id, domain);
  opened.value = await getOrganization(realm.value, opened.value.org_id);
}

const doomName = ref("");
async function dropOrg() {
  if (!opened.value) return;
  try {
    await deleteOrganization(realm.value, opened.value.org_id);
    opened.value = null;
    page.value = await listOrganizations(realm.value, first.value, size.value);
  } catch {
    // The toast already said.
  }
}

async function open(org: OrganizationRow) {
  challenge.value = null;
  doomName.value = "";
  opened.value = org;
  members.value = null;
  const [organization, heldMembers, theme] = await Promise.all([
    getOrganization(realm.value, org.org_id),
    listOrganizationMembers(realm.value, org.org_id),
    getOrganizationTheme(realm.value, org.org_id),
  ]);
  opened.value = organization;
  members.value = heldMembers;
  orgTheme.value = { light: { ...theme?.light }, dark: { ...theme?.dark } };
  themeWorn.value = theme !== null;
}

async function saveTheme() {
  if (!opened.value) return;
  themeFailed.value = "";
  const theme: NonNullable<RealmTheme> = {};
  for (const half of ["light", "dark"] as const) {
    const values = Object.fromEntries(Object.entries(orgTheme.value[half]).filter(([, value]) => value.trim()));
    if (Object.keys(values).length) theme[half] = values;
  }
  try {
    await writeOrganizationTheme(realm.value, opened.value.org_id, theme);
    themeWorn.value = true;
  } catch (refused) {
    themeFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

async function clearTheme() {
  if (!opened.value) return;
  try {
    await forgetOrganizationTheme(realm.value, opened.value.org_id);
    orgTheme.value = { light: {}, dark: {} };
    themeWorn.value = false;
  } catch (refused) {
    themeFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function joined(member: OrgMember): string {
  if (!member.joined_at) return "";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
    new Date(member.joined_at),
  );
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-lg font-semibold tracking-tight">{{ say("organizations-title") }}</h1>

      <button
        type="button"
        class="sf-button sf-button-primary"
        @click="making = !making"
      >
        {{ say("org-new") }}
      </button>
    </div>

      <PageTabs class="mt-3" />
    <p v-if="failed" class="mt-4 text-xs text-danger" role="alert">{{ failed }}</p>

    <form
      v-if="making"
      class="mt-3 flex max-w-xl flex-wrap items-end gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs"
      @submit.prevent="makeOrg"
    >
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("settings-name") }}
        <input
          v-model="newName"
          class="sf-field mt-1 font-mono"
          spellcheck="false"
        />
      </label>
      <label class="flex-1 text-[11px] font-medium text-muted">
        {{ say("directory-col-display") }}
        <input
          v-model="newDisplay"
          class="sf-field mt-1"
        />
      </label>
      <button
        type="submit"
        class="sf-button sf-button-primary"
      >
        {{ say("realm-create") }}
      </button>
    </form>

    <div v-if="page" class="mt-4">
      <DirectoryTable
        :items="page.items"
        :opened-key="opened?.org_id ?? null"
        :key-of="(row: OrganizationRow) => row.org_id"
        @open="open"
      >
        <template #extra="{ row }">
          <span v-if="!row.enabled" class="text-[10.5px] text-danger">{{
            say("users-disabled")
          }}</span>
        </template>
        <template #foot>
        <AppPaging
          v-if="page"
          :first="first"
          :count="page.items.length"
          :size="size"
          @update:first="(held) => { first = held; void turn(); }"
          @update:size="resize"
        />
        </template>
      </DirectoryTable>
    </div>

    <AppDrawer
      v-if="opened"
      :title="opened.display_name || opened.name"
      :subtitle="opened.name"
      @close="opened = null"
    >
      <dl class="grid grid-cols-[140px_1fr] gap-y-2 text-xs">
        <dt class="text-muted">{{ say("org-slug") }}</dt>
        <dd class="font-mono text-[11.5px]">{{ opened.name }}</dd>
        <dt class="text-muted">{{ say("users-col-state") }}</dt>
        <dd>{{ opened.enabled ? say("users-active") : say("users-disabled") }}</dd>
        <dt v-if="opened.redirect_url" class="text-muted">{{ say("org-landing") }}</dt>
        <dd v-if="opened.redirect_url" class="font-mono text-[10.5px]">
          {{ opened.redirect_url }}
        </dd>
      </dl>

      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("org-domains") }}
        </div>
        <p v-if="!opened.domains.length" class="mt-1.5 text-xs text-muted">
          {{ say("org-no-domains") }}
        </p>
        <div class="mt-1.5 flex flex-col gap-1.5">
          <div
            v-for="domain in opened.domains"
            :key="domain.name"
            class="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-xs"
          >
            <span class="font-mono text-[11px]">{{ domain.name }}</span>
            <span
              class="ml-auto inline-flex items-center gap-1.5 text-[10.5px]"
              :class="domain.verified ? 'text-ok' : 'text-warn'"
            >
              {{ domain.verified ? say("org-domain-verified") : say("org-domain-pending") }}
            </span>
            <button
              v-if="!domain.verified"
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] hover:bg-surface-2"
              @click="verify(domain.name)"
            >
              {{ say("org-domain-check") }}
            </button>
            <button
              type="button"
              class="rounded border border-border px-1.5 py-0.5 text-[10.5px] text-danger hover:bg-surface-2"
              @click="drop(domain.name)"
            >
              {{ say("action-remove") }}
            </button>
          </div>
        </div>

        <form class="mt-2 flex items-end gap-2 text-xs" @submit.prevent="claim">
          <label class="flex-1 text-[11px] font-medium text-muted">
            {{ say("org-claim-domain") }} <AppHint name="org-claim-help" />
            <input
              v-model="newDomain"
              placeholder="apps.example.com"
              class="sf-field mt-1 font-mono"
              spellcheck="false"
            />
          </label>
          <button
            type="submit"
            class="rounded-md border border-border px-3 py-1.5 text-[11px] hover:bg-surface-2"
          >
            {{ say("org-claim") }}
          </button>
        </form>
        <div
          v-if="challenge"
          class="mt-2 flex items-center gap-2 rounded-md border border-warn/40 bg-surface-2 px-2.5 py-2"
        >
          <code class="min-w-0 flex-1 truncate font-mono text-[10.5px]">{{ challenge.line }}</code>
          <button
            type="button"
            class="rounded border border-border px-2 py-0.5 text-[10.5px] text-muted hover:bg-surface-3"
            @click="copyChallenge"
          >
            {{ say("action-copy") }}
          </button>
        </div>
        <p v-if="challenge" class="mt-1 text-[10.5px] text-muted">
          {{ say("org-challenge-lede") }}
        </p>
      </div>

      <div class="mt-4">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
          {{ say("org-members") }}
        </div>
        <p v-if="members && !members.length" class="mt-1.5 text-xs text-muted">
          {{ say("directory-nobody") }}
        </p>
        <div class="mt-1.5 flex flex-col gap-1.5">
          <div
            v-for="member in members ?? []"
            :key="member.user_id"
            class="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-xs"
          >
            <span class="font-mono text-[11px]">{{ member.user_id }}</span>
            <span class="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">{{
              member.membership_type
            }}</span>
            <span class="ml-auto font-mono text-[10px] text-faint">{{ joined(member) }}</span>
          </div>
        </div>
      </div>
      <div class="mt-4 border-t border-border pt-4">
        <div class="flex items-center gap-2">
          <div>
            <div class="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
              {{ say("org-theme-title") }}
            </div>
            <p class="mt-1 text-[11px] text-muted">{{ say("org-theme-lede") }}</p>
          </div>
          <button v-if="themeWorn" type="button" class="ml-auto text-[10.5px] text-danger hover:underline" @click="clearTheme">
            {{ say("org-theme-inherit") }}
          </button>
        </div>
        <div class="mt-2 flex gap-1">
          <button v-for="which in ['light', 'dark'] as const" :key="which" type="button" class="rounded px-2 py-1 text-[10.5px] text-muted hover:bg-surface-2" :class="themeHalf === which && 'bg-surface-2 text-ink'" @click="themeHalf = which">
            {{ say(`theme-half-${which}`) }}
          </button>
        </div>
        <div class="mt-2 grid gap-1.5">
          <label v-for="token in THEME_TOKENS" :key="token" class="grid grid-cols-[112px_1fr] items-center gap-2 text-[10.5px] text-muted">
            <span class="font-mono">--{{ token }}</span>
            <input v-model="orgTheme[themeHalf][token]" class="sf-field font-mono text-[10.5px]" :placeholder="say('theme-inherit')" spellcheck="false" />
          </label>
        </div>
        <p v-if="themeFailed" class="mt-2 text-[10.5px] text-danger" role="alert">{{ themeFailed }}</p>
        <button type="button" class="sf-button sf-button-secondary mt-2" @click="saveTheme">
          {{ say("settings-save") }}
        </button>
      </div>
      <div class="mt-4 rounded-lg border border-danger/40 p-3">
        <div class="text-[11px] font-semibold tracking-[0.08em] text-danger uppercase">
          {{ say("settings-danger") }}
        </div>
        <p class="mt-1 text-[11px] text-muted">{{ say("org-delete-lede") }}</p>
        <div class="mt-2 flex items-center gap-2">
          <input
            v-model="doomName"
            :placeholder="opened.name"
            class="sf-field font-mono"
            spellcheck="false"
          />
          <button
            type="button"
            class="sf-button sf-button-danger disabled:opacity-40"
            :disabled="doomName !== opened.name"
            @click="dropOrg"
          >
            {{ say("org-delete") }}
          </button>
        </div>
      </div>
    </AppDrawer>
  </div>
</template>
