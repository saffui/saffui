<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import { offeredTongues, pinTongue, say, tongueInForce } from "@/i18n";
import AppHint from "@/components/AppHint.vue";
import { useSession } from "@/stores/session";
import { createRealm, listRealms } from "@/services/realms";
import type { RealmBrief } from "@/models/realm";
import CommandPalette from "./CommandPalette.vue";

const session = useSession();
const route = useRoute();
const router = useRouter();
const dark = ref(document.documentElement.classList.contains("dark"));
const paletteOpen = ref(false);
const realmsOpen = ref(false);
const profileOpen = ref(false);
const tongues = offeredTongues();
const tongue = tongueInForce();
const realms = ref<RealmBrief[]>([]);

const current = computed(() => String(route.params.realm ?? session.realm ?? "main"));

function flipTheme() {
  dark.value = !dark.value;
  document.documentElement.classList.toggle("dark", dark.value);
  localStorage.setItem("sf-console-theme", dark.value ? "dark" : "light");
}

function signOut() {
  session.signOut();
  router.push("/login");
}

async function openRealms() {
  realmsOpen.value = !realmsOpen.value;
  if (realmsOpen.value) {
    try {
      realms.value = await listRealms();
    } catch {
      realms.value = [];
    }
  }
}

function switchTo(realm: RealmBrief) {
  realmsOpen.value = false;
  router.push(`/${realm.name}/overview`);
}

const making = ref(false);
const newName = ref("");
const newDisplay = ref("");
const makeFailed = ref("");

function openMaking() {
  realmsOpen.value = false;
  making.value = true;
  newName.value = "";
  newDisplay.value = "";
  makeFailed.value = "";
}

/// What the server will accept as a name; refused here first so the person
/// is told before a request is spent.
function usableName(name: string): boolean {
  return /^[A-Za-z0-9_-]{1,63}$/.test(name);
}

async function makeRealm() {
  makeFailed.value = "";
  const name = newName.value.trim();
  if (!usableName(name)) {
    makeFailed.value = say("realm-new-bad-name");
    return;
  }
  try {
    await createRealm(name, newDisplay.value.trim() || name);
    making.value = false;
    // By the typed name, not the echo: the destination is what was asked for.
    router.push(`/${name}/overview`);
  } catch (refused) {
    makeFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}

function onAway(event: MouseEvent) {
  const target = event.target as HTMLElement;
  if (!target.closest("[data-realm-menu]")) realmsOpen.value = false;
  if (!target.closest("[data-profile-menu]")) profileOpen.value = false;
}
onMounted(() => document.addEventListener("click", onAway));
onUnmounted(() => document.removeEventListener("click", onAway));

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase() || "?";
}
</script>

<template>
  <header class="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
    <div class="relative" data-realm-menu>
      <button
        type="button"
        class="flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs hover:bg-surface-3"
        @click.stop="openRealms"
      >
        <span class="text-faint">{{ say("topbar-realm") }}</span>
        <span class="font-mono text-[11.5px] font-medium">{{ current }}</span>
        <AppIcon name="chevron" :size="11" class="rotate-90 text-faint" />
      </button>
      <div
        v-if="realmsOpen"
        class="absolute top-9 left-0 z-40 w-56 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
      >
        <button
          v-for="realm in realms"
          :key="realm.realm_id"
          type="button"
          class="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-surface-2"
          :class="realm.name === current && 'bg-surface-2 font-medium'"
          @click="switchTo(realm)"
        >
          <span class="font-mono text-[11px]">{{ realm.name }}</span>
          <span class="ml-auto truncate text-[10.5px] text-faint">{{ realm.display_name }}</span>
          <span v-if="!realm.enabled" class="text-[10px] text-danger">{{
            say("users-disabled")
          }}</span>
        </button>
        <p v-if="!realms.length" class="px-2 py-2 text-[11px] text-muted">
          {{ say("palette-nothing") }}
        </p>
        <button
          type="button"
          class="mt-1 flex w-full items-center gap-2 rounded border-t border-border px-2 pt-2 pb-1.5 text-left text-xs text-accent hover:bg-surface-2"
          @click="openMaking"
        >
          <AppIcon name="plus" :size="12" />
          {{ say("realm-new") }}
        </button>
      </div>
    </div>

    <div v-if="making" class="fixed inset-0 z-50">
      <div class="absolute inset-0 bg-black/30" @click="making = false"></div>
      <form
        class="absolute top-28 left-1/2 w-[380px] max-w-full -translate-x-1/2 rounded-lg border border-border bg-surface p-4 shadow-(--sf-shadow)"
        @submit.prevent="makeRealm"
      >
        <h2 class="text-sm font-semibold">{{ say("realm-new") }}</h2>
        <p class="mt-1 text-[11px] text-muted">{{ say("realm-new-lede") }}</p>
        <label class="mt-3 block text-[11px] font-medium text-muted">
          {{ say("settings-name") }} <AppHint name="realm-new-name-help" />
          <input
            v-model="newName"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-ink"
            spellcheck="false"
            autofocus
          />
        </label>
        <label class="mt-2 block text-[11px] font-medium text-muted">
          {{ say("directory-col-display") }} <AppHint name="realm-new-display-help" />
          <input
            v-model="newDisplay"
            class="mt-1 w-full rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink"
          />
        </label>
        <p v-if="makeFailed" class="mt-2 text-[11px] text-danger" role="alert">{{ makeFailed }}</p>
        <div class="mt-3 flex items-center justify-end gap-2">
          <button
            type="button"
            class="rounded-md border border-border px-3 py-1.5 text-xs text-muted hover:bg-surface-2"
            @click="making = false"
          >
            {{ say("action-cancel") }}
          </button>
          <button
            type="submit"
            class="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-ink hover:bg-accent-strong"
          >
            {{ say("realm-create") }}
          </button>
        </div>
      </form>
    </div>

    <button
      type="button"
      class="flex min-w-56 items-center gap-2 rounded-md border border-border px-2 py-1 text-xs text-faint hover:bg-surface-2"
      @click="paletteOpen = true"
    >
      <AppIcon name="search" :size="13" />
      <span>{{ say("topbar-search") }}</span>
      <kbd class="ml-auto rounded border border-border bg-surface-2 px-1 font-mono text-[10px]"
        >&#8984;K</kbd
      >
    </button>

    <div class="relative ml-auto flex items-center gap-2" data-profile-menu>
      <button
        type="button"
        class="grid size-7 place-items-center rounded-full border border-border bg-surface-2 text-[10.5px] font-semibold hover:border-accent/50"
        :aria-label="say('profile-open')"
        @click.stop="profileOpen = !profileOpen"
      >
        {{ initials(session.displayName) }}
      </button>

      <div
        v-if="profileOpen"
        class="absolute top-9 right-0 z-40 w-60 rounded-md border border-border bg-surface p-1 shadow-(--sf-shadow)"
      >
        <div class="px-2.5 pt-2 pb-1.5">
          <p class="text-xs font-semibold">{{ session.displayName }}</p>
          <p class="font-mono text-[10.5px] text-faint">{{ say("profile-realm") }} {{ current }}</p>
        </div>
        <div class="my-1 border-t border-border"></div>
        <div class="flex items-center gap-1 px-2.5 py-1.5 text-[11px] text-muted">
          {{ say("profile-tongue") }}
          <span class="ml-auto flex gap-1">
            <button
              v-for="held in tongues"
              :key="held"
              type="button"
              class="rounded border px-1.5 py-0.5 font-mono text-[10.5px]"
              :class="
                held === tongue
                  ? 'border-accent/60 text-accent'
                  : 'border-border text-muted hover:text-ink'
              "
              @click="pinTongue(held)"
            >
              {{ held }}
            </button>
          </span>
        </div>
        <button
          type="button"
          class="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left text-xs hover:bg-surface-2"
          @click="flipTheme"
        >
          <AppIcon :name="dark ? 'sun' : 'moon'" :size="13" class="text-faint" />
          {{ dark ? say("profile-light") : say("profile-dark") }}
        </button>
        <div class="my-1 border-t border-border"></div>
        <button
          type="button"
          class="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left text-xs text-danger hover:bg-surface-2"
          @click="signOut"
        >
          {{ say("action-sign-out") }}
        </button>
      </div>
    </div>

    <CommandPalette v-model="paletteOpen" />
  </header>
</template>
