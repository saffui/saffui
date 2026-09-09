<script setup lang="ts">
// The realm this console serves, named where the deck puts it: in the rail,
// under its own caption, rather than as a chip in the top bar.
//
// It no longer switches. A token reaches the realm that minted it, so the
// listing answers one row; what the popover still carries is the way to make
// another realm, and the one moment its credential can be read.
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import AppIcon from "@/components/AppIcon.vue";
import AppHint from "@/components/AppHint.vue";
import { say } from "@/i18n";
import { useSession } from "@/stores/session";
import { createRealm, listRealms, type RealmBorn } from "@/services/realms";
import type { RealmBrief } from "@/models/realm";

const session = useSession();
const route = useRoute();
const realmsOpen = ref(false);
const realms = ref<RealmBrief[]>([]);

const current = computed(() => String(route.params.realm ?? session.realm ?? "main"));

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

const making = ref(false);
const newName = ref("");
const newDisplay = ref("");
const newAdmin = ref("");
const newEmail = ref("");
const makeFailed = ref("");
/// What the birth answered with, held until the person dismisses it. This is
/// the only moment the password exists anywhere a human can read it.
const born = ref<RealmBorn | null>(null);
const copied = ref(false);

function openMaking() {
  realmsOpen.value = false;
  making.value = true;
  newName.value = "";
  newDisplay.value = "";
  newAdmin.value = "";
  newEmail.value = "";
  makeFailed.value = "";
  born.value = null;
  copied.value = false;
}

async function copyPassword() {
  if (!born.value) return;
  try {
    await navigator.clipboard.writeText(born.value.administrator.password);
    copied.value = true;
  } catch {
    // The box stays selectable; copying by hand still works.
  }
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
  const admin = newAdmin.value.trim();
  if (!usableName(admin)) {
    makeFailed.value = say("realm-new-bad-admin");
    return;
  }
  try {
    // No routing to the new realm: this session's token was minted by
    // another one and reaches nothing there. What the birth hands back is
    // the way in, and it is shown once.
    born.value = await createRealm(name, newDisplay.value.trim() || name, {
      userName: admin,
      email: newEmail.value.trim(),
    });
  } catch (refused) {
    makeFailed.value = refused instanceof Error ? refused.message : String(refused);
  }
}


function onAway(event: MouseEvent) {
  const target = event.target as HTMLElement;
  if (!target.closest("[data-realm-menu]")) realmsOpen.value = false;
}

onMounted(() => document.addEventListener("click", onAway));
onUnmounted(() => document.removeEventListener("click", onAway));
</script>

<template>
  <div class="relative px-3 py-2.5" data-realm-menu>
      <div class="text-[9.5px] tracking-[0.08em] text-faint uppercase">
        {{ say("topbar-realm") }}
      </div>
      <button
        type="button"
        class="mt-1.5 flex h-[29px] w-full items-center gap-1.5 rounded px-2.5 text-left hover:bg-surface-3"
        :class="realmsOpen ? 'bg-surface-3' : 'bg-surface-2'"
        @click.stop="openRealms"
      >
        <span class="min-w-0 flex-1 truncate text-[12.5px] text-ink">{{ current }}</span>
        <AppIcon name="chevron" :size="13" class="rotate-90 text-faint" />
      </button>
      <div
        v-if="realmsOpen"
        class="absolute top-[62px] left-3 z-40 w-[238px] overflow-hidden rounded-md border border-glass-line bg-glass shadow-(--sf-shadow) backdrop-blur-xl"
      >
        <button
          v-for="realm in realms"
          :key="realm.realm_id"
          type="button"
          class="flex h-[46px] w-full items-center gap-[9px] px-2.5 py-2 text-left"
          :class="realm.name === current ? 'bg-accent-tint' : 'hover:bg-neutral-tint'"
          @click="realmsOpen = false"
        >
          <span class="flex min-w-0 flex-1 flex-col gap-0.5">
            <span
              class="truncate font-mono text-[11.5px]"
              :class="realm.name === current ? 'text-accent' : 'text-ink'"
              >{{ realm.name }}</span
            >
            <span class="truncate text-[10.5px] text-faint">{{ realm.display_name }}</span>
          </span>
          <AppIcon
            v-if="realm.name === current"
            name="verified"
            :size="13"
            class="shrink-0 text-accent"
          />
          <span v-if="!realm.enabled" class="sf-badge sf-badge-danger shrink-0">{{
            say("users-disabled")
          }}</span>
        </button>
        <p v-if="!realms.length" class="px-2.5 py-3 text-[11px] text-muted">
          {{ say("palette-nothing") }}
        </p>
        <button
          type="button"
          class="flex h-[30px] w-full items-center gap-2 border-t border-glass-line px-2.5 text-left hover:bg-neutral-tint"
          @click="openMaking"
        >
          <AppIcon name="plus" :size="13" class="text-muted" />
          <span class="flex-1 text-[11.5px] text-muted">{{ say("realm-new") }}</span>
        </button>
      </div>

    <div v-if="making" class="fixed inset-0 z-50 flex items-start justify-center">
      <div class="absolute inset-0 bg-black/45" @click="making = false"></div>

      <div
        v-if="born"
        class="relative mt-24 w-[540px] max-w-full rounded-lg border border-glass-line bg-glass shadow-(--sf-shadow) backdrop-blur-xl"
      >
        <div class="flex h-[66px] items-center gap-3 px-[18px]">
          <span
            class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-ok-tint text-ok"
          >
            <AppIcon name="verified" :size="15" />
          </span>
          <span class="min-w-0 flex-1">
            <span class="block truncate text-[15px] text-ink">{{
              say("realm-born", { realm: born.name })
            }}</span>
            <span class="block truncate font-mono text-[11px] text-faint">{{ born.realm_id }}</span>
          </span>
        </div>
        <div class="flex flex-col gap-3.5 px-[18px] pb-1">
          <p class="text-[13px] text-ink">{{ say("realm-born-lede") }}</p>
          <div class="flex flex-col gap-1.5">
            <span class="text-[10.5px] text-faint">{{ say("realm-born-credential") }}</span>
            <div class="flex flex-col gap-1 rounded-md bg-surface-2 px-3 py-2.5">
              <span class="font-mono text-[11px] text-muted"
                >user_name = {{ born.administrator.user_name }}</span
              >
              <span class="font-mono text-[11px] break-all text-ink">{{
                born.administrator.password
              }}</span>
            </div>
          </div>
          <div class="flex items-center gap-2 rounded-md bg-warn-tint px-3 py-2.5">
            <AppIcon name="danger" :size="13" class="shrink-0 text-warn" />
            <span class="text-[11px] text-muted">{{ say("realm-born-once") }}</span>
          </div>
        </div>
        <div class="flex h-14 items-center gap-3 px-[18px]">
          <span class="min-w-0 flex-1 truncate font-mono text-[10.5px] text-faint">{{
            say("realm-born-trail")
          }}</span>
          <button type="button" class="sf-button sf-button-secondary" @click="copyPassword">
            {{ copied ? say("action-copied") : say("action-copy") }}
          </button>
          <button type="button" class="sf-button sf-button-primary" @click="making = false">
            {{ say("action-done") }}
          </button>
        </div>
      </div>

      <form
        v-else
        class="relative mt-24 w-[540px] max-w-full rounded-lg border border-glass-line bg-glass shadow-(--sf-shadow) backdrop-blur-xl"
        @submit.prevent="makeRealm"
      >
        <div class="flex h-[66px] items-center gap-3 px-[18px]">
          <span
            class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-accent-tint text-accent"
          >
            <AppIcon name="plus" :size="15" />
          </span>
          <span class="min-w-0 flex-1">
            <span class="block text-[15px] text-ink">{{ say("realm-new") }}</span>
            <span class="block text-[11px] text-faint">{{ say("realm-new-lede") }}</span>
          </span>
          <button
            type="button"
            class="shrink-0 text-muted hover:text-ink"
            :aria-label="say('action-cancel')"
            @click="making = false"
          >
            <AppIcon name="close" :size="16" />
          </button>
        </div>
        <div class="flex flex-col gap-3.5 px-[18px] pb-1">
          <div class="flex gap-3">
            <label class="flex flex-1 flex-col gap-1.5">
              <span class="text-[10.5px] text-faint">
                {{ say("settings-name") }} <AppHint name="realm-new-name-help" />
              </span>
              <input v-model="newName" class="sf-field font-mono" spellcheck="false" autofocus />
            </label>
            <label class="flex flex-1 flex-col gap-1.5">
              <span class="text-[10.5px] text-faint">
                {{ say("directory-col-display") }} <AppHint name="realm-new-display-help" />
              </span>
              <input v-model="newDisplay" class="sf-field" />
            </label>
          </div>
          <div class="flex flex-col gap-1.5 rounded-md bg-neutral-tint px-3 py-2.5">
            <span class="text-[10.5px] text-faint">{{ say("realm-new-admin-lede") }}</span>
            <div class="flex gap-3">
              <input
                v-model="newAdmin"
                class="sf-field flex-1 font-mono"
                spellcheck="false"
                :placeholder="say('realm-new-admin-name')"
              />
              <input
                v-model="newEmail"
                class="sf-field flex-1"
                type="email"
                :placeholder="say('realm-new-admin-email')"
              />
            </div>
          </div>
          <p v-if="makeFailed" class="text-[11px] text-danger" role="alert">{{ makeFailed }}</p>
        </div>
        <div class="flex h-14 items-center gap-3 px-[18px]">
          <span class="min-w-0 flex-1 truncate font-mono text-[10.5px] text-faint">{{
            say("realm-new-trail")
          }}</span>
          <button
            type="button"
            class="sf-button sf-button-secondary"
            @click="making = false"
          >
            {{ say("action-cancel") }}
          </button>
          <button type="submit" class="sf-button sf-button-primary">
            {{ say("realm-create") }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
