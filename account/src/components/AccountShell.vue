<script setup lang="ts">
import { onMounted, provide, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppHint from "./AppHint.vue";
import AppIcon from "./AppIcon.vue";
import { listTongues, pinTongue, readTongue, say } from "@/i18n";
import { HELD_ME, readMe, type Me } from "@/services/me";
import { session, signIn, signOut } from "@/services/session";

const route = useRoute();
const router = useRouter();
const realm = session.realm;
const me = ref<Me | null>(null);
const unreadable = ref(false);
provide(HELD_ME, { me, unreadable });

async function loadMe() {
  try {
    me.value = await readMe(realm);
    unreadable.value = false;
  } catch {
    unreadable.value = true;
  }
}

async function endSignIn() {
  await signOut();
  await router.replace("/signed-out");
}

function chooseTongue(event: Event) {
  pinTongue((event.target as HTMLSelectElement).value);
}

// A call that finds the sign-in gone says why: an ended one is mended by signing
// in again and landing back here, a refused one is explained rather than retried.
watch(
  () => session.lost,
  async (lost) => {
    if (lost === "refused") await router.replace("/trouble");
    else if (lost === "ended") await signIn(route.fullPath);
  },
);

onMounted(loadMe);
</script>

<template>
  <div class="shell">
    <header class="masthead">
      <div class="masthead-row">
        <div class="realm">
          <span class="realm-mark" aria-hidden="true">{{ realm.slice(0, 2).toUpperCase() }}</span>
          <span class="realm-name">{{ realm }}</span>
        </div>
        <div class="masthead-tools">
          <span v-if="me" class="person">{{ me.name ?? me.preferred_username }}</span>
          <span class="tongue">
            <label class="visually-hidden" for="tongue">{{ say("tongue-label") }}</label>
            <select id="tongue" class="tongue-select" :value="readTongue()" @change="chooseTongue">
              <option v-for="held in listTongues()" :key="held" :value="held">
                {{ say(`tongue-${held}`) }}
              </option>
            </select>
            <AppHint :text="say('tongue-help')" />
          </span>
          <button
            type="button"
            class="button button-quiet"
            :title="say('account-sign-out-help', { realm })"
            @click="endSignIn"
          >
            <AppIcon name="sign-out" />
            <span>{{ say("account-sign-out") }}</span>
          </button>
        </div>
      </div>
      <nav class="tabs" :aria-label="say('nav-label')">
        <router-link to="/profile" class="tab">
          <AppIcon name="profile" :size="15" />
          <span>{{ say("nav-profile") }}</span>
        </router-link>
        <router-link to="/security" class="tab">
          <AppIcon name="security" :size="15" />
          <span>{{ say("nav-security") }}</span>
        </router-link>
        <router-link to="/sessions" class="tab">
          <AppIcon name="sessions" :size="15" />
          <span>{{ say("nav-sessions") }}</span>
        </router-link>
      </nav>
    </header>
    <main class="page">
      <router-view />
    </main>
  </div>
</template>
