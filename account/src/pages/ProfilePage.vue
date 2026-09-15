<script setup lang="ts">
import { computed, inject, ref } from "vue";
import AppHint from "@/components/AppHint.vue";
import AppIcon from "@/components/AppIcon.vue";
import { readTongue, say } from "@/i18n";
import { HELD_ME, type Me } from "@/services/me";
import { session } from "@/services/session";
import { formatUpdated, listOtherFacts } from "./profile";

const realm = session.realm;
const { me, unreadable } = inject(HELD_ME, { me: ref<Me | null>(null), unreadable: ref(true) });
const facts = computed(() => (me.value ? listOtherFacts(me.value) : []));
const updated = computed(() =>
  me.value?.updated_at ? formatUpdated(me.value.updated_at, readTongue()) : "",
);
</script>

<template>
  <header class="page-head">
    <h1>{{ say("profile-title") }}</h1>
    <p class="lead">{{ say("profile-lead", { realm }) }}</p>
  </header>

  <p v-if="unreadable" class="notice notice-danger" role="alert">
    {{ say("profile-unreadable") }}
  </p>

  <template v-else-if="me">
    <section class="card" aria-labelledby="profile-identity">
      <h2 id="profile-identity" class="card-title">{{ say("profile-identity") }}</h2>
      <dl class="facts">
        <div v-if="me.name" class="fact">
          <dt>{{ say("profile-name") }}</dt>
          <dd>{{ me.name }}</dd>
        </div>
        <div class="fact">
          <dt>
            {{ say("profile-username") }}
            <AppHint :text="say('profile-username-help')" />
          </dt>
          <dd class="mono">{{ me.preferred_username }}</dd>
        </div>
      </dl>
    </section>

    <section class="card" aria-labelledby="profile-contact">
      <h2 id="profile-contact" class="card-title">{{ say("profile-contact") }}</h2>
      <dl class="facts">
        <div class="fact">
          <dt>{{ say("profile-email") }}</dt>
          <dd v-if="me.email">
            <span>{{ me.email }}</span>
            <template v-if="me.email_verified">
              <span class="badge badge-verified">
                <AppIcon name="verified" :size="14" />{{ say("profile-email-verified") }}
              </span>
              <AppHint :text="say('profile-email-verified-help', { realm })" />
            </template>
            <template v-else>
              <span class="badge badge-unverified">
                <AppIcon name="unverified" :size="14" />{{ say("profile-email-unverified") }}
              </span>
              <AppHint :text="say('profile-email-unverified-help', { realm })" />
            </template>
          </dd>
          <dd v-else class="absent">{{ say("profile-none") }}</dd>
        </div>
        <div class="fact">
          <dt>{{ say("profile-phone") }}</dt>
          <dd v-if="me.phone_number">
            <span class="numeric">{{ me.phone_number }}</span>
            <template v-if="me.phone_number_verified">
              <span class="badge badge-verified">
                <AppIcon name="verified" :size="14" />{{ say("profile-phone-verified") }}
              </span>
              <AppHint :text="say('profile-phone-verified-help', { realm })" />
            </template>
            <template v-else>
              <span class="badge badge-unverified">
                <AppIcon name="unverified" :size="14" />{{ say("profile-phone-unverified") }}
              </span>
              <AppHint :text="say('profile-phone-unverified-help', { realm })" />
            </template>
          </dd>
          <dd v-else class="absent">{{ say("profile-none") }}</dd>
        </div>
      </dl>
    </section>

    <section v-if="facts.length" class="card" aria-labelledby="profile-more">
      <h2 id="profile-more" class="card-title">{{ say("profile-more") }}</h2>
      <dl class="facts">
        <div v-for="fact in facts" :key="fact.label" class="fact">
          <dt>{{ fact.label }}</dt>
          <dd class="lines">{{ fact.value }}</dd>
        </div>
      </dl>
    </section>

    <p class="footnote">
      {{ say("profile-managed", { realm }) }}
      <template v-if="updated">{{ say("profile-updated", { when: updated }) }}</template>
    </p>
  </template>

  <p v-else class="loading" aria-busy="true">{{ say("loading") }}</p>
</template>
