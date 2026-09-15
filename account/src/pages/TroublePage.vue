<script setup lang="ts">
import { say } from "@/i18n";
import { session, signIn } from "@/services/session";

const realm = session.realm;
</script>

<template>
  <main class="standalone">
    <section class="card card-narrow" aria-labelledby="trouble" role="alert">
      <span class="realm-mark" aria-hidden="true">{{ realm.slice(0, 2).toUpperCase() }}</span>
      <h1 id="trouble">{{ say("trouble-title") }}</h1>
      <p class="lead">{{ say("trouble-lead", { realm }) }}</p>
      <button type="button" class="button button-primary" @click="signIn('/profile')">
        {{ say("trouble-again") }}
      </button>
    </section>
  </main>
</template>
