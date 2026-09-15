<script setup lang="ts">
import { say } from "@/i18n";
import { session, signIn } from "@/services/session";

const realm = session.realm;
</script>

<template>
  <main class="standalone">
    <section class="card card-narrow" aria-labelledby="signed-out">
      <span class="realm-mark" aria-hidden="true">{{ realm.slice(0, 2).toUpperCase() }}</span>
      <h1 id="signed-out">{{ say("signed-out-title") }}</h1>
      <p class="lead">{{ say("signed-out-lead", { realm }) }}</p>
      <button type="button" class="button button-primary" @click="signIn('/profile')">
        {{ say("signed-out-again") }}
      </button>
    </section>
  </main>
</template>
