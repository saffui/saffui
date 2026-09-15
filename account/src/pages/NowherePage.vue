<script setup lang="ts">
import { say } from "@/i18n";

document.title = say("nowhere-title");
</script>

<template>
  <main class="standalone">
    <section class="card card-narrow" aria-labelledby="nowhere">
      <h1 id="nowhere">{{ say("nowhere-title") }}</h1>
      <p class="lead">{{ say("nowhere-lead") }}</p>
    </section>
  </main>
</template>
