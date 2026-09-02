<script setup lang="ts">
import { onMounted } from "vue";

// The visitor's stored choice wins; the OS decides otherwise. Stored under
// one key so the toggle in the top bar and this boot read the same fact.
onMounted(() => {
  const kept = localStorage.getItem("sf-console-theme");
  const dark = kept ? kept === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.classList.toggle("dark", dark);
});
</script>

<template>
  <router-view />
</template>
