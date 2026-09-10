<script setup lang="ts">
import { ref } from "vue";
import SideNav from "./SideNav.vue";
import TopBar from "./TopBar.vue";
import StatusBar from "./StatusBar.vue";
import AppToasts from "@/components/AppToasts.vue";

const navOpen = ref(false);
</script>

<template>
  <div class="flex h-full">
    <SideNav :open="navOpen" @close="navOpen = false" />
    <AppToasts />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopBar @toggle-nav="navOpen = !navOpen" />
      <main class="min-h-0 flex-1 overflow-y-auto bg-bg p-4 md:p-6">
        <router-view />
      </main>
      <StatusBar />
    </div>
  </div>
</template>
