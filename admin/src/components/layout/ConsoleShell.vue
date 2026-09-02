<script setup lang="ts">
import SideNav from "./SideNav.vue";
import TopBar from "./TopBar.vue";
</script>

<template>
  <div class="flex h-full">
    <SideNav />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopBar />
      <main class="min-h-0 flex-1 overflow-y-auto bg-bg p-6">
        <router-view />
      </main>
    </div>
  </div>
</template>
