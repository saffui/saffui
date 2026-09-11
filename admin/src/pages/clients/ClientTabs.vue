<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import PageTabs from "@/components/PageTabs.vue";
import { CLIENT_TABS, clientTabPath } from "./clientTabs";

const route = useRoute();
const realm = computed(() => String(route.params.realm));
</script>

<template>
  <PageTabs
    :leaves="[...CLIENT_TABS]"
    :to="(tab) => clientTabPath(realm, tab as (typeof CLIENT_TABS)[number])"
  />
</template>
