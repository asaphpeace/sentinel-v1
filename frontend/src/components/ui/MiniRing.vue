<script setup lang="ts">
const props = defineProps<{ pct: number; color: string }>()
const r = 15
const c = 2 * Math.PI * r
const offset = computed(() => c * (1 - props.pct / 100))
import { computed } from 'vue'
</script>

<template>
  <svg class="miniring" viewBox="0 0 36 36" style="transform:rotate(-90deg)">
    <circle cx="18" cy="18" :r="r" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="4"/>
    <circle cx="18" cy="18" :r="r" fill="none" :stroke="color" stroke-width="4"
      :stroke-dasharray="c" :stroke-dashoffset="offset" stroke-linecap="round"/>
  </svg>
</template>

<style scoped>
.miniring { width: 36px; height: 36px; flex: none; }
</style>
