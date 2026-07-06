<script setup lang="ts">
defineProps<{
  segments: Array<{ value: number; pct: number; label: string; color: string }>
}>()
</script>

<template>
  <div class="split">
    <div
      v-for="seg in segments" :key="seg.label"
      class="seg"
      :style="`background:${seg.color};width:${Math.max(seg.pct, 0.5)}%`"
    >
      <span class="sv">{{ seg.value.toLocaleString() }}</span>
      <span class="sl">{{ seg.label }} · {{ seg.pct.toFixed(1) }}%</span>
    </div>
  </div>
</template>

<style scoped>
.split { display: flex; height: 42px; border-radius: 12px; overflow: hidden; margin-bottom: 10px; background: rgba(255,255,255,.04); }
.seg { display: flex; flex-direction: column; justify-content: center; padding: 0 15px; color: #06121a; min-width: 0; white-space: nowrap; }
.sv { font-family: var(--disp); font-weight: 800; font-size: 15px; }
.sl { font-family: var(--mono); font-size: 8.5px; text-transform: uppercase; letter-spacing: .4px; opacity: .85; }
</style>
