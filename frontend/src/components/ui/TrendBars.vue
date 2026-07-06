<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ data: Array<{ week: string; successful: number; failed: number }> }>()
const max = computed(() => Math.max(...props.data.map(d => d.successful + d.failed), 1))
</script>

<template>
  <div>
    <div class="trendbars">
      <div v-for="d in data" :key="d.week" class="tb">
        <div class="bf" :style="`height:${d.failed / max * 100}%`" />
        <div class="bs" :class="{ rb: d.failed === 0 }" :style="`height:${d.successful / max * 100}%`" />
      </div>
    </div>
    <div class="trendlabs">
      <span v-for="d in data" :key="d.week">{{ d.week }}</span>
    </div>
    <div class="legend">
      <div class="lg"><i style="background:#2ee6c5" />Negotiated TLS</div>
      <div class="lg"><i style="background:#ff4d6d" />Failed</div>
    </div>
  </div>
</template>

<style scoped>
.trendbars { display: flex; align-items: flex-end; gap: 8px; height: 120px; }
.tb { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; min-height: 2px; }
.bf { width: 100%; background: #ff4d6d; border-radius: 4px 4px 0 0; }
.bs { width: 100%; background: linear-gradient(180deg,#2ee6c5,#159e87); }
.bs.rb { border-radius: 4px 4px 0 0; }
.trendlabs { display: flex; gap: 8px; margin-top: 7px; }
.trendlabs span { flex: 1; text-align: center; font-family: var(--mono); font-size: 9px; color: var(--faint); }
.legend { display: flex; gap: 16px; margin-top: 12px; }
.lg { display: flex; align-items: center; gap: 9px; font-size: 12px; }
.lg i { width: 9px; height: 9px; border-radius: 3px; flex: none; }
</style>
