<script setup lang="ts">
defineProps<{ label: string; value: string | number; delta?: string; dotColor?: string; deltaColor?: string }>()
</script>

<template>
  <div class="kpi">
    <div class="top">
      <span class="lab">{{ label }}</span>
      <span class="dot" :style="dotColor ? `background:${dotColor}` : ''" />
    </div>
    <div class="val">{{ value }}</div>
    <div class="delta" :style="deltaColor ? `color:${deltaColor}` : 'color:var(--muted)'">{{ delta }}</div>
  </div>
</template>

<style scoped>
.kpi {
  background: var(--glass); border: 1px solid var(--line); border-radius: 16px;
  padding: 16px; position: relative; overflow: hidden;
  backdrop-filter: blur(12px); transition: .18s;
}
.kpi:hover { transform: translateY(-3px); border-color: var(--line2); }
.top { display: flex; align-items: center; justify-content: space-between; }
.lab { font-family: var(--mono); font-size: 9px; letter-spacing: .6px; text-transform: uppercase; color: var(--muted); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--indigo); }
.val { font-family: var(--disp); font-weight: 800; font-size: 23px; letter-spacing: -1px; margin-top: 9px; }
.delta { font-family: var(--mono); font-size: 10px; margin-top: 2px; }
</style>
