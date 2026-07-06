<script setup lang="ts">
defineProps<{ aligned: number; partial: number; fail: number }>()
</script>

<template>
  <div>
    <div class="vbar">
      <span :style="`width:${aligned}%;background:var(--good)`" />
      <span :style="`width:${partial}%;background:var(--amber)`" />
      <span :style="`width:${fail}%;background:var(--bad)`" />
    </div>
    <div class="vbarlab">
      <span style="color:var(--good)">{{ aligned }}% aligned</span>
      <span style="color:var(--amber)">{{ partial }}% partial</span>
      <span style="color:var(--bad)">{{ fail }}% fail</span>
    </div>
  </div>
</template>

<style scoped>
.vbar { height: 9px; border-radius: 5px; overflow: hidden; display: flex; background: rgba(255,255,255,.07); }
.vbar span { height: 100%; }
.vbarlab { display: flex; justify-content: space-between; font-family: var(--mono); font-size: 9px; margin-top: 4px; }
</style>
