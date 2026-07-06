<script setup lang="ts">
defineProps<{ gates: Array<{ label: string; ok: boolean }> }>()
</script>

<template>
  <div class="gate">
    <div v-for="g in gates" :key="g.label" class="gi">
      <span :class="['gc', g.ok ? 'ok' : 'no']">
        <svg v-if="g.ok" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <path d="M20 6L9 17l-5-5"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <path d="M12 5v14M5 12h14"/>
        </svg>
      </span>
      {{ g.label }}
    </div>
  </div>
</template>

<style scoped>
.gate { display: flex; flex-direction: column; gap: 8px; }
.gi { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.gc { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; flex: none; }
.gc svg { width: 11px; height: 11px; }
.gc.ok { background: rgba(52,224,161,.2); color: var(--good); }
.gc.no { background: rgba(245,197,66,.18); color: var(--amber); }
</style>
