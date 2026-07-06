<script setup lang="ts">
defineProps<{ current: string; proposed: string; host?: string }>()
</script>

<template>
  <div>
    <div class="diff">
      <div class="dl rem">− {{ current }}</div>
      <div class="dl add">+ {{ proposed }}</div>
    </div>
    <div v-if="host" class="host-label">{{ host }}</div>
  </div>
</template>

<style scoped>
.diff { font-family: var(--mono); font-size: 12px; border-radius: 11px; overflow: hidden; border: 1px solid var(--line2); }
.dl { padding: 10px 14px; white-space: pre-wrap; word-break: break-word; }
.rem { background: rgba(255,77,109,.1); color: #ffb3c0; }
.add { background: rgba(52,224,161,.1); color: #9ff5cf; }
.host-label { font-family: var(--mono); font-size: 10.5px; color: var(--faint); margin-top: 9px; }
</style>
