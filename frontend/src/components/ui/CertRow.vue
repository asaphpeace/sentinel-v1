<script setup lang="ts">
defineProps<{ host: string; issuer?: string; days?: number | null; status: string; validPct?: number }>()
const pillMap: Record<string, string> = { healthy:'ok', expiring_soon:'warnp', critical:'danger', expired:'danger', error:'danger' }
const statusLabel: Record<string, string> = { healthy:'HEALTHY', expiring_soon:'RENEW SOON', critical:'CRITICAL', expired:'EXPIRED', error:'ERROR' }
const barColor: Record<string, string> = { healthy:'var(--good)', expiring_soon:'var(--warn)', critical:'var(--bad)', expired:'var(--bad)', error:'var(--faint)' }
</script>

<template>
  <div class="certrow">
    <div class="cn">{{ host }}<small>{{ issuer }}</small></div>
    <div class="days" :style="`color:${barColor[status]}`">{{ days ?? '—' }}d</div>
    <div class="expbar"><i :style="`width:${Math.min(validPct ?? 100, 100)}%;background:${barColor[status]}`" /></div>
    <div style="text-align:right">
      <span :class="['pill', pillMap[status] || 'warnp']">{{ statusLabel[status] ?? status.toUpperCase() }}</span>
    </div>
  </div>
</template>

<style scoped>
.certrow { display: grid; grid-template-columns: 1.5fr 70px 1fr 80px; gap: 14px; align-items: center; padding: 13px 4px; border-bottom: 1px solid var(--line); }
.certrow:last-child { border: 0; }
.cn { font-family: var(--mono); font-size: 12px; }
.cn small { display: block; color: var(--faint); font-size: 10px; }
.days { font-family: var(--mono); font-weight: 700; }
.expbar { height: 8px; border-radius: 5px; background: rgba(255,255,255,.06); overflow: hidden; }
.expbar i { display: block; height: 100%; border-radius: 5px; }
.pill { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 20px; }
.pill.ok    { background: rgba(52,224,161,.15); color: var(--good); }
.pill.warnp { background: rgba(245,197,66,.16); color: var(--amber); }
.pill.danger{ background: rgba(255,77,109,.16); color: var(--bad); }
</style>
