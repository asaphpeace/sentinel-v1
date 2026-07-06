<script setup lang="ts">
import AiBadge from './AiBadge.vue'

defineProps<{
  summary?: string | null
  threats?: string | null
  actions?: string | null
  generatedAt?: string | null
  loading?: boolean
  regenerating?: boolean
  isAi?: boolean
}>()

defineEmits<{ regenerate: [] }>()
</script>

<template>
  <div class="ai-card" :class="{ loading }">
    <div class="ai-card-head">
      <span class="ai-card-title">Intelligence Summary</span>
      <div class="ai-card-actions">
        <AiBadge v-if="isAi !== false" :timestamp="generatedAt" :loading="loading" />
        <span v-else class="rule-label">Analysis</span>
        <button
          class="regen-btn"
          :class="{ spinning: regenerating }"
          :disabled="loading || regenerating"
          title="Regenerate with Ollama"
          @click="$emit('regenerate')"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          <span>{{ regenerating ? 'Regenerating…' : 'Regenerate' }}</span>
        </button>
      </div>
    </div>

    <div v-if="loading" class="ai-skels">
      <div class="skel" style="width:85%;height:13px" />
      <div class="skel" style="width:70%;height:13px;margin-top:6px" />
      <div class="skel" style="width:90%;height:13px;margin-top:18px" />
      <div class="skel" style="width:60%;height:13px;margin-top:6px" />
      <div class="skel" style="width:78%;height:13px;margin-top:18px" />
    </div>

    <div v-else-if="regenerating" class="ai-skels">
      <div class="skel" style="width:88%;height:13px" />
      <div class="skel" style="width:72%;height:13px;margin-top:6px" />
      <div class="skel" style="width:93%;height:13px;margin-top:18px" />
      <div class="skel" style="width:55%;height:13px;margin-top:6px" />
      <div class="skel" style="width:80%;height:13px;margin-top:18px" />
    </div>

    <div v-else-if="summary || threats || actions" class="ai-paragraphs">
      <p v-if="summary" class="ai-p">{{ summary }}</p>
      <p v-if="threats" class="ai-p threats">{{ threats }}</p>
      <p v-if="actions" class="ai-p actions">{{ actions }}</p>
    </div>

    <div v-else class="ai-empty">No narrative available yet — data is still being collected.</div>
  </div>
</template>

<style scoped>
.ai-card {
  background: rgba(46,230,197,.03);
  border: 1px solid rgba(46,230,197,.14);
  border-radius: 16px; padding: 18px 20px;
  backdrop-filter: blur(10px);
}
.ai-card-head {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 14px; gap: 10px; flex-wrap: wrap;
}
.ai-card-title {
  font-family: var(--mono); font-size: 9.5px; letter-spacing: 1.2px;
  text-transform: uppercase; color: var(--faint);
}
.ai-card-actions {
  display: flex; align-items: center; gap: 10px;
}
.rule-label {
  font-family: var(--mono); font-size: 9px; color: var(--faint);
  border: 1px solid var(--line); border-radius: 20px; padding: 3px 10px;
}

.regen-btn {
  display: flex; align-items: center; gap: 5px;
  background: none; border: 1px solid var(--line2);
  border-radius: 20px; padding: 4px 11px;
  color: var(--faint); font-family: var(--mono); font-size: 9.5px;
  cursor: pointer; transition: .15s; letter-spacing: .3px;
}
.regen-btn svg { width: 11px; height: 11px; flex: none; }
.regen-btn:hover:not(:disabled) { color: var(--teal); border-color: rgba(46,230,197,.35); }
.regen-btn:disabled { opacity: .45; cursor: not-allowed; }
.regen-btn.spinning svg { animation: spin .9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.ai-paragraphs { display: flex; flex-direction: column; gap: 10px; }
.ai-p { font-size: 13.5px; line-height: 1.7; color: #c8cfe8; margin: 0; }
.ai-p.threats { color: #e0c8d0; }
.ai-p.actions { color: #c8d8e0; }

.skel {
  background: rgba(255,255,255,.05); border-radius: 6px;
  animation: pulse 1.4s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { opacity:.5 } 50% { opacity:.9 } }
.ai-skels { padding: 4px 0 2px; }
.ai-empty { font-size: 12px; color: var(--faint); padding: 4px 0; }
</style>
