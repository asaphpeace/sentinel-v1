<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import StatusChip from '@/components/ui/StatusChip.vue'
import CodeBlock from '@/components/ui/CodeBlock.vue'

const props = defineProps<{ domains: string[] }>()
const emit  = defineEmits<{ next: [results: any[]] }>()

const router = useRouter()

interface DomainResult {
  domain: string
  already_exists: boolean
  dmarc_exists: boolean
  current_record: string | null
  generated_record: string
  reporting_address: string
  skipped: boolean   // user chose to skip already-monitored domain
}

const results     = ref<DomainResult[]>([])
const loading     = ref(true)
const checkingIdx = ref(0)
const error       = ref('')

onMounted(async () => {
  try {
    for (let i = 0; i < props.domains.length; i++) {
      checkingIdx.value = i
      const r = await api.wizardStart(props.domains[i])
      results.value.push({ ...r, skipped: r.already_exists })
    }
  } catch (e: any) {
    error.value = e.message || 'Failed to check domains — is Sentinel backend running?'
  } finally {
    loading.value = false
  }
})

const newDomains      = computed(() => results.value.filter(r => !r.already_exists))
const existingDomains = computed(() => results.value.filter(r => r.already_exists))
const toProcess       = computed(() => results.value.filter(r => !r.skipped))
const allSkipped      = computed(() => toProcess.value.length === 0 && results.value.length > 0)

function proceed() {
  emit('next', toProcess.value)
}
</script>

<template>
  <div>
    <div class="sh">DMARC status check</div>
    <p class="hint">Checking each domain for an existing DMARC record. New domains are generated with p=none for immediate monitoring.</p>

    <!-- Loading progress -->
    <div v-if="loading" class="progress-wrap">
      <div class="spin" />
      <div>
        <div class="prog-label">Checking <b>{{ domains[checkingIdx] }}</b>…</div>
        <div class="prog-bar-track">
          <div class="prog-bar-fill" :style="{ width: ((checkingIdx / domains.length) * 100) + '%' }" />
        </div>
        <div class="prog-count">{{ checkingIdx + 1 }} of {{ domains.length }}</div>
      </div>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-box">
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--bad)" stroke-width="2" style="width:18px;height:18px;flex:none"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      <div>
        <div style="font-weight:600;margin-bottom:4px">Check failed</div>
        <div>{{ error }}</div>
        <div style="margin-top:8px;font-size:11px;color:var(--faint)">Make sure uvicorn is running on port 8000.</div>
      </div>
    </div>

    <template v-else>
      <!-- New domains -->
      <template v-if="newDomains.length">
        <div class="section-hdr">
          <span class="dot new" />
          New domains <span class="count">{{ newDomains.length }}</span>
        </div>
        <div v-for="r in newDomains" :key="r.domain" class="domain-card">
          <div class="card-head">
            <span class="dn">{{ r.domain }}</span>
            <StatusChip :variant="r.dmarc_exists ? 'pill' : 'am'" :value="r.dmarc_exists ? 'good' : 'none'" :label="r.dmarc_exists ? 'Record found' : 'No record'" />
          </div>
          <div v-if="r.dmarc_exists" class="field-row">
            <span class="fl">Existing record</span>
            <span class="fv fm">{{ r.current_record }}</span>
          </div>
          <template v-else>
            <div class="notice amber">
              <svg viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
              No DMARC record — publish the generated record below to start monitoring.
            </div>
            <CodeBlock :code="r.generated_record" lang="dns" style="margin-top:10px" />
          </template>
          <div class="field-row" style="margin-top:10px">
            <span class="fl">Reporting address</span>
            <span class="fv fm">{{ r.reporting_address }}</span>
          </div>
        </div>
      </template>

      <!-- Already monitored domains -->
      <template v-if="existingDomains.length">
        <div class="section-hdr">
          <span class="dot existing" />
          Already monitored <span class="count">{{ existingDomains.length }}</span>
        </div>
        <div v-for="r in existingDomains" :key="r.domain" class="domain-card existing-card" :class="{ dimmed: r.skipped }">
          <div class="card-head">
            <span class="dn">{{ r.domain }}</span>
            <div style="display:flex;align-items:center;gap:10px">
              <span class="already-badge">Already monitored</span>
              <label class="toggle-wrap">
                <input type="checkbox" :checked="!r.skipped" @change="r.skipped = !($event.target as HTMLInputElement).checked" />
                <span class="toggle-label">{{ r.skipped ? 'Skip' : 'Re-onboard' }}</span>
              </label>
            </div>
          </div>
          <div v-if="!r.skipped" class="re-onboard-note">
            Re-running wizard will refresh the reporting address and re-check DNS records for this domain.
          </div>
          <div v-else class="skip-note">This domain will be skipped — it stays as-is in your portfolio.</div>
        </div>
      </template>

      <!-- All domains already exist and all skipped -->
      <div v-if="allSkipped" class="all-done-box">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2" style="width:20px;height:20px;flex:none"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <div>
          <div style="font-weight:600;margin-bottom:4px">All domains are already monitored</div>
          <div style="font-size:12px;color:var(--faint)">Nothing to add. Toggle "Re-onboard" above if you want to refresh a domain's setup.</div>
        </div>
      </div>

      <!-- Actions -->
      <div class="actions">
        <button v-if="allSkipped" class="btn" @click="router.push({ name: 'overview' })">Go to dashboard →</button>
        <button v-else class="btn" @click="proceed">
          Configure TLS
          <span v-if="toProcess.length !== domains.length"> ({{ toProcess.length }} domain{{ toProcess.length !== 1 ? 's' : '' }})</span>
          →
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 18px; margin-bottom: 8px; }
.hint { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 18px; }

.progress-wrap { display: flex; align-items: flex-start; gap: 14px; padding: 20px 0; }
.spin { width: 20px; height: 20px; border: 2px solid var(--line2); border-top-color: var(--teal); border-radius: 50%; animation: spin .8s linear infinite; flex: none; margin-top: 2px; }
@keyframes spin { to { transform: rotate(360deg); } }
.prog-label { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.prog-bar-track { width: 260px; height: 4px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; }
.prog-bar-fill { height: 100%; background: linear-gradient(90deg,#2ee6c5,#5b6ef5); border-radius: 4px; transition: width .35s ease; }
.prog-count { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 5px; }

.error-box { display: flex; gap: 12px; padding: 16px; background: rgba(255,80,80,.07); border: 1px solid rgba(255,80,80,.25); border-radius: 14px; font-size: 13px; color: var(--muted); }

.section-hdr { display: flex; align-items: center; gap: 8px; font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); margin: 18px 0 10px; }
.dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.dot.new { background: var(--teal); }
.dot.existing { background: var(--amber); }
.count { background: rgba(255,255,255,.08); border-radius: 20px; padding: 1px 7px; font-size: 9px; }

.domain-card { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin-bottom: 12px; transition: opacity .2s; }
.existing-card { border-color: rgba(255,190,0,.2); background: rgba(255,190,0,.04); }
.dimmed { opacity: .55; }

.card-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; gap: 12px; flex-wrap: wrap; }
.dn { font-family: var(--mono); font-size: 13px; font-weight: 600; }

.already-badge { font-family: var(--mono); font-size: 9.5px; text-transform: uppercase; letter-spacing: .6px; padding: 3px 9px; background: rgba(255,190,0,.15); border: 1px solid rgba(255,190,0,.3); border-radius: 20px; color: var(--amber); }

.toggle-wrap { display: flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; }
.toggle-wrap input { accent-color: var(--teal); width: 14px; height: 14px; cursor: pointer; }
.toggle-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }

.re-onboard-note { font-size: 12px; color: var(--muted); padding: 8px 12px; background: rgba(46,230,197,.06); border-radius: 9px; border: 1px solid rgba(46,230,197,.15); }
.skip-note { font-size: 12px; color: var(--faint); font-style: italic; }

.notice { display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px; border-radius: 11px; font-size: 12.5px; color: var(--muted); }
.notice.amber { background: rgba(255,190,0,.08); border: 1px solid rgba(255,190,0,.25); }
.notice svg { width: 16px; height: 16px; flex: none; margin-top: 1px; }
.field-row { display: flex; align-items: flex-start; gap: 12px; }
.fl { font-family: var(--mono); font-size: 10px; color: var(--faint); text-transform: uppercase; letter-spacing: .6px; min-width: 130px; padding-top: 1px; }
.fv { font-size: 12.5px; }
.fm { font-family: var(--mono); color: var(--teal); word-break: break-all; }

.all-done-box { display: flex; gap: 14px; padding: 18px; background: rgba(52,224,161,.07); border: 1px solid rgba(52,224,161,.25); border-radius: 14px; color: var(--muted); margin-top: 8px; }

.actions { margin-top: 20px; display: flex; justify-content: flex-end; }
.btn { background: linear-gradient(90deg,#5b6ef5,#8b5cf6); color:#fff; border:none; border-radius:12px; padding:11px 24px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
</style>
