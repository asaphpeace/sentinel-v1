<script setup lang="ts">
import { ref } from 'vue'
import { useUiStore } from '@/stores/ui'
import StepTracker from '@/components/ui/StepTracker.vue'
import WizardStep1Domains   from './WizardStep1Domains.vue'
import WizardStep2Dmarc     from './WizardStep2Dmarc.vue'
import WizardStep3Tls       from './WizardStep3Tls.vue'
import WizardStep4Confirm   from './WizardStep4Confirm.vue'
import WizardStepPlatforms  from './WizardStepPlatforms.vue'
import { useRouter } from 'vue-router'

const emit = defineEmits<{ close: [] }>()
const ui     = useUiStore()
const router = useRouter()

const step         = ref(0)
const domains      = ref<string[]>([])
const dmarcResults = ref<any[]>([])
const tlsResults   = ref<any[]>([])
const confirmedDomainNames = ref<string[]>([])

const STEPS = ['Domains', 'DMARC check', 'TLS setup', 'Confirm', 'Platforms']

function step1Done(d: string[]) { domains.value = d; step.value = 1 }
function step2Done(r: any[])    { dmarcResults.value = r; step.value = 2 }
function step3Done(r: any[])    { tlsResults.value = r; step.value = 3 }
function step4Confirmed(names: string[]) { confirmedDomainNames.value = names; step.value = 4 }
function done() {
  emit('close')
  router.push({ name: 'roadmap' })
}
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="wizard-panel">
        <div class="wizard-header">
          <div class="wh-title">
            <div class="wh-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="width:16px">
                <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
              </svg>
            </div>
            Add domains to Sentinel
          </div>
          <button class="close-btn" @click="emit('close')">×</button>
        </div>

        <div class="wizard-steps">
          <StepTracker :steps="STEPS" :current="step" />
        </div>

        <div class="wizard-body">
          <WizardStep1Domains  v-if="step === 0" @next="step1Done" />
          <WizardStep2Dmarc    v-else-if="step === 1" :domains="domains" @next="step2Done" />
          <WizardStep3Tls      v-else-if="step === 2" :domains="domains" :dmarc-results="dmarcResults" @next="step3Done" />
          <WizardStep4Confirm  v-else-if="step === 3" :tls-results="tlsResults" @confirmed="step4Confirmed" @cancel="emit('close')" />
          <WizardStepPlatforms v-else :domain-names="confirmedDomainNames" @done="done" />
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(6px); z-index: 1000; display: grid; place-items: center; padding: 20px; }
.wizard-panel { width: 620px; max-width: 96vw; max-height: 90vh; background: #0f1118; border: 1px solid var(--line2); border-radius: 22px; box-shadow: 0 40px 120px rgba(0,0,0,.7); display: flex; flex-direction: column; overflow: hidden; }
.wizard-header { display: flex; align-items: center; justify-content: space-between; padding: 20px 24px 0; }
.wh-title { display: flex; align-items: center; gap: 10px; font-family: var(--disp); font-weight: 800; font-size: 15px; }
.wh-logo { width: 32px; height: 32px; border-radius: 10px; background: radial-gradient(circle at 30% 25%,#2ef5d4,#5b6ef5); display: grid; place-items: center; color: #06060f; }
.close-btn { background: none; border: none; color: var(--muted); font-size: 22px; cursor: pointer; line-height: 1; padding: 4px; border-radius: 8px; }
.close-btn:hover { color: var(--txt); background: rgba(255,255,255,.06); }
.wizard-steps { padding: 20px 24px 0; }
.wizard-body { flex: 1; overflow-y: auto; padding: 20px 24px 24px; }
</style>
