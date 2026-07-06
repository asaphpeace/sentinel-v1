<script setup lang="ts">
/**
 * Deepest level of the DMARC drill-down.
 * Shows header-from, envelope-from, DKIM selector/d=/result, SPF domain/result,
 * DMARC outcome, and plain-English explanation — all from one aggregate row.
 */
defineProps<{
  detail: {
    header_from: string
    envelope_from?: string | null
    dkim_selector?: string | null
    dkim_domain?: string | null
    dkim_result?: string | null
    dkim_aligned: boolean
    spf_domain?: string | null
    spf_result?: string | null
    spf_aligned: boolean
    dmarc_result: string
    disposition: string
    volume: number
    explanation: string
  }
}>()

const resultColor = (r: string | null | undefined) => {
  if (!r) return 'var(--faint)'
  const lo = r.toLowerCase()
  if (lo === 'pass') return 'var(--good)'
  if (lo === 'fail') return 'var(--bad)'
  if (lo === 'softfail' || lo === 'neutral') return 'var(--amber)'
  return 'var(--faint)'
}
const alignBadge = (aligned: boolean, result: string | null | undefined) => {
  if (aligned) return { text: 'ALIGNED', color: 'var(--good)', bg: 'rgba(52,224,161,.15)' }
  if (result === 'pass') return { text: 'NOT ALIGNED', color: 'var(--amber)', bg: 'rgba(245,197,66,.14)' }
  return { text: 'FAIL', color: 'var(--bad)', bg: 'rgba(255,77,109,.15)' }
}
</script>

<template>
  <div class="auth-detail">
    <!-- Explanation banner -->
    <div class="explanation">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2">
        <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
      </svg>
      {{ detail.explanation }}
    </div>

    <div class="detail-grid">
      <!-- Addresses -->
      <div class="section">
        <div class="sec-label">Email addresses</div>
        <div class="field-row">
          <span class="field-key">Header-From (visible From:)</span>
          <span class="field-val mono">{{ detail.header_from }}</span>
          <span class="field-hint">What recipients see in their inbox</span>
        </div>
        <div class="field-row">
          <span class="field-key">Envelope-From (MAIL FROM)</span>
          <span class="field-val mono">{{ detail.envelope_from || '—' }}</span>
          <span class="field-hint">Hidden return-path used for bounces — must match for SPF alignment</span>
        </div>
      </div>

      <!-- DKIM -->
      <div class="section">
        <div class="sec-label">DKIM signature</div>
        <div class="field-row">
          <span class="field-key">Selector</span>
          <span class="field-val mono">{{ detail.dkim_selector || 'none' }}</span>
        </div>
        <div class="field-row">
          <span class="field-key">Signing domain (d=)</span>
          <span class="field-val mono">{{ detail.dkim_domain || 'none' }}</span>
          <span class="field-hint">Must match {{ detail.header_from }} for alignment</span>
        </div>
        <div class="field-row">
          <span class="field-key">Signature result</span>
          <span class="field-val" :style="`color:${resultColor(detail.dkim_result)}`">{{ (detail.dkim_result || 'none').toUpperCase() }}</span>
        </div>
        <div class="field-row">
          <span class="field-key">Alignment</span>
          <span class="badge" :style="`color:${alignBadge(detail.dkim_aligned, detail.dkim_result).color};background:${alignBadge(detail.dkim_aligned, detail.dkim_result).bg}`">
            {{ alignBadge(detail.dkim_aligned, detail.dkim_result).text }}
          </span>
          <span v-if="!detail.dkim_aligned && detail.dkim_domain" class="field-hint">
            Signed as {{ detail.dkim_domain }}, not {{ detail.header_from }}
          </span>
        </div>
      </div>

      <!-- SPF -->
      <div class="section">
        <div class="sec-label">SPF check</div>
        <div class="field-row">
          <span class="field-key">Domain checked</span>
          <span class="field-val mono">{{ detail.spf_domain || detail.envelope_from || '—' }}</span>
          <span class="field-hint">The envelope-from domain evaluated against your SPF record</span>
        </div>
        <div class="field-row">
          <span class="field-key">SPF result</span>
          <span class="field-val" :style="`color:${resultColor(detail.spf_result)}`">{{ (detail.spf_result || 'none').toUpperCase() }}</span>
        </div>
        <div class="field-row">
          <span class="field-key">Alignment</span>
          <span class="badge" :style="`color:${alignBadge(detail.spf_aligned, detail.spf_result).color};background:${alignBadge(detail.spf_aligned, detail.spf_result).bg}`">
            {{ alignBadge(detail.spf_aligned, detail.spf_result).text }}
          </span>
          <span v-if="!detail.spf_aligned && detail.spf_domain" class="field-hint">
            SPF passed for {{ detail.spf_domain }}, not {{ detail.header_from }}
          </span>
        </div>
      </div>

      <!-- DMARC outcome -->
      <div class="section outcome-row">
        <div class="sec-label">DMARC outcome</div>
        <div class="field-row">
          <span class="field-key">Result</span>
          <span class="field-val" :style="`color:${detail.dmarc_result === 'pass' ? 'var(--good)' : 'var(--bad)'};font-weight:700`">
            {{ detail.dmarc_result.toUpperCase() }}
          </span>
          <span class="field-hint">
            {{ detail.dmarc_result === 'pass'
              ? 'At least one of DKIM or SPF is aligned — DMARC passes.'
              : 'Neither DKIM nor SPF is aligned to the header-from domain — DMARC fails.' }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-key">Disposition</span>
          <span class="field-val mono">{{ detail.disposition }}</span>
          <span class="field-hint">What happened to this mail under the current policy</span>
        </div>
        <div class="field-row">
          <span class="field-key">Message volume</span>
          <span class="field-val mono">{{ detail.volume.toLocaleString() }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.auth-detail { padding: 14px 0 10px 0; }
.explanation {
  display: flex; gap: 10px; align-items: flex-start;
  background: rgba(46,230,197,.07); border: 1px solid rgba(46,230,197,.2);
  border-radius: 10px; padding: 11px 14px; font-size: 12.5px;
  color: #cde8e0; line-height: 1.6; margin-bottom: 16px;
}
.explanation svg { flex: none; margin-top: 2px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.section { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }
.sec-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); margin-bottom: 10px; }
.field-row { display: grid; grid-template-columns: 130px 1fr; gap: 4px 10px; align-items: baseline; margin-bottom: 9px; }
.field-row:last-child { margin-bottom: 0; }
.field-key { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.field-val { font-size: 12.5px; color: var(--txt); }
.field-val.mono { font-family: var(--mono); }
.field-hint { grid-column: 2; font-size: 10.5px; color: var(--muted); line-height: 1.4; margin-top: -2px; }
.badge { font-family: var(--mono); font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 6px; }
.outcome-row { grid-column: 1 / -1; }
@media (max-width: 800px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
