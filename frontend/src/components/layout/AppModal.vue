<script setup lang="ts">
import { useUiStore } from '@/stores/ui'
const ui = useUiStore()
</script>

<template>
  <Teleport to="body">
    <div v-if="ui.modalOpen" class="backdrop" @click="ui.closeModal()" />
    <div :class="['modal', ui.modalOpen ? 'show' : '']">
      <div class="mdhead">
        <span>{{ ui.modalTitle }}</span>
        <span class="drx" @click="ui.closeModal()">✕</span>
      </div>
      <component :is="ui.modalContent?.component" v-bind="ui.modalContent?.props" v-if="ui.modalContent?.component" />
    </div>
  </Teleport>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; background: rgba(3,4,12,.62); backdrop-filter: blur(3px); z-index: 60; }
.modal {
  position: fixed; top: 50%; left: 50%; transform: translate(-50%, -46%);
  width: 580px; max-width: 94vw; max-height: 88vh; overflow-y: auto;
  background: linear-gradient(160deg, #0c0e1c, #070710);
  border: 1px solid var(--line2); border-radius: 18px; z-index: 70;
  padding: 24px; opacity: 0; pointer-events: none; transition: .25s;
  box-shadow: 0 30px 80px rgba(0,0,0,.6);
}
.modal.show { opacity: 1; pointer-events: auto; transform: translate(-50%, -50%); }
.mdhead { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.mdhead > span:first-child { font-family: var(--disp); font-weight: 800; font-size: 17px; }
.drx { cursor: pointer; color: var(--muted); width: 30px; height: 30px; display: grid; place-items: center; border-radius: 9px; border: 1px solid var(--line); }
.drx:hover { color: var(--txt); }
</style>
