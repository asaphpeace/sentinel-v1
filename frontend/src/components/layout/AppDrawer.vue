<script setup lang="ts">
import { useUiStore } from '@/stores/ui'
const ui = useUiStore()
</script>

<template>
  <Teleport to="body">
    <div v-if="ui.drawerOpen" class="backdrop" @click="ui.closeDrawer()" />
    <aside :class="['drawer', ui.drawerOpen ? 'show' : '']">
      <div class="drhead">
        <span>{{ ui.drawerTitle }}</span>
        <span class="drx" @click="ui.closeDrawer()">✕</span>
      </div>
      <div class="dr-body">
        <component :is="ui.drawerContent?.component" v-bind="ui.drawerContent?.props" v-if="ui.drawerContent?.component" />
        <div v-else-if="ui.drawerContent?.html" v-html="ui.drawerContent.html" />
      </div>
    </aside>
  </Teleport>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; background: rgba(3,4,12,.62); backdrop-filter: blur(3px); z-index: 60; }
.drawer {
  position: fixed; top: 0; right: 0; height: 100vh; width: 430px; max-width: 92vw;
  background: linear-gradient(160deg, #0c0e1c, #070710);
  border-left: 1px solid var(--line2); z-index: 70;
  transform: translateX(100%); transition: transform .28s ease;
  padding: 22px; overflow-y: auto; box-shadow: -20px 0 60px rgba(0,0,0,.55);
}
.drawer.show { transform: none; }
.drhead { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.drhead > span:first-child { font-family: var(--disp); font-weight: 800; font-size: 17px; }
.drx { cursor: pointer; color: var(--muted); font-size: 15px; width: 30px; height: 30px; display: grid; place-items: center; border-radius: 9px; border: 1px solid var(--line); }
.drx:hover { color: var(--txt); border-color: var(--line2); }
</style>
