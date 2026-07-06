import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUiStore = defineStore('ui', () => {
  // Drawer
  const drawerOpen = ref(false)
  const drawerTitle = ref('')
  const drawerContent = ref<any>(null) // component or data passed to AppDrawer slot

  function openDrawer(title: string, content: any) {
    drawerTitle.value = title
    drawerContent.value = content
    drawerOpen.value = true
  }
  function closeDrawer() { drawerOpen.value = false }

  // Modal
  const modalOpen = ref(false)
  const modalTitle = ref('')
  const modalContent = ref<any>(null)

  function openModal(title: string, content: any) {
    modalTitle.value = title
    modalContent.value = content
    modalOpen.value = true
  }
  function closeModal() { modalOpen.value = false }

  // Toast
  const toastMsg = ref('')
  const toastType = ref<'info' | 'error'>('info')
  const toastVisible = ref(false)
  let _toastTimer: ReturnType<typeof setTimeout> | null = null

  function toast(msg: string, type: 'info' | 'error' = 'info') {
    toastMsg.value = msg
    toastType.value = type
    toastVisible.value = true
    if (_toastTimer) clearTimeout(_toastTimer)
    _toastTimer = setTimeout(() => { toastVisible.value = false }, 2600)
  }

  // Alert menu
  const alertMenuOpen = ref(false)
  function toggleAlertMenu() { alertMenuOpen.value = !alertMenuOpen.value }
  function closeAlertMenu() { alertMenuOpen.value = false }

  // Wizard
  const wizardOpen = ref(false)
  function openWizard() { wizardOpen.value = true }
  function closeWizard() { wizardOpen.value = false }

  // Assistant
  const assistantOpen = ref(false)
  function toggleAssistant() { assistantOpen.value = !assistantOpen.value }

  // Nav sidebar (mobile)
  const navOpen = ref(false)
  function toggleNav() { navOpen.value = !navOpen.value }
  function closeNav() { navOpen.value = false }

  return {
    drawerOpen, drawerTitle, drawerContent, openDrawer, closeDrawer,
    modalOpen, modalTitle, modalContent, openModal, closeModal,
    toastMsg, toastType, toastVisible, toast,
    alertMenuOpen, toggleAlertMenu, closeAlertMenu,
    wizardOpen, openWizard, closeWizard,
    assistantOpen, toggleAssistant,
    navOpen, toggleNav, closeNav,
  }
})
