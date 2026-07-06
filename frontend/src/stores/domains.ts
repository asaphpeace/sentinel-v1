import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

export const useDomainsStore = defineStore('domains', () => {
  const list = ref<any[]>([])
  const loading = ref(false)

  async function fetch() {
    loading.value = true
    try { list.value = await api.domains() } finally { loading.value = false }
  }

  return { list, loading, fetch }
})
