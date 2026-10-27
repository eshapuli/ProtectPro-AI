import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

export const api = axios.create({
  baseURL: API_BASE_URL,
})

// Attach Bearer token to all authenticated requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('protectpro_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Centralized API calls
export const authService = {
  login: async (email: string, password: string) => {
    const formData = new FormData()
    formData.append('username', email)
    formData.append('password', password)
    const res = await api.post('/auth/login', formData)
    localStorage.setItem('protectpro_token', res.data.access_token)
    return res.data
  },
  register: async (email: string, password: string) => {
    return (await api.post('/auth/register', { email, password })).data
  },
  getMe: async () => {
    return (await api.get('/auth/me')).data
  },
  logout: () => {
    localStorage.removeItem('protectpro_token')
  },
  isAuthenticated: () => {
    return !!localStorage.getItem('protectpro_token')
  }
}

export const analysisService = {
  analyzeText: async (text: string) => {
    return (await api.post('/analyses/text', { text })).data
  },
  analyzeUrl: async (url: string, context_text?: string) => {
    return (await api.post('/analyses/url', { url, context_text })).data
  },
  analyzeScreenshot: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return (await api.post('/analyses/screenshot', formData)).data
  },
  analyzeQr: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return (await api.post('/analyses/qr', formData)).data
  },
  getAnalysis: async (id: number) => {
    return (await api.get(`/analyses/${id}`)).data
  },
  getSimilarMatches: async (id: number) => {
    return (await api.get(`/analyses/${id}/similar`)).data
  },
  getThreatGraph: async (id: number) => {
    return (await api.get(`/analyses/${id}/graph`)).data
  },
  getGuidance: async (id: number) => {
    return (await api.get(`/analyses/${id}/guidance`)).data
  }
}

export const historyService = {
  getHistory: async (skip = 0, limit = 20, riskFilter?: string) => {
    const params: any = { skip, limit }
    if (riskFilter) params.risk_filter = riskFilter
    return (await api.get('/history/', { params })).data
  }
}

export const campaignService = {
  getCampaigns: async () => {
    return (await api.get('/campaigns/')).data
  },
  getCampaignDetail: async (id: string) => {
    return (await api.get(`/campaigns/${id}`)).data
  }
}

export const evaluationService = {
  getMetrics: async () => {
    return (await api.get('/evaluation/metrics')).data
  }
}
