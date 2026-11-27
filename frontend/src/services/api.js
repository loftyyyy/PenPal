import axios from 'axios'

const TOKEN_KEY = 'penpal_token'
const EXPIRY_KEY = 'penpal_token_expires_at'

// sessionStorage: the token disappears when the tab closes.
export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  getExpiry: () => Number(sessionStorage.getItem(EXPIRY_KEY)) || null,
  set: (token, expiresInSeconds) => {
    sessionStorage.setItem(TOKEN_KEY, token)
    if (expiresInSeconds) {
      sessionStorage.setItem(EXPIRY_KEY, String(Date.now() + expiresInSeconds * 1000))
    }
  },
  clear: () => {
    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(EXPIRY_KEY)
  },
}

export const UNAUTHORIZED_EVENT = 'penpal:unauthorized'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = tokenStore.get()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const isLoginCall = error.config?.url?.includes('/auth/login')
    // A 401 on any other call means the token expired or was revoked.
    if (error.response?.status === 401 && !isLoginCall && tokenStore.get()) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
    }
    return Promise.reject(error)
  },
)

export default api
