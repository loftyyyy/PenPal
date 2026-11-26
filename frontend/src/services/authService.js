import api, { tokenStore } from './api'

export const authService = {
  // Backend returns { access_token, token_type, expires_in, user }
  async login(email, password) {
    const { data } = await api.post('/auth/login', { email, password })
    tokenStore.set(data.access_token, data.expires_in)
    return data.user
  },

  // Returns UserOut: { id, email, full_name, role, is_active, created_at, updated_at }
  async me() {
    const { data } = await api.get('/auth/me')
    return data
  },

  logout() {
    tokenStore.clear()
  },
}
