import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { AuthProvider } from '../context/AuthContext'
import Login from './Login'

describe('login page', () => {
  it('renders credential fields and the shared primary action', () => {
    const markup = renderToStaticMarkup(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    )

    expect(markup).toContain('class="ui-login')
    expect(markup).toContain('Sign in to PenPal')
    expect(markup).toContain('type="email"')
    expect(markup).toContain('type="password"')
    expect(markup).toContain('data-variant="primary"')
  })
})
