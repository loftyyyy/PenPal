// Turns an Axios error into one readable sentence.
// Backend shapes: { error: { code, message, details } } or FastAPI { detail: [{ loc, msg }] }.
export function getErrorMessage(error, fallback = 'Something went wrong. Try again.') {
  if (!error) return fallback

  if (!error.response) {
    return 'Cannot reach the PenPal API. Check that the backend is running and VITE_API_BASE_URL is correct.'
  }

  const { status, data } = error.response

  if (data?.error?.message) return data.error.message
  if (Array.isArray(data?.detail)) {
    return data.detail
      .map((d) => `${(d.loc || []).slice(1).join('.') || 'input'}: ${d.msg}`)
      .join('; ')
  }
  if (typeof data?.detail === 'string') return data.detail

  switch (status) {
    case 400: return 'The request was not valid.'
    case 401: return 'Your session is not valid. Log in again.'
    case 403: return 'You do not have permission to do this.'
    case 404: return 'That item was not found.'
    case 409: return 'This action conflicts with the current state.'
    case 422: return 'Some fields are not valid.'
    case 429: return 'Too many attempts. Wait a moment and try again.'
    default:  return status >= 500 ? 'The server had a problem. Try again shortly.' : fallback
  }
}
