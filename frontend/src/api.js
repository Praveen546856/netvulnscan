// The backend runs on your own computer. Scans are only possible for targets
// that the backend allowlist permits.
const API_URL = 'http://127.0.0.1:8000'

async function readError(response) {
  let message = 'Something went wrong.'
  try {
    const data = await response.json()
    if (typeof data.detail === 'string') message = data.detail
  } catch {
    /* keep generic message */
  }
  return new Error(message)
}

async function request(path, options) {
  let response
  try {
    response = await fetch(`${API_URL}${path}`, options)
  } catch {
    throw new Error('Cannot reach the local backend. Is it running on port 8000?')
  }
  if (!response.ok) throw await readError(response)
  return response
}

export async function getConfig() {
  return (await request('/api/scan/config')).json()
}

export async function startScan(payload) {
  const response = await request('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  return response.json()
}

export async function downloadReport(scanId, format) {
  const response = await request(`/api/scan/${scanId}/report?format=${format}`)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `netvulnscan-${scanId.slice(0, 8)}.${format}`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
