// Turn text like "22, 80, 8000-8003" into a list of port numbers.
// The backend validates everything again; this only gives faster feedback.
export function parsePorts(text, min, max, limit) {
  const trimmed = text.trim()
  if (!trimmed) return { ports: [], error: '' }
  const ports = []
  for (const part of trimmed.split(',')) {
    const item = part.trim()
    const range = item.match(/^(\d+)\s*-\s*(\d+)$/)
    if (range) {
      const start = Number(range[1])
      const end = Number(range[2])
      if (start > end || end - start >= limit) return { ports: [], error: `Range "${item}" is not valid.` }
      for (let p = start; p <= end; p++) ports.push(p)
    } else if (/^\d+$/.test(item)) {
      ports.push(Number(item))
    } else {
      return { ports: [], error: `"${item}" is not a valid port.` }
    }
  }
  const unique = [...new Set(ports)]
  if (unique.some((p) => p < min || p > max)) {
    return { ports: [], error: `Ports must be between ${min} and ${max}.` }
  }
  if (unique.length > limit) return { ports: [], error: `Use at most ${limit} ports.` }
  return { ports: unique, error: '' }
}
