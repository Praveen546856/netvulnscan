export default function StatusMessage({ status, error }) {
  if (status === 'loading') {
    return <p className="status loading" role="status">Scanning… this can take several seconds.</p>
  }
  if (status === 'error') return <p className="status error" role="alert">{error}</p>
  if (status === 'success') return <p className="status success" role="status">Scan complete.</p>
  return null
}
