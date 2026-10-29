import { useState } from 'react'
import { downloadReport } from '../api'

export default function ExportButtons({ scanId }) {
  const [error, setError] = useState('')

  async function run(format) {
    setError('')
    try {
      await downloadReport(scanId, format)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="export">
      <button type="button" className="btn" onClick={() => run('json')}>Export JSON</button>
      <button type="button" className="btn" onClick={() => run('csv')}>Export CSV</button>
      {error && <span className="status error" role="alert">{error}</span>}
    </div>
  )
}
