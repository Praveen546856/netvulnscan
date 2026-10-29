import { useEffect, useState } from 'react'
import { getConfig, startScan } from './api'
import ScanForm from './components/ScanForm'
import StatusMessage from './components/StatusMessage'
import Summary from './components/Summary'
import PortTable from './components/PortTable'
import Findings from './components/Findings'
import Charts from './components/Charts'
import History from './components/History'
import ExportButtons from './components/ExportButtons'

export default function App() {
  const [config, setConfig] = useState(null)
  const [configError, setConfigError] = useState('')
  const [status, setStatus] = useState('idle') // idle | loading | success | error
  const [error, setError] = useState('')
  // Scan history lives only in React state (memory). Nothing is saved to the browser.
  const [history, setHistory] = useState([])
  const [selectedId, setSelectedId] = useState(null)

  useEffect(() => {
    getConfig().then(setConfig).catch((err) => setConfigError(err.message))
  }, [])

  async function handleStart(payload) {
    setStatus('loading')
    setError('')
    try {
      const scan = await startScan(payload)
      setHistory((h) => [scan, ...h])
      setSelectedId(scan.scan_id)
      setStatus('success')
    } catch (err) {
      setError(err.message)
      setStatus('error')
    }
  }

  const selected = history.find((s) => s.scan_id === selectedId)

  return (
    <main className="app">
      <header className="header">
        <p className="eyebrow">Educational security assessment</p>
        <h1>NetVulnScan</h1>
        <p className="lead">
          A mini vulnerability assessment tool. It runs a basic TCP port check on localhost and
          explicitly configured private lab targets, then explains what it observed.
        </p>
        <p className="notice">
          Only scan systems you own or have written permission to test. Public addresses and
          arbitrary hostnames are blocked by the backend.
        </p>
      </header>

      {configError && <p className="status error" role="alert">{configError}</p>}
      {!config && !configError && <p className="status loading" role="status">Loading configuration…</p>}

      {config && <ScanForm config={config} loading={status === 'loading'} onStart={handleStart} />}
      <StatusMessage status={status} error={error} />

      {selected && (
        <section className="results" aria-label="Scan results">
          <div className="results-head">
            <h2>Results for {selected.target}</h2>
            <ExportButtons scanId={selected.scan_id} />
          </div>
          <Summary scan={selected} />
          <Charts summary={selected.summary} />
          <PortTable ports={selected.ports} />
          <Findings findings={selected.findings} />
          <div className="card">
            <h2>Limitations of this scan</h2>
            <ul className="plain">
              {selected.limitations.map((l) => <li key={l}>{l}</li>)}
            </ul>
          </div>
        </section>
      )}

      <History history={history} selectedId={selectedId} onSelect={setSelectedId} />
      <footer className="footer">Local educational tool. Not a replacement for a professional assessment.</footer>
    </main>
  )
}
