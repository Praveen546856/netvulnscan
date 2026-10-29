import { useState } from 'react'
import { parsePorts } from '../ports'

export default function ScanForm({ config, loading, onStart }) {
  const limits = config.limits
  const [target, setTarget] = useState(config.default_target)
  const [portMode, setPortMode] = useState('common')
  const [customPorts, setCustomPorts] = useState('')
  const [expected, setExpected] = useState('')
  const [timeout, setTimeoutValue] = useState(limits.default_timeout_seconds)
  const [banner, setBanner] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [formError, setFormError] = useState('')

  function submit(event) {
    event.preventDefault()
    setFormError('')

    let ports = null
    if (portMode === 'custom') {
      const parsed = parsePorts(customPorts, limits.min_port, limits.max_port, limits.max_ports_per_scan)
      if (parsed.error || parsed.ports.length === 0) {
        setFormError(parsed.error || 'Enter at least one port.')
        return
      }
      ports = parsed.ports
    }
    const exp = parsePorts(expected, limits.min_port, limits.max_port, limits.max_ports_per_scan)
    if (exp.error) {
      setFormError(`Expected ports: ${exp.error}`)
      return
    }
    onStart({
      target,
      ports,
      timeout_seconds: Number(timeout),
      grab_banner: banner,
      expected_ports: expected.trim() ? exp.ports : null,
    })
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>Scan configuration</h2>

      <div className="form-grid">
        <div className="field">
          <label htmlFor="target">Authorized target</label>
          <select id="target" value={target} onChange={(e) => setTarget(e.target.value)} disabled={loading}>
            {config.allowed_targets.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <p className="hint">Only targets on the server allowlist appear here.</p>
        </div>

        <div className="field">
          <label htmlFor="timeout">Timeout per port: {Number(timeout).toFixed(1)} s</label>
          <input
            id="timeout" type="range" disabled={loading}
            min={limits.min_timeout_seconds} max={limits.max_timeout_seconds} step="0.1"
            value={timeout} onChange={(e) => setTimeoutValue(e.target.value)}
          />
          <p className="hint">Windows can take about 2 s to report a refused local port.</p>
        </div>
      </div>

      <fieldset className="field" disabled={loading}>
        <legend>Ports</legend>
        <label className="inline">
          <input type="radio" name="ports" checked={portMode === 'common'} onChange={() => setPortMode('common')} />
          Common ports ({config.default_ports.length})
        </label>
        <label className="inline">
          <input type="radio" name="ports" checked={portMode === 'custom'} onChange={() => setPortMode('custom')} />
          Custom
        </label>
        {portMode === 'custom' ? (
          <>
            <input
              type="text" aria-label="Custom ports" placeholder="22, 80, 8000-8010"
              value={customPorts} onChange={(e) => setCustomPorts(e.target.value)}
            />
            <p className="hint">
              {limits.min_port}-{limits.max_port}, at most {limits.max_ports_per_scan} ports.
            </p>
          </>
        ) : (
          <p className="hint mono">{config.default_ports.join(', ')}</p>
        )}
      </fieldset>

      <div className="field">
        <label htmlFor="expected">Expected open ports (optional)</label>
        <input
          id="expected" type="text" placeholder="e.g. 22, 80" disabled={loading}
          value={expected} onChange={(e) => setExpected(e.target.value)}
        />
        <p className="hint">If set, other open ports are reported as "unexpected".</p>
      </div>

      <label className="inline check">
        <input type="checkbox" checked={banner} onChange={(e) => setBanner(e.target.checked)} disabled={loading} />
        Read service banner (passive: sends nothing, reads up to 128 characters)
      </label>

      <label className="inline check">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} disabled={loading} />
        I own this system or have explicit permission to assess it.
      </label>

      {formError && <p className="status error" role="alert">{formError}</p>}

      <button type="submit" className="btn primary" disabled={loading || !authorized}>
        {loading ? 'Scanning…' : 'Start scan'}
      </button>
    </form>
  )
}
