export default function History({ history, selectedId, onSelect }) {
  return (
    <div className="card">
      <h2>Scan history</h2>
      <p className="hint">Kept in memory only. It disappears when you refresh the page.</p>
      {history.length === 0 ? (
        <p className="hint">No scans yet.</p>
      ) : (
        <ul className="history">
          {history.map((scan) => (
            <li key={scan.scan_id}>
              <button
                type="button" className={scan.scan_id === selectedId ? 'active' : ''}
                onClick={() => onSelect(scan.scan_id)}
              >
                <span>{scan.target}</span>
                <span className="hint">
                  {new Date(scan.started_at).toLocaleTimeString()} · {scan.summary.open} open ·{' '}
                  {scan.findings.length} findings
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
