export default function Summary({ scan }) {
  const s = scan.summary
  const items = [
    ['Target', `${scan.target}${scan.target !== scan.target_ip ? ` (${scan.target_ip})` : ''}`],
    ['Ports scanned', s.ports_scanned],
    ['Open', s.open],
    ['Closed', s.closed],
    ['Unknown', s.unknown],
    ['Duration', `${scan.duration_seconds} s`],
  ]
  return (
    <div className="card">
      <h2>Scan summary</h2>
      <dl className="summary">
        {items.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <p className="hint">Started {new Date(scan.started_at).toLocaleString()}</p>
    </div>
  )
}
