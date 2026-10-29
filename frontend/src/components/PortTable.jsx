export default function PortTable({ ports }) {
  const open = ports.filter((p) => p.state === 'open')
  const others = ports.filter((p) => p.state !== 'open')
  return (
    <div className="card">
      <h2>Open ports</h2>
      {open.length === 0 ? (
        <p className="hint">No open ports were found among the scanned ports.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Port</th><th>State</th><th>Conventional service</th><th>Banner</th></tr>
            </thead>
            <tbody>
              {open.map((p) => (
                <tr key={p.port}>
                  <td className="mono">{p.port}</td>
                  <td><span className="badge open">open</span></td>
                  <td>{p.service_hint ?? 'No standard mapping'}</td>
                  <td className="mono">{p.banner ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">
        Service names come from the port number only. They are hints, not positive identification.
      </p>
      {others.length > 0 && (
        <details>
          <summary>Closed and unknown ports ({others.length})</summary>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Port</th><th>State</th><th>Reason</th></tr></thead>
              <tbody>
                {others.map((p) => (
                  <tr key={p.port}>
                    <td className="mono">{p.port}</td>
                    <td><span className={`badge ${p.state}`}>{p.state}</span></td>
                    <td>{p.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}
