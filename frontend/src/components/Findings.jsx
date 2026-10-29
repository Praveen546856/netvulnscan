const ORDER = ['High', 'Medium', 'Low', 'Info']

export default function Findings({ findings }) {
  return (
    <div className="card">
      <h2>Findings</h2>
      {findings.length === 0 && <p className="hint">No findings were produced for this scan.</p>}
      {ORDER.map((severity) => {
        const group = findings.filter((f) => f.severity === severity)
        if (group.length === 0) return null
        return (
          <section key={severity} className="sev-group">
            <h3><span className={`badge sev-${severity}`}>{severity}</span> {group.length}</h3>
            {group.map((f) => (
              <details key={f.id} className="finding">
                <summary>
                  {f.title}{f.port ? <span className="mono"> · port {f.port}</span> : null}
                </summary>
                <dl>
                  <dt>Evidence</dt><dd>{f.evidence}</dd>
                  <dt>Explanation</dt><dd>{f.explanation}</dd>
                  <dt>Recommended remediation</dt><dd>{f.remediation}</dd>
                  <dt>Confidence</dt><dd>{f.confidence}. {f.limitations}</dd>
                </dl>
              </details>
            ))}
          </section>
        )
      })}
    </div>
  )
}
