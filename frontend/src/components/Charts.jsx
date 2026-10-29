import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const SEV_COLORS = { High: '#f87171', Medium: '#fb923c', Low: '#facc15', Info: '#60a5fa' }
const STATE_COLORS = { open: '#4ade80', closed: '#94a3b8', unknown: '#c084fc' }
const TIP = { background: '#0b1220', border: '1px solid #26334f', color: '#e6edf7' }

export default function Charts({ summary }) {
  const states = [
    { name: 'open', value: summary.open },
    { name: 'closed', value: summary.closed },
    { name: 'unknown', value: summary.unknown },
  ].filter((d) => d.value > 0)
  const severities = ['High', 'Medium', 'Low', 'Info'].map((name) => ({
    name, value: summary.findings_by_severity[name] ?? 0,
  }))

  return (
    <div className="grid">
      <div className="card">
        <h2>Port states</h2>
        <div className="chart" role="img" aria-label="Chart of open, closed and unknown port counts">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie isAnimationActive={false} data={states} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} label>
                {states.map((d) => <Cell key={d.name} fill={STATE_COLORS[d.name]} stroke="none" />)}
              </Pie>
              <Tooltip contentStyle={TIP} itemStyle={{ color: '#e6edf7' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <p className="legend">
          {states.map((d) => (
            <span key={d.name}><i style={{ background: STATE_COLORS[d.name] }} />{d.name} {d.value}</span>
          ))}
        </p>
      </div>
      <div className="card">
        <h2>Findings by severity</h2>
        <div className="chart" role="img" aria-label="Bar chart of finding counts by severity">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severities}>
              <XAxis dataKey="name" stroke="#a3b1c9" />
              <YAxis allowDecimals={false} stroke="#a3b1c9" />
              <Tooltip contentStyle={TIP} cursor={{ fill: '#18233a' }} />
              <Bar dataKey="value" isAnimationActive={false}>
                {severities.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.name]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
