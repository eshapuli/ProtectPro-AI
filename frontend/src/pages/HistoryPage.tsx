import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react'
import { historyService } from '../services/api'
import Sidebar from '../components/Sidebar'

export default function HistoryPage() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [historyData, setHistoryData] = useState<any>({
    total_count: 0,
    page: 1,
    page_size: 15,
    analyses: []
  })
  const [page, setPage] = useState(0)
  const [riskFilter, setRiskFilter] = useState<string>('')

  const fetchHistory = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await historyService.getHistory(page * 15, 15, riskFilter || undefined)
      setHistoryData(data)
    } catch (err: any) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate('/login')
      } else {
        setError('Failed to fetch investigation history from the backend.')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [page, riskFilter])

  return (
    <div className="flex h-screen bg-navy-900">
      <Sidebar activePage="history" />

      {/* Main Content */}
      <main className="flex-grow flex flex-col overflow-y-auto">
        <header className="px-8 py-6 border-b border-navy-700 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">Investigation Audit Trail</h1>
            <p className="text-slate-400 text-sm mt-1">Immutable record of technical analyses under your tenant credentials.</p>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={riskFilter}
              onChange={(e) => { setRiskFilter(e.target.value); setPage(0) }}
              className="bg-navy-800 border border-navy-700 rounded-md text-slate-300 text-xs px-3 py-2 focus:outline-none focus:ring-1 focus:ring-accent-blue"
            >
              <option value="">All Risk Levels</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Safe">Safe</option>
            </select>
            <button onClick={fetchHistory} disabled={loading} className="btn-secondary text-sm flex items-center gap-2">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </header>

        <div className="p-8 space-y-6">
          {error && (
            <div className="bg-red-950 border border-red-800 text-red-200 px-4 py-3 rounded-md text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-accent-red flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="card">
            {loading ? (
              <div className="py-12 text-center text-slate-400 text-sm">
                Loading audit trail records...
              </div>
            ) : historyData.analyses.length === 0 ? (
              <div className="py-12 text-center text-slate-400 text-sm">
                No investigation records found for this filter criteria.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-navy-700 text-slate-400 text-xs uppercase">
                    <tr>
                      <th className="py-3 px-4">Investigation ID</th>
                      <th className="py-3 px-4">Input Type</th>
                      <th className="py-3 px-4">Risk Severity</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Execution Status</th>
                      <th className="py-3 px-4">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-700 text-slate-300">
                    {historyData.analyses.map((item: any) => (
                      <tr key={item.id} className="hover:bg-navy-700 transition-colors">
                        <td className="py-3 px-4 font-mono text-xs">#{item.id}</td>
                        <td className="py-3 px-4 uppercase text-xs font-semibold">{item.input_type}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                            item.risk_level === 'Critical' || item.risk_level === 'High'
                              ? 'bg-red-950 text-accent-red border border-red-800'
                              : item.risk_level === 'Medium'
                              ? 'bg-orange-950 text-accent-orange border border-orange-800'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          }`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-bold">{item.risk_score}/100</td>
                        <td className="py-3 px-4 text-xs font-mono capitalize text-slate-400">{item.status}</td>
                        <td className="py-3 px-4 text-xs text-slate-400">{new Date(item.created_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            <div className="mt-6 pt-4 border-t border-navy-700 flex justify-between items-center text-xs text-slate-400">
              <span>
                Showing {historyData.analyses.length} of {historyData.total_count} total records
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                  className="px-3 py-1 bg-navy-700 border border-navy-600 rounded disabled:opacity-40"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="py-1 px-2 font-mono">Page {page + 1}</span>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={(page + 1) * 15 >= historyData.total_count}
                  className="px-3 py-1 bg-navy-700 border border-navy-600 rounded disabled:opacity-40"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
