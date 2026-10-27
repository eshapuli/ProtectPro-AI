import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { BarChart3, Target, AlertTriangle, ShieldCheck, RefreshCw } from 'lucide-react'
import { historyService, campaignService } from '../services/api'
import Sidebar from '../components/Sidebar'

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState({
    total_count: 0,
    high_risk_count: 0,
    safe_count: 0,
    average_risk: 0.0,
    analyses: [] as any[]
  })
  const [campaignsCount, setCampaignsCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchDashboardData = async () => {
    setLoading(true)
    setError(null)
    try {
      const histData = await historyService.getHistory(0, 5)
      setStats(histData)
      const campData = await campaignService.getCampaigns()
      setCampaignsCount(campData.length)
    } catch (err: any) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        // Not authenticated, redirect to login
        navigate('/login')
      } else {
        setError('Failed to connect to ProtectPro security API. Verify backend service is running.')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboardData()
  }, [])

  return (
    <div className="flex h-screen bg-navy-900">
      <Sidebar activePage="dashboard" />

      {/* Main Content */}
      <main className="flex-grow flex flex-col overflow-y-auto">
        <header className="px-8 py-6 border-b border-navy-700 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">Threat Intelligence Overview</h1>
            <p className="text-slate-400 text-sm mt-1">Real-time telemetry and investigation history.</p>
          </div>
          <button 
            onClick={fetchDashboardData}
            disabled={loading}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Telemetry
          </button>
        </header>

        <div className="p-8 space-y-6">
          {error && (
            <div className="bg-red-950 border border-red-800 text-red-200 px-4 py-3 rounded-md text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-accent-red flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Top KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="card flex flex-col justify-between">
              <span className="text-slate-400 text-sm font-medium">Total Investigations</span>
              <span className="text-3xl font-bold mt-2 text-slate-100">{loading ? '...' : stats.total_count}</span>
            </div>
            <div className="card flex flex-col justify-between border-t-2 border-t-accent-red">
              <span className="text-slate-400 text-sm font-medium">High / Critical Threats</span>
              <span className="text-3xl font-bold mt-2 text-accent-red">{loading ? '...' : stats.high_risk_count}</span>
            </div>
            <div className="card flex flex-col justify-between border-t-2 border-t-emerald-500">
              <span className="text-slate-400 text-sm font-medium">Verified Benign</span>
              <span className="text-3xl font-bold mt-2 text-emerald-400">{loading ? '...' : stats.safe_count}</span>
            </div>
            <div className="card flex flex-col justify-between border-t-2 border-t-accent-blue">
              <span className="text-slate-400 text-sm font-medium">Active Threat Campaigns</span>
              <span className="text-3xl font-bold mt-2 text-accent-blue">{loading ? '...' : campaignsCount}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Risk Distribution Summary */}
            <div className="card min-h-[300px] flex flex-col">
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="w-5 h-5 text-slate-400" />
                <h3 className="font-bold text-slate-200">Average Risk Score</h3>
              </div>
              <div className="flex-grow flex flex-col items-center justify-center p-6 text-center">
                <div className="text-5xl font-black mb-2 text-slate-100">
                  {stats.average_risk}<span className="text-lg text-slate-400 font-normal">/100</span>
                </div>
                <p className="text-sm text-slate-400 max-w-sm">
                  Deterministic average severity across all tenant investigations.
                </p>
              </div>
            </div>

            {/* Recent Activity Table */}
            <div className="card min-h-[300px] flex flex-col">
              <div className="flex items-center gap-2 mb-4">
                <Target className="w-5 h-5 text-slate-400" />
                <h3 className="font-bold text-slate-200">Recent Investigations</h3>
              </div>

              {loading ? (
                <div className="flex-grow flex items-center justify-center text-slate-400 text-sm">
                  Loading telemetry...
                </div>
              ) : stats.analyses.length === 0 ? (
                <div className="flex-grow flex flex-col items-center justify-center text-slate-400 text-sm py-8">
                  <ShieldCheck className="w-12 h-12 text-slate-600 mb-2" />
                  <p>No recent analyses found in this tenant profile.</p>
                  <Link to="/workspace" className="btn-primary mt-4 text-sm">Launch Investigation</Link>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-navy-700 text-slate-400 text-xs uppercase">
                      <tr>
                        <th className="py-2">ID</th>
                        <th className="py-2">Type</th>
                        <th className="py-2">Severity</th>
                        <th className="py-2">Score</th>
                        <th className="py-2">Date</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-700 text-slate-300">
                      {stats.analyses.map((item) => (
                        <tr key={item.id} className="hover:bg-navy-700 transition-colors">
                          <td className="py-3 font-mono text-xs">#{item.id}</td>
                          <td className="py-3 uppercase text-xs font-semibold">{item.input_type}</td>
                          <td className="py-3">
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
                          <td className="py-3 font-bold">{item.risk_score}/100</td>
                          <td className="py-3 text-xs text-slate-400">{new Date(item.created_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
