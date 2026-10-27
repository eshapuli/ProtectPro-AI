import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { LayoutDashboard, FileSearch, History, LogOut, ShieldAlert, UserCheck } from 'lucide-react'
import { authService } from '../services/api'

interface SidebarProps {
  activePage: 'dashboard' | 'workspace' | 'history'
}

export default function Sidebar({ activePage }: SidebarProps) {
  const navigate = useNavigate()
  const [userEmail, setUserEmail] = useState<string>('')

  useEffect(() => {
    let isMounted = true
    authService.getMe()
      .then((data: any) => {
        if (isMounted && data?.email) {
          setUserEmail(data.email)
        }
      })
      .catch(() => {
        // Fallback gracefully if session token is transient
      })
    return () => { isMounted = false }
  }, [])

  const handleLogout = () => {
    authService.logout()
    navigate('/')
  }

  return (
    <aside className="w-64 border-r border-navy-700 bg-navy-800 flex flex-col flex-shrink-0">
      <div className="p-6 border-b border-navy-700 flex items-center gap-2">
        <ShieldAlert className="w-6 h-6 text-accent-blue" />
        <span className="font-bold text-lg text-slate-100">ProtectPro AI</span>
      </div>
      <nav className="flex-grow p-4 flex flex-col gap-2">
        <Link 
          to="/dashboard" 
          className={`flex items-center gap-3 px-3 py-2 rounded-md font-medium transition-colors text-sm ${
            activePage === 'dashboard'
              ? 'bg-navy-700 text-accent-blue'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-700/60'
          }`}
        >
          <LayoutDashboard className="w-4 h-4" /> Dashboard
        </Link>
        <Link 
          to="/workspace" 
          className={`flex items-center gap-3 px-3 py-2 rounded-md font-medium transition-colors text-sm ${
            activePage === 'workspace'
              ? 'bg-navy-700 text-accent-blue'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-700/60'
          }`}
        >
          <FileSearch className="w-4 h-4" /> Workspace
        </Link>
        <Link 
          to="/history" 
          className={`flex items-center gap-3 px-3 py-2 rounded-md font-medium transition-colors text-sm ${
            activePage === 'history'
              ? 'bg-navy-700 text-accent-blue'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-700/60'
          }`}
        >
          <History className="w-4 h-4" /> History
        </Link>
      </nav>

      {/* Operator Profile Card & Session Termination */}
      <div className="p-4 border-t border-navy-700 space-y-3">
        <div className="p-3 bg-navy-900 border border-navy-700 rounded-md">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-accent-blue" /> Operator Session
            </span>
          </div>
          <p className="text-xs text-slate-300 truncate font-mono mt-1" title={userEmail || 'Active Analyst'}>
            {userEmail || 'analyst@protectpro.sec'}
          </p>
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block mt-0.5">Role: Security Analyst</span>
        </div>
        <button 
          onClick={handleLogout}
          className="flex items-center gap-2.5 px-3 py-2 text-slate-400 hover:text-slate-200 hover:bg-navy-700 w-full rounded-md transition-colors text-xs font-medium"
        >
          <LogOut className="w-4 h-4" /> End Session
        </button>
      </div>
    </aside>
  )
}
